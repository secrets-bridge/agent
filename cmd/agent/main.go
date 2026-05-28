// Command agent is the Secrets Bridge outbound execution agent.
//
// It runs INSIDE a target boundary (a Kubernetes cluster, a private VPC,
// a customer account) and communicates ONLY outbound to the Control
// Plane API and to the local secrets provider. There is no inbound
// listener on a public network interface; the only HTTP server is a
// loopback /healthz /readyz /metrics endpoint for kubelet + Prometheus.
//
// Hard rules (BRD §15, §24, NFR-09):
//   - The agent has NO PostgreSQL, Redis, or any other CP-internal
//     runtime dependency. CI verifies that go.sum does not contain any
//     forbidden driver.
//   - Authentication is via the long-lived agent_secret minted by the
//     CP. Presented on every heartbeat AND every claim/complete in the
//     X-Agent-Secret header.
//   - Credential material lives in either env vars (SB_AGENT_ID +
//     SB_AGENT_SECRET) or a mounted K8s Secret file. No state is
//     written to disk by the agent — Pod restart re-reads the Secret.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/agent/internal/executor"
	"github.com/secrets-bridge/agent/internal/identity"
	"github.com/secrets-bridge/agent/internal/local"
	"github.com/secrets-bridge/agent/internal/observability"
)

// buildVersion is set at link time.
var buildVersion = "dev"

// Config carries the agent's runtime configuration.
type Config struct {
	CPEndpoint         string
	IdentityFile       string
	LocalAddr          string
	HeartbeatInterval  time.Duration
	ClaimInterval      time.Duration
	ClaimConcurrency   int
	ShutdownGrace      time.Duration
}

// Env var names for credential material.
const (
	envAgentID     = "SB_AGENT_ID"
	envAgentSecret = "SB_AGENT_SECRET"
)

func main() {
	cfg := loadConfig()
	logger := observability.NewLogger(os.Getenv("LOG_LEVEL"))
	slog.SetDefault(logger)

	logger.Info("starting secrets-bridge agent",
		"version", buildVersion,
		"cp_endpoint", cfg.CPEndpoint,
		"identity_file", cfg.IdentityFile,
		"local_addr", cfg.LocalAddr,
		"heartbeat_interval", cfg.HeartbeatInterval,
		"claim_interval", cfg.ClaimInterval,
		"claim_concurrency", cfg.ClaimConcurrency,
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	id, src, err := identity.Load(envAgentID, envAgentSecret, cfg.IdentityFile)
	if err != nil {
		logger.Error("identity load failed", "error", err)
		os.Exit(1)
	}
	logger.Info("identity loaded", "source", string(src), "agent_id", id.AgentID)

	httpClient := client.New(cfg.CPEndpoint)

	// PatchExecutor wires the wrap-fetch client + a provider resolver.
	// The resolver is intentionally inert here: it returns a "provider
	// not configured" error so patch jobs FAIL LOUDLY rather than
	// silently no-op. The concrete vault / awssm resolvers land in a
	// follow-up so this PR doesn't drag cloud SDKs into the agent
	// binary footprint until they're actually wired.
	patch := executor.PatchExecutor{
		AgentID:         id.AgentID,
		AgentSecret:     id.AgentSecret,
		Client:          httpClient,
		ResolveProvider: executor.NotConfiguredResolver,
	}
	exec := executor.Router{
		ByType: map[string]executor.Executor{
			"patch": patch,
		},
		Default: executor.NoOp{},
	}

	probes := local.NewProbes()
	probes.SetReady(true)
	localServer := local.NewServer(cfg.LocalAddr, probes, logger)
	go func() {
		if err := localServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("local server exited", "error", err)
		}
	}()

	// Two loops share the same ctx so SIGTERM cancels both. WaitGroup
	// blocks main from exiting until both have drained.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); heartbeatLoop(ctx, logger, cfg, httpClient, id) }()
	go func() { defer wg.Done(); claimLoop(ctx, logger, cfg, httpClient, exec, id) }()

	wg.Wait()
	logger.Info("loops drained; shutting down local server")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	_ = localServer.Shutdown(shutdownCtx)
	logger.Info("shutdown complete")
}

// heartbeatLoop calls /heartbeat at HeartbeatInterval forever (until
// ctx is cancelled). Network errors are logged and retried at the next
// interval; an Unauthorized response is fatal because either the
// identity was revoked or the credential is wrong — either way the
// caller must rotate.
func heartbeatLoop(ctx context.Context, logger *slog.Logger, cfg Config, c *client.Client, id identity.Identity) {
	t := time.NewTicker(cfg.HeartbeatInterval)
	defer t.Stop()

	if err := beatOnce(ctx, logger, c, id); errors.Is(err, client.ErrUnauthorized) {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := beatOnce(ctx, logger, c, id); errors.Is(err, client.ErrUnauthorized) {
				return
			}
		}
	}
}

func beatOnce(ctx context.Context, logger *slog.Logger, c *client.Client, id identity.Identity) error {
	hbCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := c.Heartbeat(hbCtx, id.AgentID, id.AgentSecret); err != nil {
		logger.Warn("heartbeat failed", "error", err)
		return err
	}
	logger.Debug("heartbeat ok")
	return nil
}

// claimLoop polls the CP for runnable jobs and dispatches each to a
// worker pool. Concurrency is bounded by ClaimConcurrency — a
// semaphore prevents the agent from claiming faster than it can
// execute.
func claimLoop(ctx context.Context, logger *slog.Logger, cfg Config, c *client.Client, exec executor.Executor, id identity.Identity) {
	t := time.NewTicker(cfg.ClaimInterval)
	defer t.Stop()

	sem := make(chan struct{}, cfg.ClaimConcurrency)
	var inflight sync.WaitGroup

	defer func() {
		// Graceful shutdown: wait for in-flight jobs to complete so we
		// don't leak a claimed-but-unreported execution.
		logger.Info("claim loop draining", "in_flight", len(sem))
		inflight.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			claimOne(ctx, logger, c, exec, id, sem, &inflight)
		}
	}
}

// claimOne attempts a single claim. On success it dispatches the job
// to a goroutine that executes and reports completion. Slot acquisition
// is non-blocking — if the pool is full we skip this tick.
func claimOne(ctx context.Context, logger *slog.Logger, c *client.Client, exec executor.Executor, id identity.Identity, sem chan struct{}, inflight *sync.WaitGroup) {
	// Don't even bother claiming if there's no room to execute. Better
	// to let another agent claim than to hold a claim that we won't
	// process until later.
	select {
	case sem <- struct{}{}:
	default:
		return
	}

	claimCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	job, err := c.ClaimJob(claimCtx, id.AgentID, id.AgentSecret)
	cancel()
	if err != nil {
		<-sem
		switch {
		case errors.Is(err, client.ErrNoJobs):
			// Normal — queue empty. Debug level so we don't spam logs.
			logger.Debug("no jobs in queue")
		case errors.Is(err, client.ErrUnauthorized):
			// Fatal — identity is gone. The loop's outer select will
			// observe the context (canceled by signal) — but the
			// agent process won't exit just on this. Log loudly.
			logger.Error("claim rejected — identity revoked?", "error", err)
		default:
			logger.Warn("claim failed", "error", err)
		}
		return
	}

	inflight.Add(1)
	go func() {
		defer inflight.Done()
		defer func() { <-sem }()
		processJob(ctx, logger, c, exec, id, job)
	}()
}

// processJob runs the executor and reports the outcome. Honors both the
// process-wide ctx (SIGTERM) and the claim deadline returned by the CP
// (so a stuck job doesn't outlive its lease and silently get
// re-claimed by someone else).
func processJob(parentCtx context.Context, logger *slog.Logger, c *client.Client, exec executor.Executor, id identity.Identity, job *client.Job) {
	logger.Info("job claimed",
		"job_id", job.ID,
		"job_type", job.JobType,
		"correlation_id", job.CorrelationID,
	)

	// Bound the execution by min(claim deadline, 60s) so the agent
	// can't sit on a lease forever even if the executor hangs.
	execCtx, cancel := claimBoundedContext(parentCtx, job, 60*time.Second)
	defer cancel()

	outcome := exec.Execute(execCtx, job)

	completeCtx, ccancel := context.WithTimeout(parentCtx, 10*time.Second)
	defer ccancel()
	if err := c.CompleteJob(completeCtx, id.AgentID, id.AgentSecret, job.ID, outcome); err != nil {
		switch {
		case errors.Is(err, client.ErrClaimLost):
			logger.Warn("claim lost — outcome dropped",
				"job_id", job.ID,
				"outcome", outcome.Status,
			)
		default:
			logger.Error("complete failed",
				"job_id", job.ID,
				"outcome", outcome.Status,
				"error", err,
			)
		}
		return
	}
	logger.Info("job completed",
		"job_id", job.ID,
		"outcome", outcome.Status,
	)
}

// claimBoundedContext returns a context that expires at the earliest of
// (parent ctx), (claim deadline minus a small margin), or (now + fallback).
func claimBoundedContext(parent context.Context, job *client.Job, fallback time.Duration) (context.Context, context.CancelFunc) {
	deadline := job.ClaimDeadline()
	if deadline.IsZero() {
		return context.WithTimeout(parent, fallback)
	}
	// Subtract a small safety margin so we Complete before the lease
	// actually expires; otherwise the row could rotate to another
	// agent before our complete lands.
	deadline = deadline.Add(-2 * time.Second)
	if d := time.Until(deadline); d < fallback {
		return context.WithDeadline(parent, deadline)
	}
	return context.WithTimeout(parent, fallback)
}
