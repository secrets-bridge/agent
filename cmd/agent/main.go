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
	"encoding/base64"
	"errors"
	"fmt"
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
	CPEndpoint        string
	IdentityFile      string
	LocalAddr         string
	HeartbeatInterval time.Duration
	ClaimInterval     time.Duration
	ClaimConcurrency  int
	ShutdownGrace     time.Duration
	// ClusterName identifies this agent's boundary (e.g. "prod-eu",
	// "uat-archive-account"). Required for discover jobs — the agent
	// stamps every discovered secret with this name so the CP can
	// disambiguate the same secret_ref across clusters. Optional for
	// patch/read jobs (they're scoped via target_secret_ref).
	ClusterName string

	// Transit-security knobs. Default posture: REQUIRE https://. The
	// agent refuses to start on http:// unless InsecureTransport is
	// explicitly true. Production deployments should never set
	// InsecureTransport; it exists for `docker compose` dev only.
	//
	// CAFile + TLSServerName let operators pin the CP's CA / SNI when
	// the CP serves TLS behind a private CA or a mismatching cert.
	InsecureTransport bool
	CAFile            string
	TLSServerName     string

	// Enroll-on-first-boot (agent-1). Enrollment runs ONLY when no stored
	// credential exists (env vars or a populated IdentityFile) AND
	// EnrollmentEnabled is true AND EnrollmentToken is non-empty. The
	// returned agent_token is persisted to IdentityFile so a restart
	// reuses it and never spends a second token.
	EnrollmentEnabled bool
	EnrollmentToken   string
	AgentName         string
	ProviderType      string
	Region            string
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

	// Transit-security gate: refuse plain http:// unless explicitly
	// opted in. Fails fast so a misconfigured deployment never starts
	// rather than silently leaking plaintext on the wire.
	endpointURL, err := validateEndpoint(cfg.CPEndpoint, cfg.InsecureTransport)
	if err != nil {
		logger.Error("endpoint validation failed", "error", err)
		os.Exit(1)
	}
	if cfg.InsecureTransport {
		logger.Warn("SB_INSECURE_TRANSPORT=true — plaintext over the wire; do NOT use in production",
			"endpoint", endpointURL.Redacted())
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Load (or generate) the X25519 keypair used for wire-envelope
	// encryption with the CP (Piece 8b). Private key never leaves this
	// process; the public key is registered after the credential is
	// resolved so the CP can start sealing future responses.
	kp, err := identity.LoadOrGenerateKeyPair(identity.EnvPrivateKey, identity.EnvPrivateKeyFile)
	if err != nil {
		logger.Error("keypair load failed", "error", err)
		os.Exit(1)
	}
	logger.Info("wire-envelope keypair ready",
		"source", string(kp.Source),
		"public_key_b64", base64.StdEncoding.EncodeToString(kp.Public))
	if kp.Source == identity.KeyPairSourceEphemeral {
		logger.Warn("wire-envelope keypair is EPHEMERAL — set SB_AGENT_PRIVATE_KEY[_FILE] for persistence; sealed wraps unconsumed at restart will be unrecoverable")
	}

	// Build the CP client BEFORE resolving the credential — enroll-on-
	// first-boot needs it to call /agents/enroll.
	transportClient, err := buildHTTPClient(cfg)
	if err != nil {
		logger.Error("transport setup failed", "error", err)
		os.Exit(1)
	}
	httpClient := client.New(cfg.CPEndpoint).WithHTTPClient(transportClient)

	// Resolve the agent credential: use a stored one (env vars or a
	// populated identity file) if present; otherwise enroll-on-first-boot
	// with the one-time token and persist the result. Fails closed when
	// neither is available. The token + returned agent_token are never
	// logged.
	id, src, err := resolveIdentity(ctx, &cfg, httpClient, logger)
	if err != nil {
		logger.Error("agent credential not available", "error", err)
		os.Exit(1)
	}
	logger.Info("identity ready", "source", string(src), "agent_id", id.AgentID)

	// Register the public key with the CP so future GetWrap responses
	// come SEALED. Idempotent — CP no-ops if we already have this key.
	// Failure here doesn't kill the agent: fall back to the legacy
	// plaintext-over-TLS path so the daemon stays useful.
	if err := httpClient.SetPublicKey(ctx, id.AgentID, id.AgentSecret, kp.Public, "x25519"); err != nil {
		logger.Warn("public-key registration failed — falling back to plaintext-over-TLS",
			"error", err)
	} else {
		logger.Info("public key registered with CP — sealed wire-envelope active")
	}

	// PatchExecutor wires the wrap-fetch client + the dispatching
	// provider resolver. ResolverByType registers each provider kind
	// that's compiled in (vault today; aws-sm + others land as they're
	// implemented). Unknown providerType values fall through to
	// NotConfiguredResolver so the job fails loud.
	patch := executor.PatchExecutor{
		AgentID:         id.AgentID,
		AgentSecret:     id.AgentSecret,
		AgentPublicKey:  kp.Public,
		AgentPrivateKey: kp.Private,
		Client:          httpClient,
		ResolveProvider: executor.ResolverByType(ctx),
	}
	discover := executor.DiscoverExecutor{
		AgentID:         id.AgentID,
		AgentSecret:     id.AgentSecret,
		ClusterName:     cfg.ClusterName,
		Client:          httpClient,
		ResolveProvider: executor.ResolverByType(ctx),
	}
	read := executor.ReadExecutor{
		AgentID:         id.AgentID,
		AgentSecret:     id.AgentSecret,
		AgentPublicKey:  kp.Public,
		AgentPrivateKey: kp.Private,
		Client:          httpClient,
		ResolveProvider: executor.ResolverByType(ctx),
	}
	exec := executor.Router{
		ByType: map[string]executor.Executor{
			"patch":    patch,
			"read":     read,
			"discover": discover,
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

// heartbeatLoop beats the CP at a SERVER-DRIVEN cadence: each heartbeat
// carries a small runtime body and the CP replies with next_heartbeat_
// seconds, which sets the next interval. When the CP omits it (or replies
// 204), the loop falls back to the configured HeartbeatInterval. An
// Unauthorized response is fatal — the identity was revoked or the
// credential is wrong, so the loop stops rather than spin.
func heartbeatLoop(ctx context.Context, logger *slog.Logger, cfg Config, c *client.Client, id identity.Identity) {
	interval := cfg.HeartbeatInterval
	report := &client.HeartbeatReport{Status: "active", AgentVersion: buildVersion}

	// First beat immediately so the CP sees us alive right after startup.
	if next, err := beatOnce(ctx, logger, c, id, report, cfg.HeartbeatInterval); errors.Is(err, client.ErrUnauthorized) {
		return
	} else if next > 0 {
		interval = next
	}

	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			next, err := beatOnce(ctx, logger, c, id, report, cfg.HeartbeatInterval)
			if errors.Is(err, client.ErrUnauthorized) {
				return
			}
			if next > 0 {
				interval = next
			}
			timer.Reset(interval)
		}
	}
}

// beatOnce sends one heartbeat and returns the server-suggested next
// interval (0 when absent → caller keeps its current interval). fallback is
// used only for logging clarity; the caller owns the fallback interval.
func beatOnce(ctx context.Context, logger *slog.Logger, c *client.Client, id identity.Identity, report *client.HeartbeatReport, fallback time.Duration) (time.Duration, error) {
	hbCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res, err := c.Heartbeat(hbCtx, id.AgentID, id.AgentSecret, report)
	if err != nil {
		logger.Warn("heartbeat failed", "error", err)
		return 0, err
	}
	var next time.Duration
	if res != nil && res.NextHeartbeatSeconds > 0 {
		next = time.Duration(res.NextHeartbeatSeconds) * time.Second
	}
	logger.Debug("heartbeat ok", "next_heartbeat_seconds", nextSeconds(res))
	return next, nil
}

func nextSeconds(res *client.HeartbeatResult) int {
	if res == nil {
		return 0
	}
	return res.NextHeartbeatSeconds
}

// resolveIdentity returns the agent's credential. Precedence:
//
//  1. Stored credential — env vars (SB_AGENT_ID + SB_AGENT_SECRET) or a
//     populated identity file. Covers the legacy static-secret path AND an
//     enrolled agent that already persisted its credential (restart reuse).
//  2. No stored credential + enrollment enabled + a token present → enroll
//     once, persist the returned credential to the identity file, and seed
//     the heartbeat/claim intervals from the response.
//  3. Otherwise → fail closed with a safe error.
//
// The enrollment token and the returned agent_token are never logged,
// printed, or wrapped into an error.
func resolveIdentity(ctx context.Context, cfg *Config, c *client.Client, logger *slog.Logger) (identity.Identity, identity.Source, error) {
	id, src, err := identity.LoadStored(envAgentID, envAgentSecret, cfg.IdentityFile)
	switch {
	case err == nil:
		return id, src, nil
	case !errors.Is(err, identity.ErrNotConfigured):
		// Partial env config or a corrupt file — a real misconfiguration.
		return identity.Identity{}, "", err
	}

	// No stored credential — the enroll-on-first-boot path.
	if !cfg.EnrollmentEnabled || cfg.EnrollmentToken == "" {
		return identity.Identity{}, "", errors.New(
			"agent credential not configured: set SB_AGENT_ID+SB_AGENT_SECRET, mount a " +
				"populated identity file, or provide SB_ENROLLMENT_TOKEN with SB_ENROLLMENT_ENABLED=true")
	}

	name := cfg.AgentName
	if name == "" {
		if hn, herr := os.Hostname(); herr == nil {
			name = hn
		}
	}
	logger.Info("no stored credential — enrolling with CP",
		"agent_name", name, "provider_type", cfg.ProviderType, "cluster_name", cfg.ClusterName)

	res, err := c.Enroll(ctx, client.EnrollRequest{
		EnrollmentToken: cfg.EnrollmentToken,
		AgentName:       name,
		ProviderType:    cfg.ProviderType,
		ClusterName:     cfg.ClusterName,
		AgentVersion:    buildVersion,
		Region:          cfg.Region,
	})
	if err != nil {
		// err carries only a safe reason code — never the token.
		return identity.Identity{}, "", fmt.Errorf("enrollment failed: %w", err)
	}

	newID := identity.Identity{AgentID: res.AgentID, AgentSecret: res.AgentToken}
	if err := identity.Save(cfg.IdentityFile, newID); err != nil {
		// The token is now consumed but we couldn't persist the result —
		// surface loudly so the operator fixes the writable path or issues
		// a fresh token instead of CrashLooping on a spent token.
		return identity.Identity{}, "", fmt.Errorf(
			"enrolled but FAILED to persist credential to %q (token is now consumed; "+
				"use a writable, restart-persistent identity path or issue a fresh token): %w",
			cfg.IdentityFile, err)
	}
	logger.Info("enrolled and persisted credential",
		"agent_id", res.AgentID,
		"provider_connection_id", res.ProviderConnectionID,
		"identity_file", cfg.IdentityFile)

	applyEnrollIntervals(cfg, res)
	return newID, identity.SourceEnrolled, nil
}

// applyEnrollIntervals seeds the heartbeat/claim cadence from the enrollment
// response, but only for a knob the operator did NOT explicitly set via env
// var (an explicit setting always wins). Heartbeat cadence is further
// refined per-beat by next_heartbeat_seconds; claim cadence is fixed.
func applyEnrollIntervals(cfg *Config, res *client.EnrollResult) {
	if _, set := os.LookupEnv("SB_HEARTBEAT_INTERVAL"); !set && res.HeartbeatIntervalSeconds > 0 {
		cfg.HeartbeatInterval = time.Duration(res.HeartbeatIntervalSeconds) * time.Second
	}
	if _, set := os.LookupEnv("SB_CLAIM_INTERVAL"); !set && res.JobPollIntervalSeconds > 0 {
		cfg.ClaimInterval = time.Duration(res.JobPollIntervalSeconds) * time.Second
	}
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
