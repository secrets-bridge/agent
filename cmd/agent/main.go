// Command agent is the Secrets Bridge outbound execution agent.
//
// It runs INSIDE a target boundary (a Kubernetes cluster, a private VPC,
// a customer account) and communicates ONLY outbound to the Control
// Plane API and to the local secrets provider. There is no inbound
// listener on a public network interface; the only HTTP server is a
// loopback /healthz /readyz /metrics endpoint for kubelet + Prometheus.
//
// The same binary carries two operator subcommands, enroll and
// rotate-key (internal/cli), which create the credential bundle. Run with
// no subcommand it is the agent runtime.
//
// Hard rules (BRD §15, §24, NFR-09):
//   - The agent has NO PostgreSQL, Redis, or any other CP-internal
//     runtime dependency. CI verifies that go.sum does not contain any
//     forbidden driver.
//   - The runtime reads agent_id, agent_secret and private_key from a
//     read-only credentials directory (SB_AGENT_CREDENTIALS_DIR) and
//     nothing else. It never writes a file, never generates a key and
//     fails closed when a file is missing, malformed or too open. A
//     restart re-reads the same files.
//   - Every CP call carries X-Agent-Secret and X-Agent-Key-Fingerprint.
//     A 401 (revoked) or 409 agent_key_mismatch (rotated key) stops the
//     agent with a non-zero exit.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/secrets-bridge/agent/internal/cli"
	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/agent/internal/executor"
	"github.com/secrets-bridge/agent/internal/identity"
	"github.com/secrets-bridge/agent/internal/local"
	"github.com/secrets-bridge/agent/internal/observability"
	"github.com/secrets-bridge/agent/internal/transport"
)

// buildVersion is set at link time.
var buildVersion = "dev"

// capabilities are the job types this agent executes, reported on every
// heartbeat. Keep in step with newRouter.
var capabilities = []string{"discover", "patch", "read"}

// Config carries the agent's runtime configuration.
type Config struct {
	CPEndpoint        string
	CredentialsDir    string
	LocalAddr         string
	HeartbeatInterval time.Duration
	ClaimInterval     time.Duration
	ClaimConcurrency  int
	ShutdownGrace     time.Duration
	// ClusterName identifies this agent's boundary (e.g. "prod-eu").
	// Required for discover jobs: the agent stamps every discovered
	// secret with this name so the CP can tell the same secret_ref apart
	// across clusters.
	ClusterName string

	// Transit security. The agent refuses http:// unless
	// InsecureTransport is set (docker compose dev only). CAFile and
	// TLSServerName pin the CP's CA and SNI.
	InsecureTransport bool
	CAFile            string
	TLSServerName     string
}

// retryBackoff is an exponential backoff between attempts, capped at max.
type retryBackoff struct {
	initial time.Duration
	max     time.Duration
}

// startupRetry paces the first heartbeat at boot. A variable so tests can
// shrink it.
var startupRetry = retryBackoff{initial: time.Second, max: time.Minute}

// isFatal reports a CP answer that must stop the agent: the credential is
// revoked (401) or the bound key is not ours (409 agent_key_mismatch).
func isFatal(err error) bool {
	return errors.Is(err, client.ErrUnauthorized) || errors.Is(err, client.ErrKeyMismatch)
}

func main() {
	os.Exit(dispatch(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// dispatch picks the subcommand. No subcommand (or only flags) runs the
// agent.
func dispatch(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "enroll":
			return cli.Enroll(context.Background(), args[1:], stdin, stdout, stderr)
		case "rotate-key":
			return cli.RotateKey(context.Background(), args[1:], stdin, stdout, stderr)
		case "help":
			_, _ = fmt.Fprint(stderr, cli.Usage)
			return 0
		}
		if len(args[0]) > 0 && args[0][0] != '-' {
			_, _ = fmt.Fprintf(stderr, "error: unknown command %q\n\n%s", args[0], cli.Usage)
			return 2
		}
	}
	return runAgent(args, stderr)
}

// runAgent is the agent runtime.
func runAgent(args []string, stderr io.Writer) int {
	cfg, err := loadConfig(args, stderr)
	if err != nil {
		if errors.Is(err, errHelp) {
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	logger := observability.NewLogger(stderr, os.Getenv("LOG_LEVEL"))
	slog.SetDefault(logger)

	logger.Info("starting secrets-bridge agent",
		"version", buildVersion,
		"cp_endpoint", transport.RedactEndpoint(cfg.CPEndpoint),
		"credentials_dir", cfg.CredentialsDir,
		"local_addr", cfg.LocalAddr,
		"heartbeat_interval", cfg.HeartbeatInterval,
		"claim_interval", cfg.ClaimInterval,
		"claim_concurrency", cfg.ClaimConcurrency,
	)

	// Transit-security gate: refuse plain http:// unless explicitly
	// opted in.
	endpointURL, err := transport.ValidateEndpoint(cfg.CPEndpoint, cfg.InsecureTransport)
	if err != nil {
		logger.Error("endpoint validation failed", "error", err)
		return 1
	}
	if cfg.InsecureTransport {
		logger.Warn("SB_INSECURE_TRANSPORT=true: plaintext over the wire; do NOT use in production",
			"endpoint", transport.RedactEndpoint(endpointURL.String()))
	}

	// Credentials come only from the read-only directory. Fail closed.
	id, kp, err := identity.Load(cfg.CredentialsDir)
	if err != nil {
		logger.Error("agent credentials not usable; refusing to start (create them with secrets-bridge-agent enroll and mount them read-only)",
			"credentials_dir", cfg.CredentialsDir, "error", err)
		return 1
	}
	logger.Info("credentials loaded",
		"agent_id", id.AgentID,
		"public_key_fingerprint", kp.Fingerprint)

	hc, err := transport.NewHTTPClient(transport.Options{
		CPEndpoint:        cfg.CPEndpoint,
		InsecureTransport: cfg.InsecureTransport,
		CAFile:            cfg.CAFile,
		TLSServerName:     cfg.TLSServerName,
	})
	if err != nil {
		logger.Error("transport setup failed", "error", err)
		return 1
	}
	cpClient := client.New(cfg.CPEndpoint).WithHTTPClient(hc).WithKeyFingerprint(kp.Fingerprint)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Probes come up first so liveness passes while the agent waits for
	// the CP; readiness stays false until the first heartbeat succeeds.
	probes := local.NewProbes()
	localServer := local.NewServer(cfg.LocalAddr, probes, logger)
	go func() {
		if err := localServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("local server exited", "error", err)
		}
	}()

	runErr := run(ctx, logger, cfg, cpClient, id, kp, executor.ResolverByType(ctx), probes)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	_ = localServer.Shutdown(shutdownCtx)
	if runErr != nil {
		logger.Error(fatalMessage(runErr), "error", runErr)
		return 1
	}
	logger.Info("shutdown complete")
	return 0
}

// fatalMessage explains a fatal stop to the operator.
func fatalMessage(err error) string {
	switch {
	case errors.Is(err, client.ErrKeyMismatch):
		return "agent_key_mismatch: the control plane has a different public key bound to this agent " +
			"(the key was rotated, or this pod mounts the wrong Secret); update the Secret with the current bundle and restart"
	case errors.Is(err, client.ErrUnauthorized):
		return "the control plane rejected the agent credential (revoked or wrong agent_secret); enroll a new agent"
	default:
		return "agent stopped"
	}
}

// run takes over once the agent has its credentials.
//
// It first sends one heartbeat, retrying transient failures with backoff,
// so a revoked credential or a mismatched key is reported before any job
// is claimed. It then marks the agent ready and runs the heartbeat and
// claim loops until ctx ends or the CP returns a fatal answer (401 or 409
// agent_key_mismatch), which is returned. A clean shutdown returns nil.
func run(ctx context.Context, logger *slog.Logger, cfg Config, c *client.Client, id identity.Identity, kp *identity.KeyPair, resolve executor.ProviderResolver, probes *local.Probes) error {
	report := &client.HeartbeatReport{Status: "active", AgentVersion: buildVersion, Capabilities: capabilities}
	next, err := firstHeartbeat(ctx, logger, c, id, report, startupRetry)
	if err != nil {
		if ctx.Err() != nil && !isFatal(err) {
			return nil
		}
		return err
	}
	logger.Info("control plane accepted the credential and key; sealed wire-envelope active")

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		fatalOnce sync.Once
		fatalErr  error
	)
	fatal := func(err error) {
		fatalOnce.Do(func() {
			fatalErr = err
			cancel()
		})
	}

	exec := newRouter(cfg, c, id, kp, resolve)
	probes.SetReady(true)

	interval := cfg.HeartbeatInterval
	if next > 0 {
		interval = next
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); heartbeatLoop(runCtx, logger, cfg, c, id, report, interval, fatal) }()
	go func() { defer wg.Done(); claimLoop(runCtx, logger, cfg, c, exec, id, fatal) }()
	wg.Wait()
	probes.SetReady(false)
	logger.Info("loops drained")
	return fatalErr
}

// firstHeartbeat sends the boot heartbeat until the CP answers. A fatal
// answer is returned at once; anything else is retried with backoff.
func firstHeartbeat(ctx context.Context, logger *slog.Logger, c *client.Client, id identity.Identity, report *client.HeartbeatReport, b retryBackoff) (time.Duration, error) {
	delay := b.initial
	for attempt := 1; ; attempt++ {
		next, err := beatOnce(ctx, logger, c, id, report)
		if err == nil {
			return next, nil
		}
		if isFatal(err) {
			return 0, err
		}
		logger.Warn("first heartbeat failed; no job will be claimed until it succeeds",
			"attempt", attempt, "retry_in", delay.String(), "error", err)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, fmt.Errorf("first heartbeat did not complete: %w", ctx.Err())
		case <-timer.C:
		}
		delay = min(delay*2, b.max)
	}
}

// newRouter wires the per-type executors. Every executor that moves a
// value gets the wire key; job types not listed here fail as
// unsupported (AGT-N-06).
func newRouter(cfg Config, c *client.Client, id identity.Identity, kp *identity.KeyPair, resolve executor.ProviderResolver) executor.Router {
	return executor.Router{
		ByType: map[string]executor.Executor{
			"patch": executor.PatchExecutor{
				AgentID:         id.AgentID,
				AgentSecret:     id.AgentSecret,
				AgentPublicKey:  kp.Public,
				AgentPrivateKey: kp.Private,
				Client:          c,
				ResolveProvider: resolve,
			},
			"read": executor.ReadExecutor{
				AgentID:         id.AgentID,
				AgentSecret:     id.AgentSecret,
				AgentPublicKey:  kp.Public,
				AgentPrivateKey: kp.Private,
				Client:          c,
				ResolveProvider: resolve,
			},
			"discover": executor.DiscoverExecutor{
				AgentID:         id.AgentID,
				AgentSecret:     id.AgentSecret,
				ClusterName:     cfg.ClusterName,
				Client:          c,
				ResolveProvider: resolve,
			},
		},
	}
}

// heartbeatLoop beats the CP at a server-driven cadence: the CP's
// next_heartbeat_seconds sets the next interval, and the configured
// HeartbeatInterval is the fallback. A fatal answer (401 or 409
// agent_key_mismatch) is handed to fatal, which stops the agent.
func heartbeatLoop(ctx context.Context, logger *slog.Logger, cfg Config, c *client.Client, id identity.Identity, report *client.HeartbeatReport, interval time.Duration, fatal func(error)) {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			next, err := beatOnce(ctx, logger, c, id, report)
			if isFatal(err) {
				fatal(err)
				return
			}
			interval = cfg.HeartbeatInterval
			if next > 0 {
				interval = next
			}
			timer.Reset(interval)
		}
	}
}

// beatOnce sends one heartbeat and returns the server-suggested next
// interval (0 when absent).
func beatOnce(ctx context.Context, logger *slog.Logger, c *client.Client, id identity.Identity, report *client.HeartbeatReport) (time.Duration, error) {
	hbCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res, err := c.Heartbeat(hbCtx, id.AgentID, id.AgentSecret, report)
	if err != nil {
		if !isFatal(err) && ctx.Err() == nil {
			logger.Warn("heartbeat failed", "error", err)
		}
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

// claimLoop polls the CP for runnable jobs and dispatches each to a
// worker pool. Concurrency is bounded by ClaimConcurrency — a
// semaphore prevents the agent from claiming faster than it can
// execute.
func claimLoop(ctx context.Context, logger *slog.Logger, cfg Config, c *client.Client, exec executor.Executor, id identity.Identity, fatal func(error)) {
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
			if err := claimOne(ctx, logger, c, exec, id, sem, &inflight); isFatal(err) {
				fatal(err)
				return
			}
		}
	}
}

// claimOne attempts a single claim. On success it dispatches the job
// to a goroutine that executes and reports completion. Slot acquisition
// is non-blocking: if the pool is full we skip this tick. It returns the
// claim error so the loop can stop on a fatal one.
func claimOne(ctx context.Context, logger *slog.Logger, c *client.Client, exec executor.Executor, id identity.Identity, sem chan struct{}, inflight *sync.WaitGroup) error {
	// Don't even bother claiming if there's no room to execute. Better
	// to let another agent claim than to hold a claim that we won't
	// process until later.
	select {
	case sem <- struct{}{}:
	default:
		return nil
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
		case isFatal(err):
			// The caller stops the agent.
		default:
			logger.Warn("claim failed", "error", err)
		}
		return err
	}

	inflight.Add(1)
	go func() {
		defer inflight.Done()
		defer func() { <-sem }()
		// Backstop: processJob already turns an executor panic into a
		// failed outcome; anything else that panics here must not take
		// the whole agent down either. Never log the panic value.
		defer func() {
			if r := recover(); r != nil {
				logger.Error("job goroutine panicked", "job_id", job.ID, "panic_type", fmt.Sprintf("%T", r))
			}
		}()
		processJob(ctx, logger, c, exec, id, job)
	}()
	return nil
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

	outcome := executeSafely(execCtx, logger, exec, job)
	logFailedJob(parentCtx, logger, job, outcome)

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

// logFailedJob writes one WARN line for a failed job with the job id,
// job type and the reason the CP will see, plus the executor's local
// context (for a read: the failing key and the counts). The reason is
// built by the executors from key names, counts, status codes and CP or
// provider error text, never from a value.
func logFailedJob(ctx context.Context, logger *slog.Logger, job *client.Job, outcome client.JobOutcome) {
	if outcome.Status != client.StatusFailed {
		return
	}
	attrs := make([]slog.Attr, 0, 4+len(outcome.LogAttrs))
	attrs = append(attrs,
		slog.String("job_id", job.ID),
		slog.String("job_type", job.JobType),
		slog.String("correlation_id", job.CorrelationID),
		slog.String("reason", outcome.Error))
	attrs = append(attrs, outcome.LogAttrs...)
	logger.LogAttrs(ctx, slog.LevelWarn, "job failed", attrs...)
}

// executeSafely runs the executor and turns a panic into a failed outcome
// (AGT-N-05): one malformed job must not kill the agent and every job it
// has in flight. The panic value is never logged or sent to the CP since
// it can carry provider responses or plaintext; only its Go type is
// logged. Deferred zeroing inside the executor still runs while the panic
// unwinds.
func executeSafely(ctx context.Context, logger *slog.Logger, exec executor.Executor, job *client.Job) (outcome client.JobOutcome) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("executor panicked; reporting the job as failed",
				"job_id", job.ID,
				"job_type", job.JobType,
				"panic_type", fmt.Sprintf("%T", r))
			outcome = client.JobOutcome{Status: client.StatusFailed, Error: "agent: executor panicked; details withheld"}
		}
	}()
	return exec.Execute(ctx, job)
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
