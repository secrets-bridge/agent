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
//     CP. Presented on every heartbeat in the X-Agent-Secret header.
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
	"syscall"
	"time"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/agent/internal/identity"
	"github.com/secrets-bridge/agent/internal/local"
	"github.com/secrets-bridge/agent/internal/observability"
)

// buildVersion is set at link time.
var buildVersion = "dev"

// Config carries the agent's runtime configuration.
type Config struct {
	// CPEndpoint is the Control Plane API base URL.
	CPEndpoint string

	// IdentityFile is the path to a JSON identity file:
	//   {"agent_id": "...", "agent_secret": "..."}
	// Used as a fallback when SB_AGENT_ID / SB_AGENT_SECRET env vars
	// are not set. K8s docs recommend file mode over env mode for
	// credentials; this is the default.
	IdentityFile string

	// LocalAddr is the address the local probe + metrics server binds
	// to. Defaults to 127.0.0.1:8090 (loopback only) so the agent has
	// no public listener.
	LocalAddr string

	// HeartbeatInterval is the time between heartbeats.
	HeartbeatInterval time.Duration

	// ShutdownGrace bounds the graceful-shutdown wait.
	ShutdownGrace time.Duration
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

	probes := local.NewProbes()
	probes.SetReady(true)
	localServer := local.NewServer(cfg.LocalAddr, probes, logger)
	go func() {
		if err := localServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("local server exited", "error", err)
		}
	}()

	if err := heartbeatLoop(ctx, logger, cfg, httpClient, id); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("heartbeat loop exited", "error", err)
	}

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
func heartbeatLoop(ctx context.Context, logger *slog.Logger, cfg Config, c *client.Client, id identity.Identity) error {
	t := time.NewTicker(cfg.HeartbeatInterval)
	defer t.Stop()

	// Beat once immediately so the CP sees us as alive right after
	// startup, then settle into the configured cadence.
	if err := beatOnce(ctx, logger, c, id); err != nil {
		if errors.Is(err, client.ErrUnauthorized) {
			return err
		}
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			err := beatOnce(ctx, logger, c, id)
			if errors.Is(err, client.ErrUnauthorized) {
				return err
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
