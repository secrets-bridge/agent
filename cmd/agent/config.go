package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/secrets-bridge/agent/internal/cli"
	"github.com/secrets-bridge/agent/internal/identity"
)

// errHelp is returned by loadConfig after printing -h output.
var errHelp = errors.New("help requested")

// loadConfig reads the runtime configuration from env vars and flags.
// Credentials are not configuration: they come only from the files in
// CredentialsDir.
func loadConfig(args []string, stderr io.Writer) (Config, error) {
	cfg := Config{
		CPEndpoint:        envOr("SB_CP_ENDPOINT", ""),
		CredentialsDir:    envOr("SB_AGENT_CREDENTIALS_DIR", identity.DefaultCredentialsDir),
		LocalAddr:         envOr("SB_LOCAL_ADDR", "127.0.0.1:8090"),
		HeartbeatInterval: envDuration("SB_HEARTBEAT_INTERVAL", 30*time.Second),
		ClaimInterval:     envDuration("SB_CLAIM_INTERVAL", 5*time.Second),
		ClaimConcurrency:  envInt("SB_CLAIM_CONCURRENCY", 4),
		ShutdownGrace:     envDuration("SB_SHUTDOWN_GRACE", 15*time.Second),
		ClusterName:       envOr("SB_CLUSTER_NAME", ""),
		InsecureTransport: envBool("SB_INSECURE_TRANSPORT", false),
		CAFile:            envOr("SB_CP_CA_FILE", ""),
		TLSServerName:     envOr("SB_CP_TLS_SERVER_NAME", ""),
	}

	fs := flag.NewFlagSet("secrets-bridge-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, cli.Usage+"\nAgent runtime flags:\n")
		fs.PrintDefaults()
	}
	fs.StringVar(&cfg.CPEndpoint, "cp-endpoint", cfg.CPEndpoint,
		"Control Plane API base URL (also SB_CP_ENDPOINT)")
	fs.StringVar(&cfg.CredentialsDir, "credentials-dir", cfg.CredentialsDir,
		"read-only directory with agent_id, agent_secret and private_key (also SB_AGENT_CREDENTIALS_DIR)")
	fs.StringVar(&cfg.LocalAddr, "local-addr", cfg.LocalAddr,
		"address for /healthz /readyz /metrics; loopback by default (also SB_LOCAL_ADDR)")
	fs.DurationVar(&cfg.HeartbeatInterval, "heartbeat-interval", cfg.HeartbeatInterval,
		"fallback time between heartbeats when the CP suggests none (also SB_HEARTBEAT_INTERVAL)")
	fs.DurationVar(&cfg.ClaimInterval, "claim-interval", cfg.ClaimInterval,
		"time between job claim polls (also SB_CLAIM_INTERVAL)")
	fs.IntVar(&cfg.ClaimConcurrency, "claim-concurrency", cfg.ClaimConcurrency,
		"max in-flight jobs (also SB_CLAIM_CONCURRENCY)")
	fs.DurationVar(&cfg.ShutdownGrace, "shutdown-grace", cfg.ShutdownGrace,
		"graceful-shutdown deadline (also SB_SHUTDOWN_GRACE)")
	fs.StringVar(&cfg.ClusterName, "cluster-name", cfg.ClusterName,
		"cluster identity stamped on discovered secrets (also SB_CLUSTER_NAME)")
	fs.BoolVar(&cfg.InsecureTransport, "insecure-transport", cfg.InsecureTransport,
		"allow plain http:// to the CP (DEV ONLY; also SB_INSECURE_TRANSPORT)")
	fs.StringVar(&cfg.CAFile, "cp-ca-file", cfg.CAFile,
		"path to a CA bundle to trust for the CP cert (also SB_CP_CA_FILE)")
	fs.StringVar(&cfg.TLSServerName, "cp-tls-server-name", cfg.TLSServerName,
		"override TLS SNI / cert verification hostname (also SB_CP_TLS_SERVER_NAME)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return Config{}, errHelp
		}
		return Config{}, err
	}
	if fs.NArg() != 0 {
		return Config{}, errors.New("unexpected positional argument (not echoed)")
	}
	if cfg.CPEndpoint == "" {
		return Config{}, errors.New("SB_CP_ENDPOINT (or --cp-endpoint) is required")
	}
	return cfg, nil
}

func envBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
