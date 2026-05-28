package main

import (
	"flag"
	"os"
	"time"
)

// loadConfig reads the agent's configuration from env vars and CLI flags.
func loadConfig() Config {
	cfg := Config{
		CPEndpoint:        envOr("SB_CP_ENDPOINT", ""),
		IdentityFile:      envOr("SB_IDENTITY_FILE", "/etc/secrets-bridge/identity.json"),
		LocalAddr:         envOr("SB_LOCAL_ADDR", "127.0.0.1:8090"),
		HeartbeatInterval: envDuration("SB_HEARTBEAT_INTERVAL", 30*time.Second),
		ShutdownGrace:     envDuration("SB_SHUTDOWN_GRACE", 15*time.Second),
	}

	flag.StringVar(&cfg.CPEndpoint, "cp-endpoint", cfg.CPEndpoint,
		"Control Plane API base URL (also SB_CP_ENDPOINT)")
	flag.StringVar(&cfg.IdentityFile, "identity-file", cfg.IdentityFile,
		"JSON identity file {agent_id, agent_secret} (also SB_IDENTITY_FILE). "+
			"Ignored when SB_AGENT_ID + SB_AGENT_SECRET env vars are set.")
	flag.StringVar(&cfg.LocalAddr, "local-addr", cfg.LocalAddr,
		"address for /healthz /readyz /metrics; loopback by default (also SB_LOCAL_ADDR)")
	flag.DurationVar(&cfg.HeartbeatInterval, "heartbeat-interval", cfg.HeartbeatInterval,
		"time between heartbeats (also SB_HEARTBEAT_INTERVAL)")
	flag.DurationVar(&cfg.ShutdownGrace, "shutdown-grace", cfg.ShutdownGrace,
		"graceful-shutdown deadline (also SB_SHUTDOWN_GRACE)")
	flag.Parse()

	if cfg.CPEndpoint == "" {
		panic("agent: SB_CP_ENDPOINT (or --cp-endpoint) is required")
	}
	return cfg
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
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
