// Package identity loads the agent's credential material.
//
// The agent has a single long-lived credential pair (agent_id +
// agent_secret) that the CP returns at mint time. There is intentionally
// no separate registration flow — the credential is what the admin
// hands to the agent through a K8s Secret (mounted as either a file or
// env vars).
//
// Two sources are supported, in priority order:
//
//   1. Env vars:  SB_AGENT_ID + SB_AGENT_SECRET
//   2. File:      JSON at SB_IDENTITY_FILE (default
//                 /etc/secrets-bridge/identity.json), with shape
//                 {"agent_id": "...", "agent_secret": "..."}
//
// Both modes map the same K8s Secret onto the Pod — env vars use
// `env.valueFrom.secretKeyRef`, file uses a volume mount. K8s docs
// recommend file mode for credential material; env mode is supported
// for local dev and simple installs.
//
// The file is expected to be read-only — there's no longer a write
// path. A Pod restart re-reads the same Secret and resumes heartbeats.
package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Identity is the agent's long-lived credential pair.
type Identity struct {
	AgentID     string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
}

// Source describes how the identity was loaded — useful in the boot
// log so operators can see which path won.
type Source string

const (
	SourceEnv  Source = "env"
	SourceFile Source = "file"
)

// Load resolves the agent's identity from env vars or a file, in that
// priority order. envAgentID / envAgentSecret name the env vars to
// consult; filePath is the fallback file location.
//
// Returns an error if NEITHER source has both fields populated.
func Load(envAgentID, envAgentSecret, filePath string) (Identity, Source, error) {
	if id := os.Getenv(envAgentID); id != "" {
		if secret := os.Getenv(envAgentSecret); secret != "" {
			return Identity{AgentID: id, AgentSecret: secret}, SourceEnv, nil
		}
		return Identity{}, "", fmt.Errorf(
			"identity: %s is set but %s is empty",
			envAgentID, envAgentSecret,
		)
	}

	id, err := loadFromFile(filePath)
	if err != nil {
		return Identity{}, "", fmt.Errorf(
			"identity: no env vars (%s, %s) and file %q unreadable: %w",
			envAgentID, envAgentSecret, filePath, err,
		)
	}
	return id, SourceFile, nil
}

// loadFromFile reads the JSON identity file.
func loadFromFile(path string) (Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Identity{}, err
	}
	var id Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return Identity{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if id.AgentID == "" || id.AgentSecret == "" {
		return Identity{}, errors.New("identity file missing agent_id or agent_secret")
	}
	return id, nil
}
