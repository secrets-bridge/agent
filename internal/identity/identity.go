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
//  1. Env vars:  SB_AGENT_ID + SB_AGENT_SECRET
//  2. File:      JSON at SB_IDENTITY_FILE (default
//     /etc/secrets-bridge/identity.json), with shape
//     {"agent_id": "...", "agent_secret": "..."}
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
	"path/filepath"
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
	SourceEnv      Source = "env"
	SourceFile     Source = "file"
	SourceEnrolled Source = "enrolled" // just enrolled this boot + persisted
)

// ErrNotConfigured signals that NEITHER env vars nor the identity file
// provide a credential — i.e. there is nothing stored yet. It is the
// trigger for the enroll-on-first-boot path; it is NOT returned for a
// partially-configured env or a corrupt file (those are real errors).
var ErrNotConfigured = errors.New("identity: no stored credential")

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

// LoadStored resolves a stored identity from env vars or the file, in that
// priority order, WITHOUT treating "nothing stored yet" as a hard error.
//
//   - env id + secret both set        → (id, SourceEnv, nil)
//   - env id set but secret empty      → ({}, "", error)  [misconfigured]
//   - file present + valid             → (id, SourceFile, nil)
//   - file absent (no env)             → ({}, "", ErrNotConfigured)
//   - file present but corrupt/partial → ({}, "", error)
//
// The ErrNotConfigured case is the enroll-on-first-boot trigger; every
// other error is a genuine misconfiguration the caller should surface.
func LoadStored(envAgentID, envAgentSecret, filePath string) (Identity, Source, error) {
	if id := os.Getenv(envAgentID); id != "" {
		secret := os.Getenv(envAgentSecret)
		if secret == "" {
			return Identity{}, "", fmt.Errorf(
				"identity: %s is set but %s is empty", envAgentID, envAgentSecret)
		}
		return Identity{AgentID: id, AgentSecret: secret}, SourceEnv, nil
	}

	data, err := os.ReadFile(filePath)
	if errors.Is(err, os.ErrNotExist) {
		return Identity{}, "", ErrNotConfigured
	}
	if err != nil {
		return Identity{}, "", fmt.Errorf("identity: read %q: %w", filePath, err)
	}
	var id Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return Identity{}, "", fmt.Errorf("identity: parse %q: %w", filePath, err)
	}
	if id.AgentID == "" || id.AgentSecret == "" {
		return Identity{}, "", fmt.Errorf("identity: %q missing agent_id or agent_secret", filePath)
	}
	return id, SourceFile, nil
}

// Save writes the identity to filePath atomically (temp file + rename) with
// mode 0600, creating the parent directory (0700) if needed. Used by the
// enroll-on-first-boot path to persist the returned credential so a restart
// reuses it instead of consuming a second enrollment token.
//
// The path must be on a WRITABLE, restart-persistent volume (a PVC or a
// writable mount) — NOT a read-only mounted Secret. A restart re-reads this
// file via LoadStored and skips enrollment.
func Save(filePath string, id Identity) error {
	if id.AgentID == "" || id.AgentSecret == "" {
		return errors.New("identity: refusing to save empty agent_id or agent_secret")
	}
	data, err := json.Marshal(id)
	if err != nil {
		return fmt.Errorf("identity: marshal: %w", err)
	}
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("identity: mkdir %q: %w", dir, err)
	}
	// Atomic write: a crash mid-write can't leave a half-formed identity
	// file. Temp file is created 0600 so the credential is never briefly
	// world-readable.
	tmp, err := os.CreateTemp(dir, ".identity-*.tmp")
	if err != nil {
		return fmt.Errorf("identity: create temp in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("identity: chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("identity: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("identity: close temp: %w", err)
	}
	if err := os.Rename(tmpName, filePath); err != nil {
		return fmt.Errorf("identity: rename into place %q: %w", filePath, err)
	}
	return nil
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
