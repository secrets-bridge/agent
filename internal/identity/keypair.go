package identity

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/secrets-bridge/agent/internal/sealing"
)

// KeyPair is the agent's X25519 wire-envelope keypair. The private
// key NEVER leaves the agent process — it's loaded from local storage
// (env var or file) and only the public bytes are sent to the CP via
// the registration endpoint.
type KeyPair struct {
	Public  []byte
	Private []byte
	// Source describes where the keypair came from; useful for
	// startup-log telemetry without revealing the key material.
	Source KeyPairSource
}

// KeyPairSource identifies which loader path produced the keypair.
type KeyPairSource string

const (
	// KeyPairSourceEnv: private key came from SB_AGENT_PRIVATE_KEY.
	KeyPairSourceEnv KeyPairSource = "env"
	// KeyPairSourceFileLoaded: loaded an existing private key file.
	KeyPairSourceFileLoaded KeyPairSource = "file"
	// KeyPairSourceFileGenerated: the file path didn't exist yet so
	// we generated a fresh keypair and wrote it to disk.
	KeyPairSourceFileGenerated KeyPairSource = "file-generated"
	// KeyPairSourceEphemeral: neither env nor file was configured; we
	// generated a fresh keypair this boot only. Lost on restart; the
	// agent re-registers and previously-sealed unconsumed wraps will
	// be unrecoverable. Acceptable for `docker compose up` style dev —
	// logged at WARN so operators see they're not in persistent mode.
	KeyPairSourceEphemeral KeyPairSource = "ephemeral"
)

// Env var names. Order of precedence: SB_AGENT_PRIVATE_KEY (env var)
// then SB_AGENT_PRIVATE_KEY_FILE (file path); if neither is set, an
// ephemeral keypair is generated this boot.
const (
	EnvPrivateKey     = "SB_AGENT_PRIVATE_KEY"
	EnvPrivateKeyFile = "SB_AGENT_PRIVATE_KEY_FILE"
)

// LoadOrGenerateKeyPair resolves the agent's X25519 keypair from
// env var, file, or fresh generation in that order.
//
// File mode behavior: if the path is non-empty and the file exists,
// we read it. If the path is non-empty and the file does NOT exist,
// we generate a fresh keypair and write the private bytes (raw, 32
// bytes, 0600). This makes first-start the same shape as N-th-start.
func LoadOrGenerateKeyPair(envKey, envKeyFile string) (*KeyPair, error) {
	// 1. env var takes precedence
	if v := os.Getenv(envKey); v != "" {
		priv, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("identity: %s is not valid base64: %w", envKey, err)
		}
		if len(priv) != 32 {
			return nil, fmt.Errorf("identity: %s must be 32 raw bytes after base64 decode, got %d", envKey, len(priv))
		}
		pub, err := sealing.PublicFromPrivate(priv)
		if err != nil {
			return nil, fmt.Errorf("identity: derive public key: %w", err)
		}
		return &KeyPair{Public: pub, Private: priv, Source: KeyPairSourceEnv}, nil
	}

	// 2. file path mode
	if path := os.Getenv(envKeyFile); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			if len(data) != 32 {
				return nil, fmt.Errorf("identity: %s file %q must be exactly 32 raw bytes, got %d", envKeyFile, path, len(data))
			}
			pub, err := sealing.PublicFromPrivate(data)
			if err != nil {
				return nil, fmt.Errorf("identity: derive public key: %w", err)
			}
			return &KeyPair{Public: pub, Private: data, Source: KeyPairSourceFileLoaded}, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("identity: read %s: %w", path, err)
		}

		// File path was set but doesn't exist yet — generate + write.
		pub, priv, err := sealing.GenerateKeypair()
		if err != nil {
			return nil, fmt.Errorf("identity: generate keypair: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("identity: mkdir %s: %w", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, priv, 0o600); err != nil {
			return nil, fmt.Errorf("identity: write %s: %w", path, err)
		}
		return &KeyPair{Public: pub, Private: priv, Source: KeyPairSourceFileGenerated}, nil
	}

	// 3. neither configured — ephemeral
	pub, priv, err := sealing.GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("identity: generate ephemeral keypair: %w", err)
	}
	return &KeyPair{Public: pub, Private: priv, Source: KeyPairSourceEphemeral}, nil
}
