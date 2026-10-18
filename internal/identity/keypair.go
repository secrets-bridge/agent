package identity

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
		kp, err := loadKeyFile(envKeyFile, path)
		if !errors.Is(err, os.ErrNotExist) {
			return kp, err
		}
		// File path was set but doesn't exist yet — generate + write.
		kp, err = generateKeyFile(path)
		if errors.Is(err, os.ErrExist) {
			// Another process (a second replica on a shared volume, or a
			// restarted container racing the old one) created the file
			// between our read and our create. Use its key instead of
			// overwriting it, so every process agrees with the file.
			return loadKeyFile(envKeyFile, path)
		}
		return kp, err
	}

	// 3. neither configured — ephemeral
	pub, priv, err := sealing.GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("identity: generate ephemeral keypair: %w", err)
	}
	return &KeyPair{Public: pub, Private: priv, Source: KeyPairSourceEphemeral}, nil
}

// loadKeyFile reads an existing 32-byte private key file. A missing file
// comes back as an error matching os.ErrNotExist.
func loadKeyFile(envKeyFile, path string) (*KeyPair, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("identity: read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	// AGT-04: a private key file must not be readable by group or
	// other. The agent drops those bits on the open file, as it does for
	// the identity file: kubelet re-adds group bits to every file on a
	// volume when the pod sets fsGroup. Where the mode can't change (a
	// read-only Secret volume, a file owned by someone else) it warns
	// rather than refuses, so a Secret volume defaulting to 0644 doesn't
	// hard-fail the agent; operators can set the volume defaultMode.
	if info, statErr := f.Stat(); statErr == nil && keyFileModeTooOpen(info.Mode()) {
		perm := info.Mode().Perm()
		if err := tightenFileMode(f, perm&^0o077); err == nil {
			slog.Warn("agent private key file was group/other-accessible; tightened to owner-only before reading (on Kubernetes, fsGroup re-adds group bits at mount; set fsGroupChangePolicy: OnRootMismatch to stop that)",
				"path", path,
				"mode_was", fmt.Sprintf("%#o", perm))
		} else {
			slog.Warn("agent private key file is group/other-accessible and could not be tightened; chmod it to 0600 (or set the Secret volume defaultMode to 0400)",
				"path", path,
				"mode", fmt.Sprintf("%#o", perm),
				"error", err)
		}
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("identity: read %s: %w", path, err)
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("identity: %s file %q must be exactly 32 raw bytes, got %d", envKeyFile, path, len(data))
	}
	pub, err := sealing.PublicFromPrivate(data)
	if err != nil {
		return nil, fmt.Errorf("identity: derive public key: %w", err)
	}
	return &KeyPair{Public: pub, Private: data, Source: KeyPairSourceFileLoaded}, nil
}

// generateKeyFile creates a fresh keypair and publishes the private key at
// path atomically, mode 0600 (AGT-04). The key is written and synced to a
// temp file in the same directory, then hard-linked into place: link(2)
// never overwrites, so an existing key (or a symlink planted at path) makes
// it fail with os.ErrExist, and a reader never sees a partly written file.
// On a filesystem without hard links it falls back to an O_CREATE|O_EXCL
// create, which keeps the no-overwrite and no-symlink guarantees.
func generateKeyFile(path string) (*KeyPair, error) {
	pub, priv, err := sealing.GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("identity: generate keypair: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("identity: mkdir %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".agent-key-*.tmp") // created 0600
	if err != nil {
		return nil, fmt.Errorf("identity: create temp key in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := writeSyncClose(tmp, priv); err != nil {
		return nil, fmt.Errorf("identity: write temp key: %w", err)
	}

	linkErr := linkFile(tmpName, path)
	switch {
	case linkErr == nil:
	case errors.Is(linkErr, os.ErrExist):
		return nil, fmt.Errorf("identity: create %s: %w", path, linkErr)
	default:
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, fmt.Errorf("identity: create %s: %w", path, err)
		}
		if err := writeSyncClose(f, priv); err != nil {
			// Never leave a short key file behind: the next start would
			// refuse it as "must be exactly 32 raw bytes".
			_ = os.Remove(path)
			return nil, fmt.Errorf("identity: write %s: %w", path, err)
		}
	}
	return &KeyPair{Public: pub, Private: priv, Source: KeyPairSourceFileGenerated}, nil
}

// linkFile is os.Link; a variable only so tests can exercise the
// no-hard-link fallback.
var linkFile = os.Link

func writeSyncClose(f *os.File, b []byte) error {
	_, err := f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// keyFileModeTooOpen reports whether mode grants any group or other
// permission bit. A private key should be accessible only by its owner
// (mode 0600 / 0400); anything looser is a leak risk (AGT-04).
func keyFileModeTooOpen(mode os.FileMode) bool {
	return mode.Perm()&0o077 != 0
}
