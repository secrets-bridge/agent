package identity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/secrets-bridge/agent/internal/sealing"
)

func TestKeyFileModeTooOpen(t *testing.T) {
	cases := []struct {
		mode os.FileMode
		want bool
	}{
		{0o600, false},
		{0o400, false},
		{0o640, true},
		{0o604, true},
		{0o644, true},
		{0o660, true},
		{0o666, true},
		{0o777, true},
	}
	for _, tc := range cases {
		if got := keyFileModeTooOpen(tc.mode); got != tc.want {
			t.Errorf("keyFileModeTooOpen(%#o) = %v want %v", tc.mode, got, tc.want)
		}
	}
}

func writeKeyFile(t *testing.T, mode os.FileMode) string {
	t.Helper()
	_, priv, err := sealing.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	path := filepath.Join(t.TempDir(), "agent.key")
	if err := os.WriteFile(path, priv, mode); err != nil {
		t.Fatalf("write key: %v", err)
	}
	// os.WriteFile honours umask; force the exact bits for the test.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	return path
}

func TestLoadKeyPair_FileMode0600_Loads(t *testing.T) {
	t.Setenv(EnvPrivateKey, "")
	t.Setenv(EnvPrivateKeyFile, writeKeyFile(t, 0o600))
	kp, err := LoadOrGenerateKeyPair(EnvPrivateKey, EnvPrivateKeyFile)
	if err != nil {
		t.Fatalf("LoadOrGenerateKeyPair: %v", err)
	}
	if kp.Source != KeyPairSourceFileLoaded {
		t.Fatalf("source = %v want %v", kp.Source, KeyPairSourceFileLoaded)
	}
}

// AGT-04: a group/other-accessible key file WARNS but still loads
// (non-fatal), so a K8s Secret volume defaulting to 0644 doesn't crash the
// agent. The warning is emitted via slog; here we assert the load itself
// still succeeds.
func TestLoadKeyPair_FileModeTooOpen_LoadsAnyway(t *testing.T) {
	t.Setenv(EnvPrivateKey, "")
	t.Setenv(EnvPrivateKeyFile, writeKeyFile(t, 0o644))
	kp, err := LoadOrGenerateKeyPair(EnvPrivateKey, EnvPrivateKeyFile)
	if err != nil {
		t.Fatalf("loose perms must not fail the load: %v", err)
	}
	if kp.Source != KeyPairSourceFileLoaded {
		t.Fatalf("source = %v want %v", kp.Source, KeyPairSourceFileLoaded)
	}
}
