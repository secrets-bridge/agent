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

// kubelet re-adds group bits to files on an fsGroup volume, and a key
// written before the chart set OnRootMismatch can be left 0660. Like the
// identity file, the key is dropped back to owner-only on load.
func TestLoadKeyPair_LooseModeTightenedOnLoad(t *testing.T) {
	t.Setenv(EnvPrivateKey, "")
	for _, mode := range []os.FileMode{0o660, 0o640, 0o644, 0o604} {
		path := writeKeyFile(t, mode)
		t.Setenv(EnvPrivateKeyFile, path)
		if _, err := LoadOrGenerateKeyPair(EnvPrivateKey, EnvPrivateKeyFile); err != nil {
			t.Fatalf("mode %#o: %v", mode, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("mode %#o left at %#o, want 0600", mode, got)
		}
	}
}

// A Secret volume is read-only, so its mode can't change: the key still
// loads (with a warning) and the file is left as it is.
func TestLoadKeyPair_LooseModeNotFixable_LoadsAnyway(t *testing.T) {
	t.Setenv(EnvPrivateKey, "")
	orig := tightenFileMode
	tightenFileMode = func(*os.File, os.FileMode) error { return os.ErrPermission }
	t.Cleanup(func() { tightenFileMode = orig })

	path := writeKeyFile(t, 0o644)
	t.Setenv(EnvPrivateKeyFile, path)
	kp, err := LoadOrGenerateKeyPair(EnvPrivateKey, EnvPrivateKeyFile)
	if err != nil {
		t.Fatalf("a key whose mode can't be tightened must still load: %v", err)
	}
	if kp.Source != KeyPairSourceFileLoaded {
		t.Fatalf("source = %v want %v", kp.Source, KeyPairSourceFileLoaded)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("mode changed to %#o although tightening failed", got)
	}
}

// A Secret volume exposes keys as symlinks into ..data/; the target's
// mode is the one that gets tightened.
func TestLoadKeyPair_SymlinkedKeyTightensTarget(t *testing.T) {
	t.Setenv(EnvPrivateKey, "")
	target := writeKeyFile(t, 0o640)
	link := filepath.Join(t.TempDir(), "agent.key")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvPrivateKeyFile, link)
	if _, err := LoadOrGenerateKeyPair(EnvPrivateKey, EnvPrivateKeyFile); err != nil {
		t.Fatalf("symlinked key: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("target left at %#o, want 0600", got)
	}
}
