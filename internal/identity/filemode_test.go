package identity

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	fmEnvID  = "TEST_FM_SB_AGENT_ID"
	fmEnvSec = "TEST_FM_SB_AGENT_SECRET"
)

func writeIdentityFile(t *testing.T, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(p, []byte(`{"agent_id":"agent-a","agent_secret":"fake-agent-secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // bypass umask
		t.Fatal(err)
	}
	return p
}

// AGT-04: identity.json holds the bearer secret. A world-accessible file
// is refused outright, for both loaders.
func TestLoadStored_WorldReadableIdentityRefused(t *testing.T) {
	t.Setenv(fmEnvID, "")
	t.Setenv(fmEnvSec, "")
	for _, mode := range []os.FileMode{0o644, 0o604, 0o606, 0o666, 0o640 | 0o004} {
		p := writeIdentityFile(t, mode)
		id, _, err := LoadStored(fmEnvID, fmEnvSec, p)
		if err == nil {
			t.Fatalf("identity file with mode %#o was loaded (agent %q)", mode, id.AgentID)
		}
		if strings.Contains(err.Error(), "fake-agent-secret") {
			t.Fatalf("error carries the secret: %v", err)
		}
		if _, _, err := Load(fmEnvID, fmEnvSec, p); err == nil {
			t.Fatalf("Load accepted an identity file with mode %#o", mode)
		}
	}
}

func TestLoadStored_OwnerOnlyIdentityLoads(t *testing.T) {
	t.Setenv(fmEnvID, "")
	t.Setenv(fmEnvSec, "")
	for _, mode := range []os.FileMode{0o600, 0o400} {
		p := writeIdentityFile(t, mode)
		id, src, err := LoadStored(fmEnvID, fmEnvSec, p)
		if err != nil {
			t.Fatalf("mode %#o refused: %v", mode, err)
		}
		if src != SourceFile || id.AgentID != "agent-a" {
			t.Fatalf("mode %#o: src=%s id=%q", mode, src, id.AgentID)
		}
	}
}

// Group bits on a file the agent owns are what kubelet adds to every file
// on a volume when the pod sets fsGroup (the chart does). The agent drops
// them back to 0600 before reading the secret, instead of crash-looping an
// enrolled agent on its next restart.
func TestLoadStored_GroupBitsTightenedBeforeRead(t *testing.T) {
	t.Setenv(fmEnvID, "")
	t.Setenv(fmEnvSec, "")
	for _, mode := range []os.FileMode{0o640, 0o660, 0o620} {
		p := writeIdentityFile(t, mode)
		if _, _, err := LoadStored(fmEnvID, fmEnvSec, p); err != nil {
			t.Fatalf("mode %#o: %v", mode, err)
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("mode %#o left at %#o, want 0600", mode, got)
		}
	}
}

// When the group bits can't be removed (a read-only Secret mount, a file
// owned by someone else) the load fails closed.
func TestLoadStored_GroupBitsRefusedWhenNotFixable(t *testing.T) {
	t.Setenv(fmEnvID, "")
	t.Setenv(fmEnvSec, "")
	orig := tightenFileMode
	tightenFileMode = func(*os.File, os.FileMode) error { return os.ErrPermission }
	t.Cleanup(func() { tightenFileMode = orig })

	p := writeIdentityFile(t, 0o640)
	if _, _, err := LoadStored(fmEnvID, fmEnvSec, p); err == nil {
		t.Fatal("group-readable identity file loaded although its mode could not be tightened")
	}
}

func TestLoadStored_NonRegularIdentityRefused(t *testing.T) {
	t.Setenv(fmEnvID, "")
	t.Setenv(fmEnvSec, "")
	if _, _, err := LoadStored(fmEnvID, fmEnvSec, t.TempDir()); err == nil {
		t.Fatal("a directory was accepted as the identity file")
	}
}

// A Kubernetes Secret volume exposes keys as symlinks into ..data/. The
// mode that matters is the target's; a 0400 target behind a symlink loads.
func TestLoadStored_SymlinkedSecretVolumeLoads(t *testing.T) {
	t.Setenv(fmEnvID, "")
	t.Setenv(fmEnvSec, "")
	target := writeIdentityFile(t, 0o400)
	link := filepath.Join(t.TempDir(), "identity.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadStored(fmEnvID, fmEnvSec, link); err != nil {
		t.Fatalf("symlinked 0400 identity refused: %v", err)
	}
}

// AGT-04: generating the private key file must not follow a pre-planted
// symlink at the configured path and must create the file 0600.
func TestLoadKeyPair_GenerateDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere", "stolen.key")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "agent.key")
	if err := os.Symlink(target, keyPath); err != nil { // dangling
		t.Fatal(err)
	}
	t.Setenv(EnvPrivateKey, "")
	t.Setenv(EnvPrivateKeyFile, keyPath)

	_, err := LoadOrGenerateKeyPair(EnvPrivateKey, EnvPrivateKeyFile)
	if _, statErr := os.Stat(target); statErr == nil {
		t.Fatal("private key was written through a symlink to another path")
	}
	if err == nil {
		t.Fatal("key generation over a dangling symlink succeeded")
	}
}

func TestLoadKeyPair_GeneratedFileIs0600AndReloads(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "keys", "agent.key")
	t.Setenv(EnvPrivateKey, "")
	t.Setenv(EnvPrivateKeyFile, keyPath)

	first, err := LoadOrGenerateKeyPair(EnvPrivateKey, EnvPrivateKeyFile)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if first.Source != KeyPairSourceFileGenerated {
		t.Fatalf("source = %s", first.Source)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("generated key mode %#o want 0600", info.Mode().Perm())
	}
	again, err := LoadOrGenerateKeyPair(EnvPrivateKey, EnvPrivateKeyFile)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if again.Source != KeyPairSourceFileLoaded || !bytes.Equal(again.Public, first.Public) {
		t.Fatalf("reload gave source=%s and a different key", again.Source)
	}
	entries, err := os.ReadDir(filepath.Dir(keyPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("key dir holds %d entries, want only the key (temp file left behind?)", len(entries))
	}
}

// On a filesystem without hard links the key is still created exclusively
// at 0600, and an existing key is still never overwritten.
func TestLoadKeyPair_NoHardLinkFallback(t *testing.T) {
	orig := linkFile
	linkFile = func(string, string) error { return &os.LinkError{Op: "link", Err: os.ErrPermission} }
	t.Cleanup(func() { linkFile = orig })

	keyPath := filepath.Join(t.TempDir(), "agent.key")
	t.Setenv(EnvPrivateKey, "")
	t.Setenv(EnvPrivateKeyFile, keyPath)
	first, err := LoadOrGenerateKeyPair(EnvPrivateKey, EnvPrivateKeyFile)
	if err != nil {
		t.Fatalf("generate without hard links: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || info.Size() != 32 {
		t.Fatalf("fallback key file mode %#o size %d", info.Mode().Perm(), info.Size())
	}
	if _, err := generateKeyFile(keyPath); err == nil {
		t.Fatal("fallback overwrote an existing key")
	}
	again, err := LoadOrGenerateKeyPair(EnvPrivateKey, EnvPrivateKeyFile)
	if err != nil || !bytes.Equal(again.Public, first.Public) {
		t.Fatalf("key changed after a second generate attempt: %v", err)
	}
}

// Two agent processes starting on the same key path must end up with the
// same key: the loser of the create race reads the winner's file instead
// of overwriting it.
func TestLoadKeyPair_ConcurrentFirstStartAgrees(t *testing.T) {
	for i := 0; i < 20; i++ {
		keyPath := filepath.Join(t.TempDir(), "agent.key")
		t.Setenv(EnvPrivateKey, "")
		t.Setenv(EnvPrivateKeyFile, keyPath)

		const n = 8
		pubs := make([][]byte, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		for j := 0; j < n; j++ {
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				kp, err := LoadOrGenerateKeyPair(EnvPrivateKey, EnvPrivateKeyFile)
				errs[j] = err
				if kp != nil {
					pubs[j] = kp.Public
				}
			}(j)
		}
		wg.Wait()
		onDisk, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		pk, err := LoadOrGenerateKeyPair(EnvPrivateKey, EnvPrivateKeyFile)
		if err != nil {
			t.Fatal(err)
		}
		if len(onDisk) != 32 {
			t.Fatalf("key file has %d bytes", len(onDisk))
		}
		for j := 0; j < n; j++ {
			if errs[j] != nil {
				t.Fatalf("racer %d: %v", j, errs[j])
			}
			if !bytes.Equal(pubs[j], pk.Public) {
				t.Fatalf("racer %d holds a key that is not the one on disk", j)
			}
		}
	}
}
