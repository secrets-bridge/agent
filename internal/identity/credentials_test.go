package identity_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secrets-bridge/agent/internal/identity"
	"github.com/secrets-bridge/agent/internal/sealing"
)

const (
	testAgentID     = "0f8b6c7e-2a51-4d3e-9b1f-6c2d4e8a9b10"
	testAgentSecret = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE"
)

func newKey(t *testing.T) []byte {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k.Bytes()
}

func files(priv []byte) map[string]string {
	return map[string]string{
		identity.FileAgentID:     testAgentID,
		identity.FileAgentSecret: testAgentSecret,
		identity.FilePrivateKey:  base64.StdEncoding.EncodeToString(priv),
	}
}

// writeDir writes each file with mode and returns the directory.
func writeDir(t *testing.T, content map[string]string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	for name, v := range content {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// writeSecretVolume lays the files out the way the kubelet does for a
// Secret volume: the data lives in a timestamped directory, "..data" is a
// symlink to it, and each visible name is a symlink through "..data".
func writeSecretVolume(t *testing.T, content map[string]string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	ts := filepath.Join(dir, "..2026_10_25_12_00_00.000000001")
	if err := os.Mkdir(ts, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, v := range content {
		p := filepath.Join(ts, name)
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Base(ts), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	for name := range content {
		if err := os.Symlink(filepath.Join("..data", name), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoad_ValidDirectory(t *testing.T) {
	priv := newKey(t)
	dir := writeDir(t, files(priv), 0o400)
	id, kp, err := identity.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if id.AgentID != testAgentID || id.AgentSecret != testAgentSecret {
		t.Fatalf("identity = %+v", id)
	}
	pub, _ := sealing.PublicFromPrivate(priv)
	if !bytes.Equal(kp.Public, pub) || !bytes.Equal(kp.Private, priv) {
		t.Fatal("key pair does not match private_key")
	}
	if kp.Fingerprint != sealing.Fingerprint(pub) || !strings.HasPrefix(kp.Fingerprint, "sha256:") || len(kp.Fingerprint) != 7+64 {
		t.Fatalf("fingerprint = %q", kp.Fingerprint)
	}
}

// Contract (revised for fsGroup): group read is allowed, group write or
// execute and any bit for others are refused, on the resolved target.
func TestLoad_FileModes(t *testing.T) {
	cases := []struct {
		mode os.FileMode
		ok   bool
	}{
		{0o400, true},
		{0o440, true},
		{0o600, true},
		{0o640, true},
		{0o444, false},
		{0o460, false},
		{0o470, false},
		{0o604, false},
		{0o644, false},
		{0o410, false},
		{0o401, false},
		{0o420, false},
	}
	for _, tc := range cases {
		for _, layout := range []string{"plain", "secret-volume"} {
			t.Run(layout+"/"+tc.mode.String(), func(t *testing.T) {
				var dir string
				if layout == "plain" {
					dir = writeDir(t, files(newKey(t)), tc.mode)
				} else {
					dir = writeSecretVolume(t, files(newKey(t)), tc.mode)
				}
				_, _, err := identity.Load(dir)
				if tc.ok && err != nil {
					t.Fatalf("mode %#o refused: %v", tc.mode, err)
				}
				if !tc.ok && !errors.Is(err, identity.ErrInsecureMode) {
					t.Fatalf("mode %#o: got %v want ErrInsecureMode", tc.mode, err)
				}
			})
		}
	}
}

// One loose file is enough to refuse start.
func TestLoad_OneLooseFileRefused(t *testing.T) {
	for _, name := range []string{identity.FileAgentID, identity.FileAgentSecret, identity.FilePrivateKey} {
		t.Run(name, func(t *testing.T) {
			dir := writeDir(t, files(newKey(t)), 0o400)
			if err := os.Chmod(filepath.Join(dir, name), 0o444); err != nil {
				t.Fatal(err)
			}
			if _, _, err := identity.Load(dir); !errors.Is(err, identity.ErrInsecureMode) || !strings.Contains(err.Error(), name) {
				t.Fatalf("got %v want ErrInsecureMode naming %s", err, name)
			}
		})
	}
}

// A symlink that points at a loose file is refused: the check is on the
// target, not on the link (whose own mode is always 0777).
func TestLoad_SymlinkToLooseTargetRefused(t *testing.T) {
	dir := writeSecretVolume(t, files(newKey(t)), 0o400)
	target := filepath.Join(dir, "..data", identity.FilePrivateKey)
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := identity.Load(dir); !errors.Is(err, identity.ErrInsecureMode) {
		t.Fatalf("got %v want ErrInsecureMode", err)
	}
}

func TestLoad_MissingFiles(t *testing.T) {
	for _, name := range []string{identity.FileAgentID, identity.FileAgentSecret, identity.FilePrivateKey} {
		t.Run(name, func(t *testing.T) {
			f := files(newKey(t))
			delete(f, name)
			dir := writeDir(t, f, 0o400)
			_, _, err := identity.Load(dir)
			if err == nil || !strings.Contains(err.Error(), name+" is missing") {
				t.Fatalf("got %v want %s is missing", err, name)
			}
		})
	}
	if _, _, err := identity.Load(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("missing directory accepted")
	}
}

func TestLoad_MalformedFiles(t *testing.T) {
	zeroKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cases := map[string]map[string]string{
		"agent_id not a uuid":      {identity.FileAgentID: "agent-a"},
		"agent_id empty":           {identity.FileAgentID: "  \n"},
		"agent_secret short":       {identity.FileAgentSecret: "c2hvcnQ"},
		"agent_secret std base64":  {identity.FileAgentSecret: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32))},
		"private_key not base64":   {identity.FilePrivateKey: "not base64!"},
		"private_key 31 bytes":     {identity.FilePrivateKey: base64.StdEncoding.EncodeToString(make([]byte, 31))},
		"private_key 33 bytes":     {identity.FilePrivateKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 33))},
		"private_key raw bytes":    {identity.FilePrivateKey: string(bytes.Repeat([]byte{7}, 32))},
		"private_key all zero":     {identity.FilePrivateKey: zeroKey},
		"private_key oversize":     {identity.FilePrivateKey: strings.Repeat("A", 5000)},
		"agent_secret secret text": {identity.FileAgentSecret: "fake-secret-value"},
	}
	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			f := files(newKey(t))
			for k, v := range override {
				f[k] = v
			}
			dir := writeDir(t, f, 0o400)
			_, _, err := identity.Load(dir)
			if err == nil {
				t.Fatal("malformed credentials accepted")
			}
			if strings.Contains(err.Error(), "fake-secret-value") || strings.Contains(err.Error(), testAgentSecret) {
				t.Fatalf("error carries file content: %v", err)
			}
		})
	}
}

// Trailing newlines (echo, kubectl, editors) are trimmed.
func TestLoad_TrimsWhitespace(t *testing.T) {
	f := files(newKey(t))
	for k, v := range f {
		f[k] = v + "\n"
	}
	if _, _, err := identity.Load(writeDir(t, f, 0o400)); err != nil {
		t.Fatalf("Load with trailing newlines: %v", err)
	}
}

func TestLoad_DirectoryInsteadOfFileRefused(t *testing.T) {
	f := files(newKey(t))
	delete(f, identity.FilePrivateKey)
	dir := writeDir(t, f, 0o400)
	if err := os.Mkdir(filepath.Join(dir, identity.FilePrivateKey), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := identity.Load(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("got %v want not a regular file", err)
	}
}
