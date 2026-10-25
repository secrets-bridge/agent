package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/secrets-bridge/agent/internal/identity"
	"github.com/secrets-bridge/agent/internal/sealing"
)

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// secretVolume lays out credentials like a kubelet Secret volume with
// fsGroup: data in a timestamped dir with mode 0440, "..data" symlinked to
// it, and each name a symlink through "..data".
func secretVolume(t *testing.T, priv []byte) string {
	t.Helper()
	dir := t.TempDir()
	ts := filepath.Join(dir, "..2026_10_25_12_00_00.000000001")
	if err := os.Mkdir(ts, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCreds(t, ts, priv)
	for _, name := range []string{identity.FileAgentID, identity.FileAgentSecret, identity.FilePrivateKey} {
		if err := os.Chmod(filepath.Join(ts, name), 0o440); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Base(ts), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{identity.FileAgentID, identity.FileAgentSecret, identity.FilePrivateKey} {
		if err := os.Symlink(filepath.Join("..data", name), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// snapshot records every entry under root: path, type, mode, size, mtime
// and a content hash, so any write, create, chmod or delete shows up.
func snapshot(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		line := fmt.Sprintf("%s %s %d %d", p, info.Mode(), info.Size(), info.ModTime().UnixNano())
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			line += fmt.Sprintf(" %x", sha256.Sum256(data))
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			target, _ := os.Readlink(p)
			line += " -> " + target
		}
		lines = append(lines, line)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// runBinary runs the agent entry point (no subcommand) the way main does,
// with env-only configuration, and returns the exit code and the logs.
func runBinary(t *testing.T, cp *fakeCP, dir string) (int, string) {
	t.Helper()
	t.Setenv("SB_CP_ENDPOINT", cp.srv.URL)
	t.Setenv("SB_INSECURE_TRANSPORT", "true")
	t.Setenv("SB_AGENT_CREDENTIALS_DIR", dir)
	t.Setenv("SB_LOCAL_ADDR", "127.0.0.1:0")
	t.Setenv("SB_HEARTBEAT_INTERVAL", "10ms")
	t.Setenv("SB_CLAIM_INTERVAL", "5ms")
	t.Setenv("SB_SHUTDOWN_GRACE", "1s")
	var logs syncBuffer
	done := make(chan int, 1)
	go func() { done <- dispatch(nil, strings.NewReader(""), &logs, &logs) }()
	select {
	case code := <-done:
		return code, logs.String()
	case <-time.After(10 * time.Second):
		t.Fatalf("agent did not exit; logs:\n%s", logs.String())
		return 0, ""
	}
}

// A restart reads the same files and writes nothing: the credentials
// directory, the temp dir and the working directory are byte-for-byte
// unchanged across two full runs, and both runs present the same key.
// Each run ends with a rotation on the CP, so it also proves the
// mismatch is fatal (non-zero exit) through the real entry point.
func TestRuntime_RestartReadsSameFilesAndWritesNothing(t *testing.T) {
	priv := testKey(t)
	cp := newFakeCP(t, priv)
	dir := secretVolume(t, priv)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("HOME", tmp)
	wd, _ := os.Getwd()

	beforeDir, beforeTmp, beforeWd := snapshot(t, dir), snapshot(t, tmp), snapshot(t, wd)
	pub, _ := sealing.PublicFromPrivate(priv)
	want := sealing.Fingerprint(pub)

	for run := 1; run <= 2; run++ {
		cp.rotate(t, priv)
		start := cp.claims.Load()
		next := testKey(t)
		go func() {
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && cp.claims.Load() < start+3; {
				time.Sleep(2 * time.Millisecond)
			}
			cp.rotate(t, next)
		}()
		code, logs := runBinary(t, cp, dir)
		if code == 0 {
			t.Fatalf("run %d: exit 0 after agent_key_mismatch", run)
		}
		if !strings.Contains(logs, "agent_key_mismatch") || !strings.Contains(logs, want) {
			t.Fatalf("run %d logs lack the mismatch message or the fingerprint:\n%s", run, logs)
		}
		if strings.Contains(logs, testAgentSecret) || strings.Contains(logs, base64.StdEncoding.EncodeToString(priv)) {
			t.Fatalf("run %d: a credential reached the logs", run)
		}
	}

	cp.mu.Lock()
	for i, fp := range cp.fingerprint {
		if fp != want {
			cp.mu.Unlock()
			t.Fatalf("request %d presented %q want %q", i, fp, want)
		}
	}
	cp.mu.Unlock()

	if got := snapshot(t, dir); got != beforeDir {
		t.Fatalf("credentials directory changed:\nbefore:\n%s\nafter:\n%s", beforeDir, got)
	}
	if got := snapshot(t, tmp); got != beforeTmp {
		t.Fatalf("temp dir changed:\nbefore:\n%s\nafter:\n%s", beforeTmp, got)
	}
	if got := snapshot(t, wd); got != beforeWd {
		t.Fatalf("working directory changed")
	}
}

// Missing, malformed or loose credential files refuse start with exit 1
// before any CP call.
func TestRuntime_BadCredentialsRefuseStart(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"missing private_key": func(t *testing.T, dir string) {
			_ = os.Remove(filepath.Join(dir, identity.FilePrivateKey))
		},
		"malformed agent_id": func(t *testing.T, dir string) {
			p := filepath.Join(dir, identity.FileAgentID)
			_ = os.Chmod(p, 0o600)
			_ = os.WriteFile(p, []byte("not-a-uuid"), 0o600)
		},
		"world readable secret": func(t *testing.T, dir string) {
			_ = os.Chmod(filepath.Join(dir, identity.FileAgentSecret), 0o444)
		},
		"group writable key": func(t *testing.T, dir string) {
			_ = os.Chmod(filepath.Join(dir, identity.FilePrivateKey), 0o460)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			priv := testKey(t)
			cp := newFakeCP(t, priv)
			dir := credsDir(t, priv)
			mutate(t, dir)
			code, logs := runBinary(t, cp, dir)
			if code != 1 || !strings.Contains(logs, "refusing to start") {
				t.Fatalf("exit %d logs:\n%s", code, logs)
			}
			if cp.requests.Load() != 0 {
				t.Fatalf("%d CP calls with unusable credentials", cp.requests.Load())
			}
		})
	}
	t.Run("removed env credentials are ignored", func(t *testing.T) {
		priv := testKey(t)
		cp := newFakeCP(t, priv)
		t.Setenv("SB_AGENT_ID", testAgentID)
		t.Setenv("SB_AGENT_SECRET", testAgentSecret)
		t.Setenv("SB_AGENT_PRIVATE_KEY", base64.StdEncoding.EncodeToString(priv))
		t.Setenv("SB_ENROLLMENT_TOKEN", "fake-enroll-token")
		code, logs := runBinary(t, cp, filepath.Join(t.TempDir(), "empty"))
		if code != 1 || cp.requests.Load() != 0 {
			t.Fatalf("exit %d requests %d logs:\n%s", code, cp.requests.Load(), logs)
		}
	})
}

func TestDispatch(t *testing.T) {
	var out, errb bytes.Buffer
	if code := dispatch([]string{"frobnicate"}, nil, &out, &errb); code != 2 || !strings.Contains(errb.String(), "unknown command") {
		t.Fatalf("unknown command: exit %d %q", code, errb.String())
	}
	errb.Reset()
	if code := dispatch([]string{"help"}, nil, &out, &errb); code != 0 || !strings.Contains(errb.String(), "rotate-key") {
		t.Fatalf("help: exit %d %q", code, errb.String())
	}
	errb.Reset()
	if code := dispatch([]string{"enroll", "-h"}, nil, &out, &errb); code != 0 || !strings.Contains(errb.String(), "--token-file") {
		t.Fatalf("enroll -h: exit %d %q", code, errb.String())
	}
	errb.Reset()
	if code := dispatch([]string{"-enrollment-token", "x"}, nil, &out, &errb); code != 2 {
		t.Fatalf("removed runtime flag accepted: exit %d", code)
	}
}
