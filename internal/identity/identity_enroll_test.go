package identity_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/secrets-bridge/agent/internal/identity"
)

const (
	tEnvID  = "TEST_SB_AGENT_ID"
	tEnvSec = "TEST_SB_AGENT_SECRET"
)

func TestLoadStored_EnvBothSet(t *testing.T) {
	t.Setenv(tEnvID, "env-agent")
	t.Setenv(tEnvSec, "env-secret")
	id, src, err := identity.LoadStored(tEnvID, tEnvSec, "/nonexistent/identity.json")
	if err != nil {
		t.Fatalf("LoadStored: %v", err)
	}
	if src != identity.SourceEnv || id.AgentID != "env-agent" || id.AgentSecret != "env-secret" {
		t.Fatalf("wrong: src=%s id=%+v", src, id)
	}
}

func TestLoadStored_EnvPartial_IsError(t *testing.T) {
	t.Setenv(tEnvID, "env-agent")
	t.Setenv(tEnvSec, "")
	_, _, err := identity.LoadStored(tEnvID, tEnvSec, "/nonexistent/identity.json")
	if err == nil || errors.Is(err, identity.ErrNotConfigured) {
		t.Fatalf("partial env should be a hard error, got %v", err)
	}
}

func TestLoadStored_FileAbsent_ReturnsErrNotConfigured(t *testing.T) {
	// env explicitly empty so the file path is consulted.
	t.Setenv(tEnvID, "")
	t.Setenv(tEnvSec, "")
	_, _, err := identity.LoadStored(tEnvID, tEnvSec, filepath.Join(t.TempDir(), "identity.json"))
	if !errors.Is(err, identity.ErrNotConfigured) {
		t.Fatalf("absent file should be ErrNotConfigured, got %v", err)
	}
}

func TestLoadStored_FileCorrupt_IsError(t *testing.T) {
	t.Setenv(tEnvID, "")
	t.Setenv(tEnvSec, "")
	p := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(p, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := identity.LoadStored(tEnvID, tEnvSec, p)
	if err == nil || errors.Is(err, identity.ErrNotConfigured) {
		t.Fatalf("corrupt file should be a hard error, got %v", err)
	}
}

// Save persists atomically at 0600 and a subsequent LoadStored (the restart
// path) returns the same credential from the file — proving enroll-once +
// reuse-on-restart without a second token.
func TestSave_ThenLoadStored_RoundTripsAndRestartReuses(t *testing.T) {
	t.Setenv(tEnvID, "")
	t.Setenv(tEnvSec, "")
	p := filepath.Join(t.TempDir(), "sub", "identity.json") // parent dir does not exist yet
	want := identity.Identity{AgentID: "enrolled-a", AgentSecret: "enrolled-token"}

	if err := identity.Save(p, want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// perms are 0600
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("identity file perms = %o want 600", info.Mode().Perm())
	}

	// restart: LoadStored reads it back → SourceFile, same credential.
	got, src, err := identity.LoadStored(tEnvID, tEnvSec, p)
	if err != nil {
		t.Fatalf("LoadStored after Save: %v", err)
	}
	if src != identity.SourceFile || got != want {
		t.Fatalf("round-trip wrong: src=%s got=%+v want=%+v", src, got, want)
	}
}

func TestSave_RefusesEmptyCredential(t *testing.T) {
	if err := identity.Save(filepath.Join(t.TempDir(), "x.json"), identity.Identity{AgentID: "a"}); err == nil {
		t.Fatal("Save should refuse an empty agent_secret")
	}
}
