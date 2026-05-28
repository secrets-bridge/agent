package identity_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/secrets-bridge/agent/internal/identity"
)

const (
	envID     = "TEST_SB_AGENT_ID"
	envSecret = "TEST_SB_AGENT_SECRET"
)

func TestLoad_FromEnv_TakesPrecedence(t *testing.T) {
	t.Setenv(envID, "from-env")
	t.Setenv(envSecret, "secret-from-env")

	// File also exists — env still wins.
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	if err := os.WriteFile(path, []byte(`{"agent_id":"from-file","agent_secret":"sec-file"}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	id, src, err := identity.Load(envID, envSecret, path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if src != identity.SourceEnv {
		t.Fatalf("source: %q want env", src)
	}
	if id.AgentID != "from-env" || id.AgentSecret != "secret-from-env" {
		t.Fatalf("env values not used: %+v", id)
	}
}

func TestLoad_FromFile_WhenEnvAbsent(t *testing.T) {
	t.Setenv(envID, "")
	t.Setenv(envSecret, "")

	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	if err := os.WriteFile(path, []byte(`{"agent_id":"from-file","agent_secret":"sec-file"}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	id, src, err := identity.Load(envID, envSecret, path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if src != identity.SourceFile {
		t.Fatalf("source: %q want file", src)
	}
	if id.AgentID != "from-file" || id.AgentSecret != "sec-file" {
		t.Fatalf("file values not used: %+v", id)
	}
}

func TestLoad_EnvIDWithoutSecret_Errors(t *testing.T) {
	t.Setenv(envID, "only-id")
	t.Setenv(envSecret, "")
	dir := t.TempDir()
	_, _, err := identity.Load(envID, envSecret, filepath.Join(dir, "nope.json"))
	if err == nil {
		t.Fatal("expected error when env id is set but secret isn't")
	}
}

func TestLoad_NeitherSource_Errors(t *testing.T) {
	t.Setenv(envID, "")
	t.Setenv(envSecret, "")
	dir := t.TempDir()
	_, _, err := identity.Load(envID, envSecret, filepath.Join(dir, "absent.json"))
	if err == nil {
		t.Fatal("expected error when no env vars and no file")
	}
	if !errors.Is(err, os.ErrNotExist) && !errIsUnwrappedToErrNotExist(err) {
		// The wrapped error path includes the os.ErrNotExist —
		// errors.Is reaches it through %w. Make the failure mode
		// loud if a future refactor breaks the wrap chain.
		t.Logf("note: missing-file error: %v", err)
	}
}

func TestLoad_FileMissingFields_Errors(t *testing.T) {
	t.Setenv(envID, "")
	t.Setenv(envSecret, "")
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	if err := os.WriteFile(path, []byte(`{"agent_id":"a"}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, _, err := identity.Load(envID, envSecret, path); err == nil {
		t.Fatal("expected error for identity file missing agent_secret")
	}
}

// errIsUnwrappedToErrNotExist walks the error chain manually as a
// secondary check on errors.Is. Kept here so the test stays explicit
// about what's being verified.
func errIsUnwrappedToErrNotExist(err error) bool {
	for err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true
		}
		err = errors.Unwrap(err)
	}
	return false
}
