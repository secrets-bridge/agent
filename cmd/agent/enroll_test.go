package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/agent/internal/identity"
)

// fakeEnrollCP stands up a CP that returns a fixed 201 enrollment response
// and counts how many times /agents/enroll is hit.
func fakeEnrollCP(t *testing.T, enrollCalls *atomic.Int32) *client.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/enroll", func(w http.ResponseWriter, _ *http.Request) {
		enrollCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"agent_id":"enrolled-agent","provider_connection_id":"pc-9","agent_token":"PERSISTENT-AGENT-TOKEN","heartbeat_interval_seconds":30,"job_poll_interval_seconds":5}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return client.New(srv.URL)
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestResolveIdentity_FirstBootEnrollsPersists_RestartReuses(t *testing.T) {
	t.Setenv(envAgentID, "")
	t.Setenv(envAgentSecret, "")
	var calls atomic.Int32
	c := fakeEnrollCP(t, &calls)
	idFile := filepath.Join(t.TempDir(), "identity.json")
	cfg := Config{
		IdentityFile:      idFile,
		EnrollmentEnabled: true,
		EnrollmentToken:   "ENROLL-TOKEN-SECRET",
		AgentName:         "a",
		ProviderType:      "aws-sm",
	}

	// First boot → enroll + persist.
	id, src, err := resolveIdentity(context.Background(), &cfg, c, quietLogger())
	if err != nil {
		t.Fatalf("first resolveIdentity: %v", err)
	}
	if src != identity.SourceEnrolled || id.AgentID != "enrolled-agent" || id.AgentSecret != "PERSISTENT-AGENT-TOKEN" {
		t.Fatalf("enroll result wrong: src=%s id=%+v", src, id)
	}
	if calls.Load() != 1 {
		t.Fatalf("enroll called %d times, want 1", calls.Load())
	}
	var persisted identity.Identity
	data, _ := os.ReadFile(idFile)
	_ = json.Unmarshal(data, &persisted)
	if persisted.AgentID != "enrolled-agent" || persisted.AgentSecret != "PERSISTENT-AGENT-TOKEN" {
		t.Fatalf("credential not persisted: %+v", persisted)
	}

	// Restart: same cfg (token still set) → reuse the file, do NOT re-enroll.
	id2, src2, err := resolveIdentity(context.Background(), &cfg, c, quietLogger())
	if err != nil {
		t.Fatalf("restart resolveIdentity: %v", err)
	}
	if src2 != identity.SourceFile {
		t.Errorf("restart source = %s want file", src2)
	}
	if id2 != id {
		t.Errorf("restart credential changed: %+v vs %+v", id2, id)
	}
	if calls.Load() != 1 {
		t.Fatalf("restart re-enrolled (calls=%d) — the one-time token would be spent twice", calls.Load())
	}
}

func TestResolveIdentity_NoCredsNoToken_FailsClosed(t *testing.T) {
	t.Setenv(envAgentID, "")
	t.Setenv(envAgentSecret, "")
	var calls atomic.Int32
	c := fakeEnrollCP(t, &calls)
	cfg := Config{
		IdentityFile:      filepath.Join(t.TempDir(), "identity.json"),
		EnrollmentEnabled: true,
		EnrollmentToken:   "", // no token
	}
	_, _, err := resolveIdentity(context.Background(), &cfg, c, quietLogger())
	if err == nil {
		t.Fatal("expected fail-closed error with no creds and no token")
	}
	if calls.Load() != 0 {
		t.Errorf("must not call enroll without a token")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Errorf("expected fail-closed message, got %v", err)
	}
}

func TestResolveIdentity_EnrollmentDisabled_FailsClosed(t *testing.T) {
	t.Setenv(envAgentID, "")
	t.Setenv(envAgentSecret, "")
	var calls atomic.Int32
	c := fakeEnrollCP(t, &calls)
	cfg := Config{
		IdentityFile:      filepath.Join(t.TempDir(), "identity.json"),
		EnrollmentEnabled: false, // explicitly off
		EnrollmentToken:   "tok",
	}
	_, _, err := resolveIdentity(context.Background(), &cfg, c, quietLogger())
	if err == nil || calls.Load() != 0 {
		t.Fatalf("disabled enrollment must fail closed without enrolling (err=%v calls=%d)", err, calls.Load())
	}
}

func TestResolveIdentity_LegacyEnvCreds_SkipsEnroll(t *testing.T) {
	t.Setenv(envAgentID, "legacy-agent")
	t.Setenv(envAgentSecret, "legacy-secret")
	var calls atomic.Int32
	c := fakeEnrollCP(t, &calls)
	cfg := Config{
		IdentityFile:      filepath.Join(t.TempDir(), "identity.json"),
		EnrollmentEnabled: true,
		EnrollmentToken:   "tok", // present, but stored env creds take precedence
	}
	id, src, err := resolveIdentity(context.Background(), &cfg, c, quietLogger())
	if err != nil {
		t.Fatalf("resolveIdentity: %v", err)
	}
	if src != identity.SourceEnv || id.AgentID != "legacy-agent" {
		t.Fatalf("legacy env path wrong: src=%s id=%+v", src, id)
	}
	if calls.Load() != 0 {
		t.Errorf("legacy static path must not enroll")
	}
}

func TestResolveIdentity_RedactsTokensFromLogs(t *testing.T) {
	t.Setenv(envAgentID, "")
	t.Setenv(envAgentSecret, "")
	var calls atomic.Int32
	c := fakeEnrollCP(t, &calls)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := Config{
		IdentityFile:      filepath.Join(t.TempDir(), "identity.json"),
		EnrollmentEnabled: true,
		EnrollmentToken:   "ENROLL-TOKEN-SECRET",
		AgentName:         "a",
		ProviderType:      "aws-sm",
	}
	if _, _, err := resolveIdentity(context.Background(), &cfg, c, logger); err != nil {
		t.Fatalf("resolveIdentity: %v", err)
	}
	logs := buf.String()
	if strings.Contains(logs, "ENROLL-TOKEN-SECRET") {
		t.Errorf("enrollment token leaked into logs")
	}
	if strings.Contains(logs, "PERSISTENT-AGENT-TOKEN") {
		t.Errorf("agent_token leaked into logs")
	}
	if !strings.Contains(logs, "enrolled-agent") {
		t.Errorf("expected the safe agent_id in logs for observability")
	}
}
