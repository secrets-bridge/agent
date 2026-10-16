package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/agent/internal/identity"
)

// completeRecorder is a fake CP that records every outcome posted to
// /jobs/:id/complete.
type completeRecorder struct {
	mu       sync.Mutex
	outcomes []client.JobOutcome
}

func (r *completeRecorder) handle(w http.ResponseWriter, req *http.Request) {
	var out client.JobOutcome
	_ = json.NewDecoder(req.Body).Decode(&out)
	r.mu.Lock()
	r.outcomes = append(r.outcomes, out)
	r.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (r *completeRecorder) all() []client.JobOutcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]client.JobOutcome(nil), r.outcomes...)
}

type panickingExecutor struct{}

func (panickingExecutor) Execute(context.Context, *client.Job) client.JobOutcome {
	// Shape of the real failure: a malformed sealed nonce reaching
	// gcm.Open. The panic message must never reach logs or the CP.
	panic("fake-value-in-panic-message")
}

// AGT-N-05: one bad job must not take down the agent. A panic inside an
// executor is recovered, the job is reported failed, and nothing from the
// panic value is logged or sent to the CP.
func TestProcessJob_RecoversExecutorPanic(t *testing.T) {
	rec := &completeRecorder{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agents/agent-a/jobs/job-1/complete", rec.handle)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := client.New(srv.URL)
	id := identity.Identity{AgentID: "agent-a", AgentSecret: "secret-a"}

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("executor panic escaped processJob and would crash the agent: %v", r)
			}
		}()
		processJob(context.Background(), logger, c, panickingExecutor{}, id, &client.Job{ID: "job-1", JobType: "patch"})
	}()

	got := rec.all()
	if len(got) != 1 || got[0].Status != client.StatusFailed {
		t.Fatalf("outcomes = %+v want one failed outcome", got)
	}
	if strings.Contains(got[0].Error, "fake-value") {
		t.Fatalf("panic value reached the CP: %q", got[0].Error)
	}
	if strings.Contains(logs.String(), "fake-value") {
		t.Fatalf("panic value reached the logs: %s", logs.String())
	}
}

// AGT-N-08: the one-time enrollment token is dropped from cfg and from the
// process env once enrollment has succeeded.
func TestResolveIdentity_ScrubsEnrollmentTokenAfterEnroll(t *testing.T) {
	t.Setenv(envAgentID, "")
	t.Setenv(envAgentSecret, "")
	t.Setenv("SB_ENROLLMENT_TOKEN", "ENROLL-TOKEN-SECRET")
	var calls atomic.Int32
	c := fakeEnrollCP(t, &calls)
	cfg := Config{
		IdentityFile:      filepath.Join(t.TempDir(), "identity.json"),
		EnrollmentEnabled: true,
		EnrollmentToken:   "ENROLL-TOKEN-SECRET",
		AgentName:         "a",
		ProviderType:      "aws-sm",
	}
	if _, _, err := resolveIdentity(context.Background(), &cfg, c, quietLogger()); err != nil {
		t.Fatalf("resolveIdentity: %v", err)
	}
	if cfg.EnrollmentToken != "" {
		t.Fatal("enrollment token still held in cfg after enrollment")
	}
	if v, ok := os.LookupEnv("SB_ENROLLMENT_TOKEN"); ok {
		t.Fatalf("SB_ENROLLMENT_TOKEN still in the process env after enrollment (%d bytes)", len(v))
	}
}

// AGT-N-02 end to end with the transport the binary builds: an https CP
// that redirects to a plain-http host on another port must not get the
// agent to follow, and the redirect target must never see X-Agent-Secret.
func TestBuildHTTPClient_RefusesHTTPSToHTTPRedirect(t *testing.T) {
	var targetHits, targetSecrets atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		if r.Header.Get("X-Agent-Secret") != "" {
			targetSecrets.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)

	cp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(cp.Close)

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cp.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	hc, err := buildHTTPClient(Config{CPEndpoint: cp.URL, CAFile: caPath, TLSServerName: "example.com"})
	if err != nil {
		t.Fatalf("buildHTTPClient: %v", err)
	}

	// Raw transport check: the client itself must not follow.
	req, _ := http.NewRequest(http.MethodPost, cp.URL+"/api/v1/agents/agent-a/heartbeat", http.NoBody)
	req.Header.Set("X-Agent-Secret", "secret-a")
	resp, err := hc.Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	// And through the CP client the agent actually uses.
	c := client.New(cp.URL).WithHTTPClient(hc)
	_, hbErr := c.Heartbeat(context.Background(), "agent-a", "secret-a", &client.HeartbeatReport{Status: "active"})

	if targetHits.Load() != 0 {
		t.Fatalf("redirect followed: target hit %d times, %d with X-Agent-Secret", targetHits.Load(), targetSecrets.Load())
	}
	if resp == nil || resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("raw transport did not return the 307 as-is: resp=%v err=%v", resp, err)
	}
	if hbErr == nil {
		t.Fatal("heartbeat treated a 307 as success")
	}
}

// AGT-N-08: credentials in SB_CP_ENDPOINT never reach the startup log.
func TestRedactEndpoint(t *testing.T) {
	cases := map[string]string{
		"https://cp.example.com":                            "https://cp.example.com",
		"https://cp.example.com:8443/base":                  "https://cp.example.com:8443/base",
		"https://user:fake-password@cp.example.com/":        "https://cp.example.com/",
		"https://fake-token@cp.example.com":                 "https://cp.example.com",
		"https://cp.example.com/?token=fake-token#frag":     "https://cp.example.com/",
		"http://user:fake-password@127.0.0.1:18080/api?x=y": "http://127.0.0.1:18080/api",
		"%%not a url fake-password":                         "<unparseable endpoint>",
	}
	for in, want := range cases {
		got := redactEndpoint(in)
		if got != want {
			t.Errorf("redactEndpoint(%q) = %q want %q", in, got, want)
		}
		if strings.Contains(got, "fake-") {
			t.Errorf("redactEndpoint(%q) kept a credential: %q", in, got)
		}
	}
}

// The startup error for an unparseable SB_CP_ENDPOINT must not echo the
// URL, which can carry userinfo.
func TestValidateEndpoint_ParseErrorDoesNotEchoCredentials(t *testing.T) {
	_, err := validateEndpoint("https://agent:fake-password%zz@cp.example.com", false)
	if err == nil {
		t.Fatal("malformed endpoint accepted")
	}
	if strings.Contains(err.Error(), "fake-password") || strings.Contains(err.Error(), "agent:") {
		t.Fatalf("endpoint error carries the credential: %v", err)
	}
	if !strings.Contains(err.Error(), "valid URL") {
		t.Fatalf("error lost its hint: %v", err)
	}
}
