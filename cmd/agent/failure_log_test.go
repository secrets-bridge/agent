package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/agent/internal/executor"
	"github.com/secrets-bridge/agent/internal/identity"
	"github.com/secrets-bridge/core/providers"
)

const failureCanary = "canary-value-7c1e9a"

// bundleProvider serves one fixed JSON bundle.
type bundleProvider struct{ bundle []byte }

func (p bundleProvider) GetMetadata(context.Context, providers.SecretRef) (providers.SecretMetadata, error) {
	return providers.SecretMetadata{}, errors.New("unused")
}

func (p bundleProvider) ListMetadata(context.Context, providers.ProviderScope) ([]providers.SecretMetadata, error) {
	return nil, errors.New("unused")
}

func (p bundleProvider) GetValue(context.Context, providers.SecretRef) (providers.SecretValue, error) {
	return providers.SecretValue{Bytes: append([]byte(nil), p.bundle...)}, nil
}

func (p bundleProvider) PutValue(context.Context, providers.SecretRef, providers.SecretValue, providers.PutOptions) (providers.SecretVersion, error) {
	return providers.SecretVersion{}, errors.New("unused")
}

// refusingWrapClient accepts every key except refuse, which gets the
// CP's 500. The error body echoes the value to prove the agent redacts
// it before logging or reporting.
type refusingWrapClient struct{ refuse string }

func (c refusingWrapClient) PostWrap(_ context.Context, _, _, _, keyName string, plaintext []byte) (*client.PostWrapResponse, error) {
	if keyName == c.refuse {
		return nil, &client.HTTPError{Status: http.StatusInternalServerError,
			Body: `{"error":"wraps: refused value ` + string(plaintext) + `"}`}
	}
	return &client.PostWrapResponse{WrapID: "w-" + keyName, KeyName: keyName}, nil
}

func runJob(t *testing.T, exec executor.Executor, job *client.Job) (logs string, outcomes []client.JobOutcome) {
	t.Helper()
	rec := &completeRecorder{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agents/agent-a/jobs/"+job.ID+"/complete", rec.handle)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	id := identity.Identity{AgentID: "agent-a", AgentSecret: "secret-a"}
	processJob(context.Background(), logger, client.New(srv.URL), exec, id, job)
	return buf.String(), rec.all()
}

// warnLine returns the decoded "job failed" WARN line, failing the test
// unless exactly one exists.
func warnLine(t *testing.T, logs string) map[string]any {
	t.Helper()
	var found []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		if m["msg"] == "job failed" {
			found = append(found, m)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want one \"job failed\" line, got %d:\n%s", len(found), logs)
	}
	if found[0]["level"] != "WARN" {
		t.Fatalf("level = %v want WARN", found[0]["level"])
	}
	return found[0]
}

// agent#39: a read refused at one key logs a WARN line with the key, the
// counts and the CP's reason, and never the value.
func TestProcessJob_FailedReadLogsKeyCountsAndReason(t *testing.T) {
	exec := executor.ReadExecutor{
		AgentID: "agent-a", AgentSecret: "secret-a",
		AgentPublicKey:  make([]byte, 32),
		AgentPrivateKey: make([]byte, 32),
		Client:          refusingWrapClient{refuse: "K2"},
		ResolveProvider: func(string, map[string]any) (providers.Provider, error) {
			return bundleProvider{bundle: []byte(`{"K1":"v1","K2":"` + failureCanary + `","K3":"v3"}`)}, nil
		},
	}
	job := &client.Job{ID: "job-r", JobType: "read", Payload: map[string]any{
		"request_id":           "req-1",
		"target_provider_type": "vault",
		"target_secret_ref":    "secret/data/app",
		"target_keys":          []any{"K1", "K2", "K3", "GONE"},
	}}

	logs, outcomes := runJob(t, exec, job)

	if len(outcomes) != 1 || outcomes[0].Status != client.StatusFailed {
		t.Fatalf("outcomes = %+v want one failed outcome", outcomes)
	}
	w := warnLine(t, logs)
	if w["job_id"] != "job-r" || w["job_type"] != "read" {
		t.Fatalf("job fields wrong: %v", w)
	}
	if w["key"] != "K2" {
		t.Fatalf("key = %v want K2", w["key"])
	}
	for field, want := range map[string]float64{"posted": 1, "missing": 1, "total": 4} {
		if w[field] != want {
			t.Fatalf("%s = %v want %v", field, w[field], want)
		}
	}
	reason, _ := w["reason"].(string)
	for _, sub := range []string{`key="K2"`, "http 500", "wraps: refused value", "1 posted", "1 missing", "4 total"} {
		if !strings.Contains(reason, sub) {
			t.Fatalf("reason %q missing %q", reason, sub)
		}
	}
	if reason != outcomes[0].Error {
		t.Fatalf("logged reason %q differs from the CP outcome %q", reason, outcomes[0].Error)
	}
	if strings.Contains(logs, failureCanary) {
		t.Fatalf("value reached the logs: %s", logs)
	}
	if strings.Contains(outcomes[0].Error, failureCanary) {
		t.Fatalf("value reached the CP outcome: %q", outcomes[0].Error)
	}
}

// The generic claim loop path: a job the router can't run is logged with
// its reason too.
func TestProcessJob_UnsupportedJobTypeLogsReason(t *testing.T) {
	logs, outcomes := runJob(t, executor.Router{ByType: map[string]executor.Executor{}},
		&client.Job{ID: "job-u", JobType: "frobnicate"})
	if len(outcomes) != 1 || outcomes[0].Status != client.StatusFailed {
		t.Fatalf("outcomes = %+v want one failed outcome", outcomes)
	}
	w := warnLine(t, logs)
	if w["job_id"] != "job-u" || w["job_type"] != "frobnicate" {
		t.Fatalf("job fields wrong: %v", w)
	}
	if reason, _ := w["reason"].(string); !strings.Contains(reason, `unsupported job type "frobnicate"`) {
		t.Fatalf("reason = %q", reason)
	}
}

// Patch and discover failures take the same path.
func TestProcessJob_FailedPatchAndDiscoverLogReason(t *testing.T) {
	for _, jt := range []string{"patch", "discover"} {
		t.Run(jt, func(t *testing.T) {
			exec := executor.Router{ByType: map[string]executor.Executor{
				"patch":    executor.PatchExecutor{},
				"discover": executor.DiscoverExecutor{},
			}}
			logs, _ := runJob(t, exec, &client.Job{ID: "job-" + jt, JobType: jt, Payload: map[string]any{}})
			w := warnLine(t, logs)
			if w["job_type"] != jt {
				t.Fatalf("job_type = %v", w["job_type"])
			}
			if reason, _ := w["reason"].(string); reason == "" {
				t.Fatal("empty reason")
			}
		})
	}
}

// A succeeded job logs no WARN line.
func TestProcessJob_SucceededJobLogsNoFailure(t *testing.T) {
	logs, _ := runJob(t, okExecutor{}, &client.Job{ID: "job-ok", JobType: "read"})
	if strings.Contains(logs, "job failed") {
		t.Fatalf("succeeded job logged a failure: %s", logs)
	}
}

type okExecutor struct{}

func (okExecutor) Execute(context.Context, *client.Job) client.JobOutcome {
	return client.JobOutcome{Status: client.StatusSucceeded}
}
