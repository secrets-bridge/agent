package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
