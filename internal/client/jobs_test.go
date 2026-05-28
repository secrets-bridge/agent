package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/secrets-bridge/agent/internal/client"
)

func TestClaimJob_HappyPath(t *testing.T) {
	gotSecret := ""
	_, c := newFakeCP(t,
		route{
			method: http.MethodPost,
			path:   "/api/v1/agents/agent-1/jobs/claim",
			fn: func(w http.ResponseWriter, r *http.Request) {
				gotSecret = r.Header.Get("X-Agent-Secret")
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(client.Job{
					ID:             "job-42",
					JobType:        "sync",
					Payload:        map[string]any{"ref": "secret-1"},
					CorrelationID:  "corr-1",
					ClaimExpiresAt: "2026-06-01T00:00:30.000Z",
				})
			},
		},
	)
	j, err := c.ClaimJob(context.Background(), "agent-1", "sec")
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}
	if gotSecret != "sec" {
		t.Fatalf("X-Agent-Secret on request: got %q", gotSecret)
	}
	if j.ID != "job-42" || j.JobType != "sync" {
		t.Fatalf("decoded job: %+v", j)
	}
	if j.Payload["ref"] != "secret-1" {
		t.Fatalf("payload not preserved: %+v", j.Payload)
	}
	if d := j.ClaimDeadline(); d.IsZero() {
		t.Fatal("ClaimDeadline did not parse the timestamp")
	}
}

func TestClaimJob_NoContentMapsToErrNoJobs(t *testing.T) {
	_, c := newFakeCP(t,
		route{
			method: http.MethodPost,
			path:   "/api/v1/agents/x/jobs/claim",
			fn:     func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) },
		},
	)
	_, err := c.ClaimJob(context.Background(), "x", "sec")
	if !errors.Is(err, client.ErrNoJobs) {
		t.Fatalf("expected ErrNoJobs, got %v", err)
	}
}

func TestClaimJob_401MapsToErrUnauthorized(t *testing.T) {
	_, c := newFakeCP(t,
		route{
			method: http.MethodPost,
			path:   "/api/v1/agents/x/jobs/claim",
			fn:     func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusUnauthorized) },
		},
	)
	_, err := c.ClaimJob(context.Background(), "x", "wrong")
	if !errors.Is(err, client.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestCompleteJob_HappyPath(t *testing.T) {
	gotBody := map[string]any{}
	_, c := newFakeCP(t,
		route{
			method: http.MethodPost,
			path:   "/api/v1/agents/agent-1/jobs/job-42/complete",
			fn: func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&gotBody)
				w.WriteHeader(http.StatusNoContent)
			},
		},
	)
	if err := c.CompleteJob(context.Background(), "agent-1", "sec", "job-42",
		client.JobOutcome{Status: client.StatusSucceeded}); err != nil {
		t.Fatalf("CompleteJob: %v", err)
	}
	if gotBody["status"] != client.StatusSucceeded {
		t.Fatalf("status not propagated: %+v", gotBody)
	}
}

func TestCompleteJob_409MapsToErrClaimLost(t *testing.T) {
	_, c := newFakeCP(t,
		route{
			method: http.MethodPost,
			path:   "/api/v1/agents/x/jobs/y/complete",
			fn:     func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "lost", http.StatusConflict) },
		},
	)
	err := c.CompleteJob(context.Background(), "x", "sec", "y",
		client.JobOutcome{Status: client.StatusSucceeded})
	if !errors.Is(err, client.ErrClaimLost) {
		t.Fatalf("expected ErrClaimLost, got %v", err)
	}
}

// TestJob_ClaimDeadline_Zero — empty string field → zero time.
func TestJob_ClaimDeadline_Zero(t *testing.T) {
	j := client.Job{}
	if !j.ClaimDeadline().IsZero() {
		t.Fatalf("expected zero time for empty deadline, got %v", j.ClaimDeadline())
	}
}

// Use a real httptest.Server to make sure the request actually leaves
// our process — confirms the URL templating + JSON shape end-to-end.
func TestCompleteJob_SerializesErrorField(t *testing.T) {
	gotBody := map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	c := client.New(srv.URL)
	if err := c.CompleteJob(context.Background(), "a", "s", "j",
		client.JobOutcome{Status: client.StatusFailed, Error: "provider denied"}); err != nil {
		t.Fatalf("CompleteJob: %v", err)
	}
	if gotBody["error"] != "provider denied" {
		t.Fatalf("error field not serialized: %+v", gotBody)
	}
}

// Smoke: ClaimDeadline returns a parseable RFC3339Nano timestamp.
func TestJob_ClaimDeadline_Parsed(t *testing.T) {
	j := client.Job{ClaimExpiresAt: time.Now().UTC().Format(time.RFC3339Nano)}
	d := j.ClaimDeadline()
	if d.IsZero() {
		t.Fatal("ClaimDeadline did not parse a valid RFC3339Nano string")
	}
}
