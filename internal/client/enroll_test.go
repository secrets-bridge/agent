package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/secrets-bridge/agent/internal/client"
)

func TestEnroll_HappyPath_TokenInBodyNotHeader(t *testing.T) {
	var gotBody map[string]any
	var authHeaders []string
	_, c := newFakeCP(t, route{
		method: http.MethodPost,
		path:   "/api/v1/agents/enroll",
		fn: func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			authHeaders = []string{r.Header.Get("X-Agent-Secret"), r.Header.Get("Authorization")}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"agent_id":"a-1","provider_connection_id":"pc-1","agent_token":"secret-token-xyz","heartbeat_interval_seconds":30,"job_poll_interval_seconds":5}`)
		},
	})
	res, err := c.Enroll(context.Background(), client.EnrollRequest{
		EnrollmentToken: "enroll-tok-abc", AgentName: "a", ProviderType: "aws-sm",
		ClusterName: "eks-x", AgentVersion: "v1", Region: "eu",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if res.AgentID != "a-1" || res.AgentToken != "secret-token-xyz" || res.ProviderConnectionID != "pc-1" {
		t.Fatalf("result wrong: %+v", res)
	}
	if res.HeartbeatIntervalSeconds != 30 || res.JobPollIntervalSeconds != 5 {
		t.Errorf("intervals wrong: %+v", res)
	}
	// The token travels in the BODY, never an auth header.
	if gotBody["enrollment_token"] != "enroll-tok-abc" {
		t.Errorf("token not in body: %v", gotBody)
	}
	for _, h := range authHeaders {
		if strings.Contains(h, "enroll-tok-abc") {
			t.Errorf("token leaked into an auth header: %q", h)
		}
	}
}

func TestEnroll_InvalidToken_PermanentRejection_NoTokenLeak(t *testing.T) {
	_, c := newFakeCP(t, route{
		method: http.MethodPost,
		path:   "/api/v1/agents/enroll",
		fn: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"enrollment_token_invalid"}`)
		},
	})
	_, err := c.Enroll(context.Background(), client.EnrollRequest{EnrollmentToken: "super-secret-token", AgentName: "a"})
	var rej *client.ErrEnrollmentRejected
	if !errors.As(err, &rej) {
		t.Fatalf("expected *ErrEnrollmentRejected, got %T: %v", err, err)
	}
	if rej.Status != http.StatusUnauthorized || rej.Reason != "enrollment_token_invalid" {
		t.Errorf("rejection wrong: %+v", rej)
	}
	if strings.Contains(err.Error(), "super-secret-token") {
		t.Errorf("token leaked into error: %v", err)
	}
}

func TestEnroll_ConsumedToken_409Rejection(t *testing.T) {
	_, c := newFakeCP(t, route{
		method: http.MethodPost,
		path:   "/api/v1/agents/enroll",
		fn: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":"enrollment_token_already_consumed"}`)
		},
	})
	_, err := c.Enroll(context.Background(), client.EnrollRequest{EnrollmentToken: "t", AgentName: "a"})
	var rej *client.ErrEnrollmentRejected
	if !errors.As(err, &rej) || rej.Reason != "enrollment_token_already_consumed" {
		t.Fatalf("expected consumed rejection, got %v", err)
	}
}

func TestEnroll_Transient5xx_IsRetryableNotPermanent(t *testing.T) {
	_, c := newFakeCP(t, route{
		method: http.MethodPost,
		path:   "/api/v1/agents/enroll",
		fn: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "upstream down")
		},
	})
	_, err := c.Enroll(context.Background(), client.EnrollRequest{EnrollmentToken: "t", AgentName: "a"})
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusBadGateway {
		t.Fatalf("expected retryable *HTTPError 502, got %T: %v", err, err)
	}
	var rej *client.ErrEnrollmentRejected
	if errors.As(err, &rej) {
		t.Errorf("a 5xx must NOT be classified as a permanent rejection")
	}
}

func TestHeartbeat_WithBody_Parses200NextInterval(t *testing.T) {
	var gotBody map[string]any
	_, c := newFakeCP(t, route{
		method: http.MethodPost,
		path:   "/api/v1/agents/a-1/heartbeat",
		fn: func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"ok","server_time":"2026-08-13T00:00:00Z","next_heartbeat_seconds":45}`)
		},
	})
	res, err := c.Heartbeat(context.Background(), "a-1", "sec", &client.HeartbeatReport{Status: "active", AgentVersion: "v1"})
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if res.NextHeartbeatSeconds != 45 {
		t.Errorf("next_heartbeat_seconds = %d want 45", res.NextHeartbeatSeconds)
	}
	if gotBody["status"] != "active" || gotBody["agent_version"] != "v1" {
		t.Errorf("heartbeat body not sent: %v", gotBody)
	}
}

func TestHeartbeat_Bodyless_204NoNextInterval(t *testing.T) {
	_, c := newFakeCP(t, route{
		method: http.MethodPost,
		path:   "/api/v1/agents/a-1/heartbeat",
		fn: func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > 0 {
				t.Errorf("expected a bodyless heartbeat, got content-length %d", r.ContentLength)
			}
			w.WriteHeader(http.StatusNoContent)
		},
	})
	res, err := c.Heartbeat(context.Background(), "a-1", "sec", nil)
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if res.NextHeartbeatSeconds != 0 {
		t.Errorf("bodyless heartbeat should yield next=0, got %d", res.NextHeartbeatSeconds)
	}
}
