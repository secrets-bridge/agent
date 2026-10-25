package client_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/secrets-bridge/agent/internal/client"
)

func TestSecret_JSONRoundTripAndRefusals(t *testing.T) {
	b, err := json.Marshal(struct {
		T client.Secret `json:"t"`
	}{client.Secret("abc-_123")})
	if err != nil || string(b) != `{"t":"abc-_123"}` {
		t.Fatalf("marshal = %s, %v", b, err)
	}
	if _, err := json.Marshal(client.Secret("a\"b")); err == nil {
		t.Fatal("secret needing escapes was marshalled")
	}
	var out struct {
		T client.Secret `json:"t"`
	}
	if err := json.Unmarshal([]byte(`{"t":"xyz"}`), &out); err != nil || string(out.T) != "xyz" {
		t.Fatalf("unmarshal = %q, %v", out.T, err)
	}
	if err := json.Unmarshal([]byte(`{"t":"x\\y"}`), &out); err == nil {
		t.Fatal("escaped secret accepted")
	}
	out.T.Zero()
	if string(out.T) != "\x00\x00\x00" {
		t.Fatal("Zero left bytes behind")
	}
}

// The enrollment endpoints are token-only: no X-Agent-Secret, the token in
// the body with schema_version "2", and CP refusals mapped to safe codes.
func TestEnroll_RequestShapeAndErrors(t *testing.T) {
	var body map[string]any
	var hdr http.Header
	status, reply := http.StatusUnauthorized, `{"error":"enrollment_rejected"}`
	c, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		hdr = r.Header.Clone()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	})
	_, err := c.EnrollChallenge(t.Context(), client.Secret("fake-enroll-token"), make([]byte, 32))
	var rej *client.ErrEnrollmentRejected
	if !errors.As(err, &rej) || rej.Reason != "enrollment_rejected" || rej.Status != 401 {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "fake-enroll-token") {
		t.Fatalf("token in error: %v", err)
	}
	if body["schema_version"] != "2" || body["enrollment_token"] != "fake-enroll-token" || body["public_key_algorithm"] != "x25519" {
		t.Fatalf("challenge body = %v", body)
	}
	if hdr.Get("X-Agent-Secret") != "" || hdr.Get("X-Agent-Key-Fingerprint") != "" {
		t.Fatal("token-only call carried agent headers")
	}

	for _, tc := range []struct {
		status int
		reply  string
		reason string
	}{
		{400, `{"error":"invalid_public_key"}`, "invalid_public_key"},
		{400, `{"error":"unsupported_schema_version"}`, "unsupported_schema_version"},
		{429, `{"error":"slow down"}`, "rate_limited"},
		{403, `not json`, "enrollment_rejected"},
	} {
		status, reply = tc.status, tc.reply
		_, err := c.Enroll(t.Context(), client.EnrollRequest{EnrollmentToken: client.Secret("fake-enroll-token"), Name: "a"})
		if !errors.As(err, &rej) || rej.Reason != tc.reason {
			t.Errorf("%d %s: got %v want %s", tc.status, tc.reply, err, tc.reason)
		}
		if body["schema_version"] != "2" {
			t.Errorf("enroll body lacks schema_version 2: %v", body)
		}
	}

	status, reply = http.StatusCreated, `{"agent_id":"a"}`
	if _, err := c.Enroll(t.Context(), client.EnrollRequest{EnrollmentToken: client.Secret("t"), Name: "a"}); err == nil {
		t.Fatal("incomplete enroll response accepted")
	}
	status, reply = http.StatusOK, `{"challenge_id":"c1"}`
	if _, err := c.EnrollChallenge(t.Context(), client.Secret("t"), make([]byte, 32)); err == nil {
		t.Fatal("challenge without sealed_challenge accepted")
	}
}
