package client_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/secrets-bridge/agent/internal/client"
)

func newServer(t *testing.T, h http.HandlerFunc) (*client.Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := client.New(srv.URL).WithHTTPClient(srv.Client())
	return c, srv
}

func TestGetWrap_HappyPath_VerifiesContentHash(t *testing.T) {
	plaintext := []byte("hunter2")
	sum := sha256.Sum256(plaintext)
	hashHex := hex.EncodeToString(sum[:])
	body := `{"wrap_id":"w","request_id":"r","key_name":"DB_PASSWORD","value":"` +
		base64.StdEncoding.EncodeToString(plaintext) +
		`","byte_length":7,"content_hash":"` + hashHex + `","algorithm":"AES-256-GCM"}`

	c, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s want GET", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/wraps/w") {
			t.Errorf("path = %s want suffix /wraps/w", r.URL.Path)
		}
		if r.Header.Get("X-Agent-Secret") != "s" {
			t.Errorf("missing X-Agent-Secret header")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})

	got, err := c.GetWrap(t.Context(), "agent-x", "s", "w")
	if err != nil {
		t.Fatalf("GetWrap: %v", err)
	}
	if string(got.Plaintext) != "hunter2" {
		t.Fatalf("plaintext = %q want hunter2", got.Plaintext)
	}
	if got.KeyName != "DB_PASSWORD" {
		t.Fatalf("key_name = %q", got.KeyName)
	}
}

func TestGetWrap_ContentHashMismatch(t *testing.T) {
	// Send a hash that won't match the bytes.
	body := `{"wrap_id":"w","value":"` + base64.StdEncoding.EncodeToString([]byte("hunter2")) +
		`","byte_length":7,"content_hash":"deadbeef","algorithm":"AES-256-GCM"}`
	c, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	_, err := c.GetWrap(t.Context(), "a", "s", "w")
	if !errors.Is(err, client.ErrContentHashMismatch) {
		t.Fatalf("got %v want ErrContentHashMismatch", err)
	}
}

func TestGetWrap_StatusMapping(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusUnauthorized, client.ErrUnauthorized},
		{http.StatusNotFound, client.ErrNotFound},
		{http.StatusGone, client.ErrWrapGone},
		{http.StatusConflict, client.ErrRequestNotApproved},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			c, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			})
			_, err := c.GetWrap(t.Context(), "a", "s", "w")
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}
