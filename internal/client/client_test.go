package client_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/secrets-bridge/agent/internal/client"
)

// newFakeCP returns an httptest.Server impersonating the CP API.
type route struct {
	method string
	path   string
	fn     http.HandlerFunc
}

func newFakeCP(t *testing.T, routes ...route) (*httptest.Server, *client.Client) {
	t.Helper()
	mux := http.NewServeMux()
	for _, r := range routes {
		r := r
		mux.HandleFunc(r.path, func(w http.ResponseWriter, req *http.Request) {
			if req.Method != r.method {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			r.fn(w, req)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := client.New(srv.URL)
	return srv, c
}

func TestHeartbeat_SendsSecretInHeader(t *testing.T) {
	gotHeader := ""
	_, c := newFakeCP(t,
		route{
			method: http.MethodPost,
			path:   "/api/v1/agents/agent-1/heartbeat",
			fn: func(w http.ResponseWriter, r *http.Request) {
				gotHeader = r.Header.Get("X-Agent-Secret")
				w.WriteHeader(http.StatusNoContent)
			},
		},
	)
	if err := c.Heartbeat(context.Background(), "agent-1", "sec-xyz"); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if gotHeader != "sec-xyz" {
		t.Fatalf("X-Agent-Secret on request: got %q", gotHeader)
	}
}

func TestHeartbeat_401MapsToErrUnauthorized(t *testing.T) {
	_, c := newFakeCP(t,
		route{
			method: http.MethodPost,
			path:   "/api/v1/agents/x/heartbeat",
			fn:     func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusUnauthorized) },
		},
	)
	if err := c.Heartbeat(context.Background(), "x", "wrong"); !errors.Is(err, client.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestHeartbeat_404MapsToErrNotFound(t *testing.T) {
	_, c := newFakeCP(t,
		route{
			method: http.MethodPost,
			path:   "/api/v1/agents/missing/heartbeat",
			fn:     func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusNotFound) },
		},
	)
	if err := c.Heartbeat(context.Background(), "missing", "tok"); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestHeartbeat_500ReturnsHTTPErrorWithSnippet(t *testing.T) {
	_, c := newFakeCP(t,
		route{
			method: http.MethodPost,
			path:   "/api/v1/agents/x/heartbeat",
			fn: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = io.WriteString(w, "db down")
			},
		},
	)
	err := c.Heartbeat(context.Background(), "x", "sec")
	if err == nil {
		t.Fatal("expected error on 500")
	}
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected *HTTPError, got %T: %v", err, err)
	}
	if httpErr.Status != http.StatusInternalServerError {
		t.Fatalf("status: %d", httpErr.Status)
	}
	if !strings.Contains(httpErr.Body, "db down") {
		t.Fatalf("body snippet missing: %q", httpErr.Body)
	}
}
