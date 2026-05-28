package local_test

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/secrets-bridge/agent/internal/local"
)

func newServerOnEphemeralPort(t *testing.T, ready bool) (string, *local.Server) {
	t.Helper()
	p := local.NewProbes()
	p.SetReady(ready)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := local.NewServer(ln.Addr().String(), p, nil)
	go func() { _ = srv.ServeOn(ln) }()
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })

	return "http://" + ln.Addr().String(), srv
}

func TestHealthz_AlwaysOK(t *testing.T) {
	base, _ := newServerOnEphemeralPort(t, false)
	resp, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Fatalf("body: %q", body)
	}
}

func TestReadyz_GatedByState(t *testing.T) {
	base, _ := newServerOnEphemeralPort(t, false)
	resp, err := http.Get(base + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	// Flip + retry; same server.
	base2, _ := newServerOnEphemeralPort(t, true)
	resp2, err := http.Get(base2 + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz (ready): %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("ready status: %d", resp2.StatusCode)
	}
}

func TestMetrics_ServesPromText(t *testing.T) {
	base, _ := newServerOnEphemeralPort(t, true)
	resp, err := http.Get(base + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "go_") && !strings.Contains(string(body), "process_") {
		t.Fatalf("metrics body looks empty: %q", string(body[:min(200, len(body))]))
	}
}
