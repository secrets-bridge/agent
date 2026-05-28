// Package local hosts the agent's loopback-only HTTP server for
// /healthz, /readyz, and /metrics. Built on stdlib net/http; no
// framework dependency — the agent's whole point is to stay small
// inside customer boundaries.
package local

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Probes serves liveness and readiness.
type Probes struct {
	ready atomic.Bool
}

// NewProbes returns Probes in the "not ready" state.
func NewProbes() *Probes { return &Probes{} }

// SetReady toggles the readiness gate. The agent flips it true after
// identity is loaded and the first heartbeat succeeds.
func (p *Probes) SetReady(v bool) { p.ready.Store(v) }

func (p *Probes) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (p *Probes) readyz(w http.ResponseWriter, _ *http.Request) {
	if p.ready.Load() {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
}

// Server bundles the loopback HTTP server. Keep it tiny — handlers
// live in this file so adding a new one is one method + one route.
type Server struct {
	srv *http.Server
}

// NewServer builds the loopback server.
func NewServer(addr string, probes *Probes, _ *slog.Logger) *Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", probes.healthz)
	mux.HandleFunc("/readyz", probes.readyz)
	mux.Handle("/metrics", promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{EnableOpenMetrics: true},
	))

	return &Server{
		srv: &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
}

// ListenAndServe blocks until the server is shut down.
func (s *Server) ListenAndServe() error { return s.srv.ListenAndServe() }

// ServeOn lets tests bind to a pre-created listener (typically port 0)
// so they don't fight for fixed ports under parallel runs.
func (s *Server) ServeOn(ln net.Listener) error { return s.srv.Serve(ln) }

// Shutdown drains in-flight requests, bounded by ctx.
func (s *Server) Shutdown(ctx context.Context) error { return s.srv.Shutdown(ctx) }

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
