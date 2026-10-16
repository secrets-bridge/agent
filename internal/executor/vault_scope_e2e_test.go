package executor_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/agent/internal/executor"
)

// fakeVault records every request path the real core/providers/vault
// client sends and answers KV v2 reads with a small bundle. It lets the
// tests below drive the real resolver + real Vault provider end to end
// and assert which Vault paths a job payload can reach (AGT-N-01).
type fakeVault struct {
	mu    sync.Mutex
	paths []string
}

func (f *fakeVault) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == "LIST" || r.URL.Query().Get("list") == "true":
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": []string{"db"}}})
	case strings.Contains(r.URL.Path, "/metadata/"):
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"current_version": 1, "custom_metadata": map[string]any{},
		}})
	case r.Method == http.MethodGet:
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"data": map[string]any{"DB_PASSWORD": "fake-value"},
		}})
	default:
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": 2}})
	}
}

func (f *fakeVault) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

// newFakeVault starts the fake and pins the agent to mount "team-a-kv",
// prefix "team-a" via env, the way the chart does.
func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()
	fv := &fakeVault{}
	srv := httptest.NewServer(http.HandlerFunc(fv.handler))
	t.Cleanup(srv.Close)
	t.Setenv(executor.EnvVaultAddr, srv.URL)
	t.Setenv(executor.EnvVaultToken, "test-token")
	t.Setenv(executor.EnvVaultKVMount, "team-a-kv")
	t.Setenv(executor.EnvVaultKVPrefix, "team-a")
	return fv
}

func assertOnlyPinnedPaths(t *testing.T, fv *fakeVault) {
	t.Helper()
	for _, p := range fv.seen() {
		urlPath := strings.SplitN(p, " ", 2)[1]
		rest, ok := strings.CutPrefix(urlPath, "/v1/team-a-kv/")
		if ok {
			_, rest, ok = strings.Cut(rest, "/") // drop "data" / "metadata"
		}
		if !ok || (rest != "team-a" && !strings.HasPrefix(rest, "team-a/")) {
			t.Fatalf("job reached a Vault path outside the pinned mount/prefix: %s (all: %v)", p, fv.seen())
		}
	}
}

func sealedReadExecutor(c executor.PostWrapClient) executor.ReadExecutor {
	return executor.ReadExecutor{
		AgentID:         "agent-a",
		AgentSecret:     "secret-a",
		AgentPublicKey:  make([]byte, 32),
		AgentPrivateKey: make([]byte, 32),
		Client:          c,
		ResolveProvider: executor.ResolverByType(context.Background()),
	}
}

func TestVaultE2E_ReadPayloadCannotLeavePinnedScope(t *testing.T) {
	cases := map[string]map[string]any{
		"kvPrefix traversal": {
			"target_provider_config": map[string]any{"kvPrefix": "../../other-kv/data/team-b"},
		},
		"kvMount override": {
			"target_provider_config": map[string]any{"kvMount": "other-kv"},
		},
		"secret ref traversal": {
			"target_secret_ref": "../../../other-kv/data/team-b/db",
		},
	}
	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			fv := newFakeVault(t)
			payload := map[string]any{
				"request_id":           "req-1",
				"target_provider_type": "vault",
				"target_secret_ref":    "db",
			}
			for k, v := range override {
				payload[k] = v
			}
			wc := &fakePostWrapClient{}
			out := sealedReadExecutor(wc).Execute(t.Context(), &client.Job{Payload: payload})
			if out.Status != client.StatusFailed {
				t.Fatalf("status=%q (vault paths %v); a payload must not widen the Vault scope", out.Status, fv.seen())
			}
			if len(fv.seen()) != 0 {
				t.Fatalf("Vault was called before the payload was refused: %v", fv.seen())
			}
			if len(wc.calls) != 0 {
				t.Fatalf("a wrap was posted for a refused job: %d", len(wc.calls))
			}
		})
	}
}

func TestVaultE2E_PatchPayloadCannotLeavePinnedScope(t *testing.T) {
	for name, payload := range map[string]map[string]any{
		"kvPrefix": {"target_provider_config": map[string]any{"kvPrefix": "../../other-kv/data/team-b"}, "target_secret_ref": "db"},
		"kvMount":  {"target_provider_config": map[string]any{"kvMount": "other-kv"}, "target_secret_ref": "db"},
		"ref":      {"target_secret_ref": "../../../other-kv/data/team-b/db"},
	} {
		t.Run(name, func(t *testing.T) {
			fv := newFakeVault(t)
			wc := &fakeWrapClient{
				values:  map[string]string{"wrap-1": "fake-value"},
				keyName: map[string]string{"wrap-1": "DB_PASSWORD"},
			}
			exec := executor.PatchExecutor{
				AgentID: "agent-a", AgentSecret: "secret-a",
				AgentPublicKey:  make([]byte, 32),
				AgentPrivateKey: make([]byte, 32),
				Client:          wc,
				ResolveProvider: executor.ResolverByType(t.Context()),
			}
			payload["target_provider_type"] = "vault"
			payload["wraps"] = []any{map[string]any{"wrap_id": "wrap-1", "key_name": "DB_PASSWORD"}}
			out := exec.Execute(t.Context(), &client.Job{Payload: payload})
			if out.Status != client.StatusFailed {
				t.Fatalf("status=%q (vault paths %v)", out.Status, fv.seen())
			}
			if len(fv.seen()) != 0 || len(wc.calls) != 0 {
				t.Fatalf("refused job still touched Vault (%v) or fetched wraps (%v)", fv.seen(), wc.calls)
			}
		})
	}
}

func TestVaultE2E_DiscoverScopeCannotLeavePinnedPrefix(t *testing.T) {
	for _, scope := range []string{"../../other-kv/metadata/team-b", "team-b"} {
		t.Run(scope, func(t *testing.T) {
			fv := newFakeVault(t)
			bc := &fakeBulkClient{}
			exec := executor.DiscoverExecutor{
				AgentID: "agent-a", AgentSecret: "secret-a", ClusterName: "tenant-a-uat",
				Client:          bc,
				ResolveProvider: executor.ResolverByType(t.Context()),
			}
			out := exec.Execute(t.Context(), &client.Job{Payload: map[string]any{
				"target_provider_type": "vault",
				"scope":                scope,
			}})
			if out.Status != client.StatusFailed {
				t.Fatalf("status=%q (vault paths %v)", out.Status, fv.seen())
			}
			if len(fv.seen()) != 0 || bc.last != nil {
				t.Fatalf("refused discover still listed Vault (%v) or posted a batch", fv.seen())
			}
		})
	}
}

// The legit shapes keep working against the same fake Vault and only ever
// touch the pinned mount + prefix.
func TestVaultE2E_LegitJobsStayInPinnedScope(t *testing.T) {
	t.Run("read, no config", func(t *testing.T) {
		fv := newFakeVault(t)
		wc := &fakePostWrapClient{}
		out := sealedReadExecutor(wc).Execute(t.Context(), &client.Job{Payload: map[string]any{
			"request_id": "req-1", "target_provider_type": "vault", "target_secret_ref": "db",
		}})
		if out.Status != client.StatusSucceeded {
			t.Fatalf("status=%q error=%q", out.Status, out.Error)
		}
		assertOnlyPinnedPaths(t, fv)
		if len(wc.calls) != 1 {
			t.Fatalf("post-wrap calls = %d want 1", len(wc.calls))
		}
	})
	t.Run("read, echoed config", func(t *testing.T) {
		fv := newFakeVault(t)
		wc := &fakePostWrapClient{}
		out := sealedReadExecutor(wc).Execute(t.Context(), &client.Job{Payload: map[string]any{
			"request_id": "req-1", "target_provider_type": "vault", "target_secret_ref": "db",
			"target_provider_config": map[string]any{"kvMount": "team-a-kv", "kvPrefix": "team-a"},
		}})
		if out.Status != client.StatusSucceeded {
			t.Fatalf("status=%q error=%q", out.Status, out.Error)
		}
		assertOnlyPinnedPaths(t, fv)
	})
	t.Run("discover, echoed scope", func(t *testing.T) {
		fv := newFakeVault(t)
		bc := &fakeBulkClient{}
		exec := executor.DiscoverExecutor{
			AgentID: "agent-a", AgentSecret: "secret-a", ClusterName: "tenant-a-uat",
			Client:          bc,
			ResolveProvider: executor.ResolverByType(t.Context()),
		}
		out := exec.Execute(t.Context(), &client.Job{Payload: map[string]any{
			"target_provider_type": "vault", "scope": "team-a/",
		}})
		if out.Status != client.StatusSucceeded {
			t.Fatalf("status=%q error=%q", out.Status, out.Error)
		}
		assertOnlyPinnedPaths(t, fv)
		if bc.last == nil || len(bc.last.Items) != 1 {
			t.Fatalf("discover batch = %+v want 1 item", bc.last)
		}
	})
}
