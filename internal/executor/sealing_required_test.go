package executor_test

import (
	"context"
	"strings"
	"testing"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/agent/internal/executor"
)

// AGT-02: without a keypair the executors refuse to move values at all.
// There is no unsealed fallback in either direction.

func TestReadExecutor_NoKeypair_RefusesUnsealedPost(t *testing.T) {
	provider := &fakeGetProvider{bytes: []byte(`{"DB_PASSWORD":"fake-value"}`)}
	wc := &fakePostWrapClient{}
	exec := executor.ReadExecutor{
		AgentID: "agent-a", AgentSecret: "secret-a",
		Client:          wc,
		ResolveProvider: readResolverReturning(provider),
	}
	out := exec.Execute(t.Context(), &client.Job{Payload: map[string]any{
		"request_id": "req-1", "target_provider_type": "vault", "target_secret_ref": "db",
	}})
	if out.Status != client.StatusFailed {
		t.Fatalf("status=%q; a read without a keypair must not post a wrap", out.Status)
	}
	if len(wc.calls) != 0 {
		t.Fatalf("PostWrap called %d times without sealing", len(wc.calls))
	}
	if strings.Contains(out.Error, "fake-value") {
		t.Fatalf("error carries the value: %q", out.Error)
	}
}

func TestPatchExecutor_NoKeypair_RefusesUnsealedFetch(t *testing.T) {
	fp := &fakeProvider{}
	wc := &fakeWrapClient{
		values:  map[string]string{"wrap-1": "fake-value"},
		keyName: map[string]string{"wrap-1": "DB_PASSWORD"},
	}
	exec := executor.PatchExecutor{
		AgentID: "agent-a", AgentSecret: "secret-a",
		Client:          wc,
		ResolveProvider: resolverReturning(fp),
	}
	out := exec.Execute(t.Context(), &client.Job{Payload: map[string]any{
		"target_provider_type": "vault",
		"target_secret_ref":    "db",
		"wraps":                []any{map[string]any{"wrap_id": "wrap-1", "key_name": "DB_PASSWORD"}},
	}})
	if out.Status != client.StatusFailed {
		t.Fatalf("status=%q; a patch without a keypair must not fetch wraps", out.Status)
	}
	if len(wc.calls) != 0 || len(fp.putCalls) != 0 {
		t.Fatalf("wrap fetched (%v) or provider written (%d) without sealing", wc.calls, len(fp.putCalls))
	}
}

// AGT-N-06: an unknown job type is a failure, never a silent success.
func TestRouter_UnknownJobTypeFails(t *testing.T) {
	r := executor.Router{ByType: map[string]executor.Executor{
		"read": executorFunc(func(_ context.Context, _ *client.Job) client.JobOutcome {
			return client.JobOutcome{Status: client.StatusSucceeded}
		}),
	}}
	for _, jt := range []string{"sync", "", "READ", "rotate"} {
		out := r.Execute(t.Context(), &client.Job{ID: "job-1", JobType: jt})
		if out.Status != client.StatusFailed {
			t.Fatalf("job_type %q: status=%q want failed", jt, out.Status)
		}
		if !strings.Contains(out.Error, "unsupported job type") {
			t.Fatalf("job_type %q: error %q does not say unsupported job type", jt, out.Error)
		}
	}
}
