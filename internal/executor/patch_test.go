package executor_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/agent/internal/executor"
	"github.com/secrets-bridge/core/providers"
)

// --- fakes ----------------------------------------------------------

type fakeWrapClient struct {
	values map[string]string // wrap_id -> plaintext
	keyName map[string]string // wrap_id -> key_name
	err    error
	calls  []string
}

func (f *fakeWrapClient) GetWrap(_ context.Context, _, _, wrapID string, _, _ []byte) (*client.Wrap, error) {
	f.calls = append(f.calls, wrapID)
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.values[wrapID]
	if !ok {
		return nil, client.ErrNotFound
	}
	return &client.Wrap{
		WrapID:    wrapID,
		KeyName:   f.keyName[wrapID],
		Plaintext: []byte(v),
	}, nil
}

type fakeProvider struct {
	mu        sync.Mutex
	existing  []byte
	getErr    error
	putErr    error
	putCalls  []putCall
	putReturn providers.SecretVersion
}

type putCall struct {
	ref   providers.SecretRef
	value []byte
}

func (p *fakeProvider) GetValue(_ context.Context, _ providers.SecretRef) (providers.SecretValue, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.getErr != nil {
		return providers.SecretValue{}, p.getErr
	}
	if p.existing == nil {
		return providers.SecretValue{}, providers.ErrNotFound
	}
	return providers.SecretValue{Bytes: append([]byte(nil), p.existing...), ContentType: "application/json"}, nil
}

func (p *fakeProvider) PutValue(_ context.Context, ref providers.SecretRef, v providers.SecretValue, _ providers.PutOptions) (providers.SecretVersion, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.putErr != nil {
		return providers.SecretVersion{}, p.putErr
	}
	cp := append([]byte(nil), v.Bytes...)
	p.putCalls = append(p.putCalls, putCall{ref: ref, value: cp})
	p.existing = cp
	return p.putReturn, nil
}

func (p *fakeProvider) GetMetadata(context.Context, providers.SecretRef) (providers.SecretMetadata, error) {
	return providers.SecretMetadata{}, errors.New("not used by patch executor")
}
func (p *fakeProvider) ListMetadata(context.Context, providers.ProviderScope) ([]providers.SecretMetadata, error) {
	return nil, errors.New("not used by patch executor")
}

func resolverReturning(p providers.Provider) executor.ProviderResolver {
	return func(string, map[string]any) (providers.Provider, error) { return p, nil }
}

// --- tests ----------------------------------------------------------

func TestPatchExecutor_HappyPath_NewBundle(t *testing.T) {
	fp := &fakeProvider{} // no existing bundle
	wc := &fakeWrapClient{
		values: map[string]string{
			"wrap-1": "hunter2",
			"wrap-2": "billing-svc",
		},
		keyName: map[string]string{
			"wrap-1": "DB_PASSWORD",
			"wrap-2": "DB_USER",
		},
	}
	exec := executor.PatchExecutor{
		AgentID:         "agent-x",
		AgentSecret:     "secret-x",
		Client:          wc,
		ResolveProvider: resolverReturning(fp),
	}

	job := &client.Job{
		ID:      "job-1",
		JobType: "patch",
		Payload: map[string]any{
			"target_provider_type": "vault",
			"target_secret_ref":    "secret/data/billing/prod/db",
			"wraps": []any{
				map[string]any{"wrap_id": "wrap-1", "key_name": "DB_PASSWORD"},
				map[string]any{"wrap_id": "wrap-2", "key_name": "DB_USER"},
			},
		},
	}

	out := exec.Execute(t.Context(), job)
	if out.Status != client.StatusSucceeded {
		t.Fatalf("status=%q error=%q want succeeded", out.Status, out.Error)
	}
	if len(fp.putCalls) != 1 {
		t.Fatalf("PutValue calls=%d want 1", len(fp.putCalls))
	}
	var got map[string]string
	if err := json.Unmarshal(fp.putCalls[0].value, &got); err != nil {
		t.Fatalf("PutValue body not JSON: %v", err)
	}
	if got["DB_PASSWORD"] != "hunter2" || got["DB_USER"] != "billing-svc" {
		t.Fatalf("bundle = %v want both keys", got)
	}
}

func TestPatchExecutor_HappyPath_MergesWithExisting(t *testing.T) {
	// Existing bundle has API_KEY which our patch doesn't touch. After
	// the executor runs, both API_KEY (untouched) and DB_PASSWORD (new)
	// must be present.
	fp := &fakeProvider{existing: []byte(`{"API_KEY":"keep-me"}`)}
	wc := &fakeWrapClient{
		values:  map[string]string{"wrap-1": "rotated-pw"},
		keyName: map[string]string{"wrap-1": "DB_PASSWORD"},
	}
	exec := executor.PatchExecutor{
		AgentID: "a", AgentSecret: "s", Client: wc,
		ResolveProvider: resolverReturning(fp),
	}
	job := &client.Job{Payload: map[string]any{
		"target_provider_type": "vault",
		"target_secret_ref":    "secret/data/x",
		"wraps":                []any{map[string]any{"wrap_id": "wrap-1", "key_name": "DB_PASSWORD"}},
	}}
	out := exec.Execute(t.Context(), job)
	if out.Status != client.StatusSucceeded {
		t.Fatalf("status: %q err: %q", out.Status, out.Error)
	}
	var got map[string]string
	_ = json.Unmarshal(fp.putCalls[0].value, &got)
	if got["API_KEY"] != "keep-me" {
		t.Fatalf("API_KEY clobbered: %v", got)
	}
	if got["DB_PASSWORD"] != "rotated-pw" {
		t.Fatalf("DB_PASSWORD not written: %v", got)
	}
}

func TestPatchExecutor_WrapFetchFails_NoPutValue(t *testing.T) {
	fp := &fakeProvider{}
	wc := &fakeWrapClient{err: client.ErrWrapGone}
	exec := executor.PatchExecutor{
		AgentID: "a", AgentSecret: "s", Client: wc,
		ResolveProvider: resolverReturning(fp),
	}
	job := &client.Job{Payload: map[string]any{
		"target_provider_type": "vault",
		"target_secret_ref":    "secret/data/x",
		"wraps":                []any{map[string]any{"wrap_id": "wrap-1", "key_name": "X"}},
	}}
	out := exec.Execute(t.Context(), job)
	if out.Status != client.StatusFailed {
		t.Fatalf("status: %q", out.Status)
	}
	if !strings.Contains(out.Error, "fetch wrap") {
		t.Fatalf("error doesn't mention fetch wrap: %q", out.Error)
	}
	if len(fp.putCalls) != 0 {
		t.Fatalf("PutValue called %d times on fetch failure", len(fp.putCalls))
	}
}

func TestPatchExecutor_ProviderPutFails_PropagatesError(t *testing.T) {
	fp := &fakeProvider{putErr: errors.New("cas conflict")}
	wc := &fakeWrapClient{
		values:  map[string]string{"w": "v"},
		keyName: map[string]string{"w": "K"},
	}
	exec := executor.PatchExecutor{
		AgentID: "a", AgentSecret: "s", Client: wc,
		ResolveProvider: resolverReturning(fp),
	}
	job := &client.Job{Payload: map[string]any{
		"target_provider_type": "vault",
		"target_secret_ref":    "secret/data/x",
		"wraps":                []any{map[string]any{"wrap_id": "w", "key_name": "K"}},
	}}
	out := exec.Execute(t.Context(), job)
	if out.Status != client.StatusFailed {
		t.Fatalf("status: %q", out.Status)
	}
	if !strings.Contains(out.Error, "cas conflict") {
		t.Fatalf("error doesn't propagate provider error: %q", out.Error)
	}
}

func TestPatchExecutor_PayloadValidation(t *testing.T) {
	exec := executor.PatchExecutor{
		AgentID: "a", AgentSecret: "s",
		Client: &fakeWrapClient{},
		ResolveProvider: resolverReturning(&fakeProvider{}),
	}
	cases := []struct {
		name string
		p    map[string]any
		want string
	}{
		{
			"missing provider type",
			map[string]any{"target_secret_ref": "x", "wraps": []any{map[string]any{"wrap_id": "w"}}},
			"target_provider_type",
		},
		{
			"missing secret ref",
			map[string]any{"target_provider_type": "vault", "wraps": []any{map[string]any{"wrap_id": "w"}}},
			"target_secret_ref",
		},
		{
			"empty wraps",
			map[string]any{"target_provider_type": "vault", "target_secret_ref": "x", "wraps": []any{}},
			"wraps array empty",
		},
		{
			"wrap missing id",
			map[string]any{"target_provider_type": "vault", "target_secret_ref": "x", "wraps": []any{map[string]any{"key_name": "K"}}},
			"wrap_id empty",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := exec.Execute(t.Context(), &client.Job{Payload: tc.p})
			if out.Status != client.StatusFailed {
				t.Fatalf("status: %q", out.Status)
			}
			if !strings.Contains(out.Error, tc.want) {
				t.Fatalf("error %q does not contain %q", out.Error, tc.want)
			}
		})
	}
}

func TestRouter_DispatchesByJobType(t *testing.T) {
	patchCalled := false
	defaultCalled := false
	r := executor.Router{
		ByType: map[string]executor.Executor{
			"patch": executorFunc(func(ctx context.Context, job *client.Job) client.JobOutcome {
				patchCalled = true
				return client.JobOutcome{Status: client.StatusSucceeded}
			}),
		},
		Default: executorFunc(func(context.Context, *client.Job) client.JobOutcome {
			defaultCalled = true
			return client.JobOutcome{Status: client.StatusSucceeded}
		}),
	}
	r.Execute(t.Context(), &client.Job{JobType: "patch"})
	if !patchCalled || defaultCalled {
		t.Fatalf("patch called=%v default called=%v want patch only", patchCalled, defaultCalled)
	}
	patchCalled, defaultCalled = false, false
	r.Execute(t.Context(), &client.Job{JobType: "sync"})
	if patchCalled || !defaultCalled {
		t.Fatalf("for sync job: patch=%v default=%v want default only", patchCalled, defaultCalled)
	}
}

func TestRouter_NoMatchNoDefault_Fails(t *testing.T) {
	r := executor.Router{}
	out := r.Execute(t.Context(), &client.Job{JobType: "weird"})
	if out.Status != client.StatusFailed {
		t.Fatalf("status: %q", out.Status)
	}
	if !strings.Contains(out.Error, "weird") {
		t.Fatalf("error %q does not mention the job_type", out.Error)
	}
}

// executorFunc adapts a plain func into an Executor for table tests.
type executorFunc func(ctx context.Context, job *client.Job) client.JobOutcome

func (f executorFunc) Execute(ctx context.Context, job *client.Job) client.JobOutcome {
	return f(ctx, job)
}
