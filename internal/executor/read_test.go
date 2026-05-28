package executor_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/agent/internal/executor"
	"github.com/secrets-bridge/core/providers"
)

// --- fakes ----------------------------------------------------------

type fakePostWrapClient struct {
	mu    sync.Mutex
	calls []postWrapCall
	err   error
}

type postWrapCall struct {
	requestID   string
	keyName     string
	plaintext   string
	useEnvelope bool
}

func (f *fakePostWrapClient) PostWrap(_ context.Context, _, _, requestID, keyName string, plaintext []byte, useEnvelope bool) (*client.PostWrapResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, postWrapCall{
		requestID:   requestID,
		keyName:     keyName,
		plaintext:   string(plaintext),
		useEnvelope: useEnvelope,
	})
	if f.err != nil {
		return nil, f.err
	}
	return &client.PostWrapResponse{WrapID: "fake-wrap-" + keyName, KeyName: keyName}, nil
}

type fakeGetProvider struct {
	bytes  []byte
	getErr error
}

func (p *fakeGetProvider) GetMetadata(context.Context, providers.SecretRef) (providers.SecretMetadata, error) {
	return providers.SecretMetadata{}, errors.New("unused")
}
func (p *fakeGetProvider) ListMetadata(context.Context, providers.ProviderScope) ([]providers.SecretMetadata, error) {
	return nil, errors.New("unused")
}
func (p *fakeGetProvider) GetValue(_ context.Context, _ providers.SecretRef) (providers.SecretValue, error) {
	if p.getErr != nil {
		return providers.SecretValue{}, p.getErr
	}
	return providers.SecretValue{Bytes: append([]byte(nil), p.bytes...), ContentType: "application/json"}, nil
}
func (p *fakeGetProvider) PutValue(context.Context, providers.SecretRef, providers.SecretValue, providers.PutOptions) (providers.SecretVersion, error) {
	return providers.SecretVersion{}, errors.New("unused")
}

func readResolverReturning(p providers.Provider) executor.ProviderResolver {
	return func(string, map[string]any) (providers.Provider, error) { return p, nil }
}

// --- tests ----------------------------------------------------------

func TestReadExecutor_HappyPath_SpecificKeys(t *testing.T) {
	// Bundle has 3 keys; request asks for 2 of them. Agent must POST
	// exactly those 2 wraps with the correct plaintext per key.
	provider := &fakeGetProvider{
		bytes: []byte(`{"DB_PASSWORD":"hunter2","DB_USER":"billing-svc","API_KEY":"shh"}`),
	}
	wc := &fakePostWrapClient{}
	exec := executor.ReadExecutor{
		AgentID:         "agent-x",
		AgentSecret:     "secret-x",
		Client:          wc,
		ResolveProvider: readResolverReturning(provider),
	}

	out := exec.Execute(t.Context(), &client.Job{
		Payload: map[string]any{
			"request_id":           "req-1",
			"target_provider_type": "vault",
			"target_secret_ref":    "secret/data/billing/prod/db",
			"target_keys":          []any{"DB_PASSWORD", "DB_USER"},
		},
	})
	if out.Status != client.StatusSucceeded {
		t.Fatalf("status=%q error=%q", out.Status, out.Error)
	}
	if len(wc.calls) != 2 {
		t.Fatalf("post-wrap calls = %d want 2", len(wc.calls))
	}
	// Build a lookup so we don't depend on map iteration order.
	got := map[string]string{}
	for _, c := range wc.calls {
		got[c.keyName] = c.plaintext
	}
	if got["DB_PASSWORD"] != "hunter2" {
		t.Fatalf("DB_PASSWORD = %q want hunter2", got["DB_PASSWORD"])
	}
	if got["DB_USER"] != "billing-svc" {
		t.Fatalf("DB_USER = %q want billing-svc", got["DB_USER"])
	}
	if _, ok := got["API_KEY"]; ok {
		t.Fatal("API_KEY was posted but the request didn't ask for it — selective fetch broken")
	}
}

func TestReadExecutor_HappyPath_AllKeysWhenEmptyTargets(t *testing.T) {
	provider := &fakeGetProvider{
		bytes: []byte(`{"DB_PASSWORD":"hunter2","DB_USER":"billing-svc"}`),
	}
	wc := &fakePostWrapClient{}
	exec := executor.ReadExecutor{
		AgentID: "a", AgentSecret: "s",
		Client:          wc,
		ResolveProvider: readResolverReturning(provider),
	}
	out := exec.Execute(t.Context(), &client.Job{Payload: map[string]any{
		"request_id":           "req-2",
		"target_provider_type": "vault",
		"target_secret_ref":    "secret/data/x",
		// target_keys omitted → all keys in the bundle
	}})
	if out.Status != client.StatusSucceeded {
		t.Fatalf("status=%q error=%q", out.Status, out.Error)
	}
	if len(wc.calls) != 2 {
		t.Fatalf("calls = %d want 2 (all bundle keys)", len(wc.calls))
	}
}

func TestReadExecutor_AllRequestedKeysMissing_Fails(t *testing.T) {
	// User asked for keys that the bundle doesn't have at all. Job
	// fails so the requester knows their expectation didn't match.
	provider := &fakeGetProvider{
		bytes: []byte(`{"some_other_key":"v"}`),
	}
	wc := &fakePostWrapClient{}
	exec := executor.ReadExecutor{
		AgentID: "a", AgentSecret: "s",
		Client:          wc,
		ResolveProvider: readResolverReturning(provider),
	}
	out := exec.Execute(t.Context(), &client.Job{Payload: map[string]any{
		"request_id":           "req-3",
		"target_provider_type": "vault",
		"target_secret_ref":    "secret/data/x",
		"target_keys":          []any{"DB_PASSWORD"},
	}})
	if out.Status != client.StatusFailed {
		t.Fatalf("status=%q want failed", out.Status)
	}
	if !strings.Contains(out.Error, "none of the requested keys") {
		t.Fatalf("error doesn't explain: %q", out.Error)
	}
	if len(wc.calls) != 0 {
		t.Fatalf("post-wrap called for missing keys: %d", len(wc.calls))
	}
}

func TestReadExecutor_PartialMissingStillSucceeds(t *testing.T) {
	// User asked for 3 keys; bundle has 2 of them. The executor
	// posts the 2 it found and reports success — the missing one
	// just doesn't show up in the request's wraps.
	provider := &fakeGetProvider{
		bytes: []byte(`{"K1":"v1","K2":"v2"}`),
	}
	wc := &fakePostWrapClient{}
	exec := executor.ReadExecutor{
		AgentID: "a", AgentSecret: "s",
		Client:          wc,
		ResolveProvider: readResolverReturning(provider),
	}
	out := exec.Execute(t.Context(), &client.Job{Payload: map[string]any{
		"request_id":           "req-4",
		"target_provider_type": "vault",
		"target_secret_ref":    "secret/data/x",
		"target_keys":          []any{"K1", "K2", "MISSING"},
	}})
	if out.Status != client.StatusSucceeded {
		t.Fatalf("status=%q error=%q", out.Status, out.Error)
	}
	if len(wc.calls) != 2 {
		t.Fatalf("calls = %d want 2", len(wc.calls))
	}
}

func TestReadExecutor_NonJSONBundle_WrappedAsSingleValueKey(t *testing.T) {
	// Vault's PutValue convention says raw blobs get stored as
	// {"value": "<raw>"}. Symmetrically, when GetValue returns a
	// non-JSON payload we wrap it under "value".
	provider := &fakeGetProvider{bytes: []byte("not-json-just-a-blob")}
	wc := &fakePostWrapClient{}
	exec := executor.ReadExecutor{
		AgentID: "a", AgentSecret: "s",
		Client:          wc,
		ResolveProvider: readResolverReturning(provider),
	}
	out := exec.Execute(t.Context(), &client.Job{Payload: map[string]any{
		"request_id":           "req-5",
		"target_provider_type": "vault",
		"target_secret_ref":    "secret/data/x",
	}})
	if out.Status != client.StatusSucceeded {
		t.Fatalf("status=%q", out.Status)
	}
	if len(wc.calls) != 1 || wc.calls[0].keyName != "value" {
		t.Fatalf("calls = %+v want single value-key", wc.calls)
	}
	if wc.calls[0].plaintext != "not-json-just-a-blob" {
		t.Fatalf("plaintext = %q", wc.calls[0].plaintext)
	}
}

func TestReadExecutor_GetValueFails(t *testing.T) {
	provider := &fakeGetProvider{getErr: errors.New("vault: 403 permission denied")}
	wc := &fakePostWrapClient{}
	exec := executor.ReadExecutor{
		AgentID: "a", AgentSecret: "s",
		Client:          wc,
		ResolveProvider: readResolverReturning(provider),
	}
	out := exec.Execute(t.Context(), &client.Job{Payload: map[string]any{
		"request_id":           "req-6",
		"target_provider_type": "vault",
		"target_secret_ref":    "secret/data/x",
		"target_keys":          []any{"K1"},
	}})
	if out.Status != client.StatusFailed {
		t.Fatalf("status=%q", out.Status)
	}
	if !strings.Contains(out.Error, "get value") {
		t.Fatalf("error doesn't mention get value: %q", out.Error)
	}
	if len(wc.calls) != 0 {
		t.Fatal("post-wrap was called despite GetValue failure")
	}
}

func TestReadExecutor_PostWrapFails_ReportsProgress(t *testing.T) {
	// First PostWrap succeeds, second fails. The error message must
	// include progress (how many posted so far) so the requester /
	// operator can reason about partial completion. NEVER include the
	// plaintext.
	provider := &fakeGetProvider{
		bytes: []byte(`{"K1":"v1","K2":"v2","K3":"super-secret"}`),
	}
	canary := "super-secret"
	wc := &fakePostWrapClient{}
	// Simulate failure on second call by giving it an err only after
	// the first succeeds. Easiest: count calls in a custom impl.
	wc2 := &countingFailingClient{failOnCall: 2}
	exec := executor.ReadExecutor{
		AgentID: "a", AgentSecret: "s",
		Client:          wc2,
		ResolveProvider: readResolverReturning(provider),
	}
	out := exec.Execute(t.Context(), &client.Job{Payload: map[string]any{
		"request_id":           "req-7",
		"target_provider_type": "vault",
		"target_secret_ref":    "secret/data/x",
		"target_keys":          []any{"K1", "K2", "K3"},
	}})
	if out.Status != client.StatusFailed {
		t.Fatalf("status=%q", out.Status)
	}
	if !strings.Contains(out.Error, "after 1 posted") {
		t.Fatalf("error doesn't include progress: %q", out.Error)
	}
	if strings.Contains(out.Error, canary) {
		t.Fatalf("error leaked plaintext: %q", out.Error)
	}
	_ = wc // keep linter happy about the simple fake
}

func TestReadExecutor_PayloadValidation(t *testing.T) {
	exec := executor.ReadExecutor{
		AgentID: "a", AgentSecret: "s",
		Client:          &fakePostWrapClient{},
		ResolveProvider: readResolverReturning(&fakeGetProvider{}),
	}
	cases := []struct {
		name string
		p    map[string]any
		want string
	}{
		{"missing request_id",
			map[string]any{"target_provider_type": "v", "target_secret_ref": "x"},
			"request_id"},
		{"missing provider type",
			map[string]any{"request_id": "r", "target_secret_ref": "x"},
			"target_provider_type"},
		{"missing secret ref",
			map[string]any{"request_id": "r", "target_provider_type": "v"},
			"target_secret_ref"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := exec.Execute(t.Context(), &client.Job{Payload: tc.p})
			if out.Status != client.StatusFailed {
				t.Fatalf("status=%q", out.Status)
			}
			if !strings.Contains(out.Error, tc.want) {
				t.Fatalf("error %q does not contain %q", out.Error, tc.want)
			}
		})
	}
}

func TestReadExecutor_KeypairTogglesEnvelopePath(t *testing.T) {
	// When AgentPublicKey + AgentPrivateKey are both set, PostWrap is
	// called with useEnvelope=true. When nil, useEnvelope=false. This is
	// the agent-side toggle for Piece 8b wire-envelope encryption.
	provider := &fakeGetProvider{bytes: []byte(`{"K":"v"}`)}

	t.Run("with keypair → envelope path", func(t *testing.T) {
		wc := &fakePostWrapClient{}
		exec := executor.ReadExecutor{
			AgentID: "a", AgentSecret: "s",
			AgentPublicKey:  make([]byte, 32),
			AgentPrivateKey: make([]byte, 32),
			Client:          wc,
			ResolveProvider: readResolverReturning(provider),
		}
		out := exec.Execute(t.Context(), &client.Job{Payload: map[string]any{
			"request_id":           "req",
			"target_provider_type": "vault",
			"target_secret_ref":    "x",
		}})
		if out.Status != client.StatusSucceeded {
			t.Fatalf("status=%q error=%q", out.Status, out.Error)
		}
		if len(wc.calls) != 1 || !wc.calls[0].useEnvelope {
			t.Fatalf("calls=%+v want useEnvelope=true on single call", wc.calls)
		}
	})

	t.Run("without keypair → legacy path", func(t *testing.T) {
		wc := &fakePostWrapClient{}
		exec := executor.ReadExecutor{
			AgentID: "a", AgentSecret: "s",
			// AgentPublicKey + AgentPrivateKey deliberately nil
			Client:          wc,
			ResolveProvider: readResolverReturning(provider),
		}
		out := exec.Execute(t.Context(), &client.Job{Payload: map[string]any{
			"request_id":           "req",
			"target_provider_type": "vault",
			"target_secret_ref":    "x",
		}})
		if out.Status != client.StatusSucceeded {
			t.Fatalf("status=%q error=%q", out.Status, out.Error)
		}
		if len(wc.calls) != 1 || wc.calls[0].useEnvelope {
			t.Fatalf("calls=%+v want useEnvelope=false on single call", wc.calls)
		}
	})
}

func TestRouter_DispatchesRead(t *testing.T) {
	called := false
	r := executor.Router{
		ByType: map[string]executor.Executor{
			"read": executorFunc(func(ctx context.Context, _ *client.Job) client.JobOutcome {
				called = true
				return client.JobOutcome{Status: client.StatusSucceeded}
			}),
		},
		Default: executor.NoOp{},
	}
	r.Execute(context.Background(), &client.Job{JobType: "read"})
	if !called {
		t.Fatal("router did not dispatch read")
	}
}

// --- helpers --------------------------------------------------------

// countingFailingClient succeeds for the first N-1 calls then fails on
// the failOnCall-th call. Used to test partial-progress reporting.
type countingFailingClient struct {
	mu         sync.Mutex
	failOnCall int
	count      int
}

func (c *countingFailingClient) PostWrap(context.Context, string, string, string, string, []byte, bool) (*client.PostWrapResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	if c.count == c.failOnCall {
		return nil, errors.New("simulated 500")
	}
	return &client.PostWrapResponse{WrapID: "ok"}, nil
}
