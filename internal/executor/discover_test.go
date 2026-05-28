package executor_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/agent/internal/executor"
	"github.com/secrets-bridge/core/providers"
)

// --- fakes ----------------------------------------------------------

type fakeBulkClient struct {
	last *client.SecretBulkRequest
	resp *client.SecretBulkResponse
	err  error
}

func (f *fakeBulkClient) PostSecretsBulk(_ context.Context, _, _ string, body client.SecretBulkRequest) (*client.SecretBulkResponse, error) {
	cp := body
	f.last = &cp
	if f.err != nil {
		return nil, f.err
	}
	if f.resp != nil {
		return f.resp, nil
	}
	return &client.SecretBulkResponse{Count: len(body.Items)}, nil
}

type fakeListProvider struct {
	metas    []providers.SecretMetadata
	listErr  error
	gotScope providers.ProviderScope
}

func (p *fakeListProvider) GetMetadata(context.Context, providers.SecretRef) (providers.SecretMetadata, error) {
	return providers.SecretMetadata{}, errors.New("unused")
}
func (p *fakeListProvider) ListMetadata(_ context.Context, scope providers.ProviderScope) ([]providers.SecretMetadata, error) {
	p.gotScope = scope
	return p.metas, p.listErr
}
func (p *fakeListProvider) GetValue(context.Context, providers.SecretRef) (providers.SecretValue, error) {
	return providers.SecretValue{}, errors.New("unused")
}
func (p *fakeListProvider) PutValue(context.Context, providers.SecretRef, providers.SecretValue, providers.PutOptions) (providers.SecretVersion, error) {
	return providers.SecretVersion{}, errors.New("unused")
}

func discoverResolverReturning(p providers.Provider) executor.ProviderResolver {
	return func(string, map[string]any) (providers.Provider, error) { return p, nil }
}

// --- tests ----------------------------------------------------------

func TestDiscoverExecutor_HappyPath_PreservesProviderTags(t *testing.T) {
	// The core point of discovery: provider-native tags (Vault
	// custom_metadata, AWS Tags) end up in the SecretBulkItem.Labels
	// verbatim. Without this the GIN-indexed search on the CP side
	// is useless.
	created := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	updated := time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC)
	provider := &fakeListProvider{
		metas: []providers.SecretMetadata{
			{
				Ref:     providers.SecretRef{Provider: "aws-sm", Name: "archive/uat/db"},
				Version: providers.SecretVersion{ID: "v1"},
				Labels: map[string]string{
					"Environment": "uat",
					"Team":        "archive",
					"App":         "billing",
				},
				CreatedAt: created,
				UpdatedAt: updated,
			},
			{
				Ref:     providers.SecretRef{Provider: "aws-sm", Name: "archive/uat/api"},
				Version: providers.SecretVersion{ID: "v3"},
				Labels: map[string]string{
					"Environment": "uat",
					"Team":        "archive",
					"PII":         "true",
				},
			},
		},
	}
	wc := &fakeBulkClient{}
	exec := executor.DiscoverExecutor{
		AgentID:         "agent-x",
		AgentSecret:     "secret-x",
		ClusterName:     "uat-archive-cluster",
		Client:          wc,
		ResolveProvider: discoverResolverReturning(provider),
	}

	out := exec.Execute(t.Context(), &client.Job{
		JobType: "discover",
		Payload: map[string]any{"target_provider_type": "aws-sm"},
	})
	if out.Status != client.StatusSucceeded {
		t.Fatalf("status=%q error=%q want succeeded", out.Status, out.Error)
	}
	if wc.last == nil {
		t.Fatal("PostSecretsBulk was not called")
	}
	if wc.last.ClusterName != "uat-archive-cluster" {
		t.Fatalf("cluster_name = %q", wc.last.ClusterName)
	}
	if wc.last.ProviderType != "aws-sm" {
		t.Fatalf("provider_type = %q", wc.last.ProviderType)
	}
	if len(wc.last.Items) != 2 {
		t.Fatalf("items = %d want 2", len(wc.last.Items))
	}

	// First item: tags preserved verbatim.
	first := wc.last.Items[0]
	if first.SecretRef != "archive/uat/db" {
		t.Fatalf("secret_ref[0] = %q", first.SecretRef)
	}
	if first.Labels["Environment"] != "uat" || first.Labels["Team"] != "archive" || first.Labels["App"] != "billing" {
		t.Fatalf("first.Labels not preserved: %v", first.Labels)
	}
	if first.CreatedAtSource == nil || !first.CreatedAtSource.Equal(created) {
		t.Fatalf("CreatedAtSource = %v want %v", first.CreatedAtSource, created)
	}
	if first.UpdatedAtSource == nil || !first.UpdatedAtSource.Equal(updated) {
		t.Fatalf("UpdatedAtSource = %v want %v", first.UpdatedAtSource, updated)
	}
}

func TestDiscoverExecutor_RequiresClusterName(t *testing.T) {
	exec := executor.DiscoverExecutor{
		AgentID: "a", AgentSecret: "s",
		Client:          &fakeBulkClient{},
		ResolveProvider: discoverResolverReturning(&fakeListProvider{}),
	}
	out := exec.Execute(t.Context(), &client.Job{
		Payload: map[string]any{"target_provider_type": "vault"},
	})
	if out.Status != client.StatusFailed {
		t.Fatalf("status = %q want failed", out.Status)
	}
	if !strings.Contains(out.Error, "SB_CLUSTER_NAME") {
		t.Fatalf("error doesn't mention env var: %q", out.Error)
	}
}

func TestDiscoverExecutor_PayloadValidation(t *testing.T) {
	exec := executor.DiscoverExecutor{
		AgentID: "a", AgentSecret: "s", ClusterName: "c",
		Client:          &fakeBulkClient{},
		ResolveProvider: discoverResolverReturning(&fakeListProvider{}),
	}
	out := exec.Execute(t.Context(), &client.Job{Payload: map[string]any{}})
	if out.Status != client.StatusFailed {
		t.Fatalf("status = %q", out.Status)
	}
	if !strings.Contains(out.Error, "target_provider_type") {
		t.Fatalf("error doesn't mention required field: %q", out.Error)
	}
}

func TestDiscoverExecutor_ListMetadataFails(t *testing.T) {
	provider := &fakeListProvider{listErr: errors.New("vault: token expired")}
	exec := executor.DiscoverExecutor{
		AgentID: "a", AgentSecret: "s", ClusterName: "c",
		Client:          &fakeBulkClient{},
		ResolveProvider: discoverResolverReturning(provider),
	}
	out := exec.Execute(t.Context(), &client.Job{
		Payload: map[string]any{"target_provider_type": "vault"},
	})
	if out.Status != client.StatusFailed {
		t.Fatalf("status = %q", out.Status)
	}
	if !strings.Contains(out.Error, "list metadata") {
		t.Fatalf("error: %q", out.Error)
	}
}

func TestDiscoverExecutor_BulkPostFailureIsCounted(t *testing.T) {
	// On bulk-post failure the error message includes the item count,
	// not individual refs (path leakage).
	provider := &fakeListProvider{
		metas: []providers.SecretMetadata{
			{Ref: providers.SecretRef{Name: "a"}},
			{Ref: providers.SecretRef{Name: "b"}},
		},
	}
	wc := &fakeBulkClient{err: errors.New("503")}
	exec := executor.DiscoverExecutor{
		AgentID: "a", AgentSecret: "s", ClusterName: "c",
		Client:          wc,
		ResolveProvider: discoverResolverReturning(provider),
	}
	out := exec.Execute(t.Context(), &client.Job{
		Payload: map[string]any{"target_provider_type": "vault"},
	})
	if out.Status != client.StatusFailed {
		t.Fatalf("status = %q", out.Status)
	}
	if !strings.Contains(out.Error, "(2 items)") {
		t.Fatalf("error doesn't include item count: %q", out.Error)
	}
	// Ref names must NOT appear in the error (avoid path leakage in
	// telemetry / oncall pages).
	if strings.Contains(out.Error, "name=a") || strings.Contains(out.Error, "/a") {
		t.Fatalf("error leaked a secret_ref: %q", out.Error)
	}
}

func TestDiscoverExecutor_EmptyListIsSuccess(t *testing.T) {
	wc := &fakeBulkClient{}
	exec := executor.DiscoverExecutor{
		AgentID: "a", AgentSecret: "s", ClusterName: "c",
		Client:          wc,
		ResolveProvider: discoverResolverReturning(&fakeListProvider{}),
	}
	out := exec.Execute(t.Context(), &client.Job{
		Payload: map[string]any{"target_provider_type": "vault"},
	})
	if out.Status != client.StatusSucceeded {
		t.Fatalf("status = %q error = %q", out.Status, out.Error)
	}
	if wc.last == nil {
		t.Fatal("expected PostSecretsBulk to be called even for empty list (heartbeat-style)")
	}
	if len(wc.last.Items) != 0 {
		t.Fatalf("items = %d want 0", len(wc.last.Items))
	}
}

func TestDiscoverExecutor_ScopeAndLabelSelectorPassThrough(t *testing.T) {
	provider := &fakeListProvider{}
	exec := executor.DiscoverExecutor{
		AgentID: "a", AgentSecret: "s", ClusterName: "c",
		Client:          &fakeBulkClient{},
		ResolveProvider: discoverResolverReturning(provider),
	}
	_ = exec.Execute(t.Context(), &client.Job{Payload: map[string]any{
		"target_provider_type": "vault",
		"scope":                "billing/",
		"label_selector":       map[string]string{"env": "uat"},
	}})
	if provider.gotScope.Scope != "billing/" {
		t.Fatalf("scope = %q", provider.gotScope.Scope)
	}
	if provider.gotScope.LabelSelector["env"] != "uat" {
		t.Fatalf("label_selector did not propagate: %v", provider.gotScope.LabelSelector)
	}
}

func TestRouter_DispatchesDiscover(t *testing.T) {
	called := false
	r := executor.Router{
		ByType: map[string]executor.Executor{
			"discover": executorFunc(func(ctx context.Context, _ *client.Job) client.JobOutcome {
				called = true
				return client.JobOutcome{Status: client.StatusSucceeded}
			}),
		},
		Default: executor.NoOp{},
	}
	r.Execute(context.Background(), &client.Job{JobType: "discover"})
	if !called {
		t.Fatal("router did not dispatch discover")
	}
}
