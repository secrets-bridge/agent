// Package executor — discover.go: the DiscoverExecutor.
//
// DiscoverExecutor turns a claimed `discover` job into a CP-side
// upsert of the provider's currently-visible secrets. The flow:
//
//   1. Validate cluster identity (SB_CLUSTER_NAME must be set on the
//      agent — discovery is meaningless without it).
//   2. Parse job.Payload to extract target provider info + the scope
//      to enumerate.
//   3. Resolve the provider via the same ResolverByType used by
//      PatchExecutor — every wired provider supports both flows.
//   4. provider.ListMetadata(scope) → []SecretMetadata. Each entry
//      carries the provider's native tags translated into Labels
//      by the core/providers connector (Vault custom_metadata; AWS
//      Secrets Manager Tags; etc.).
//   5. Map each SecretMetadata into a SecretBulkItem, preserving
//      Labels verbatim so the CP's GIN index can find them later.
//   6. POST the batch to the CP via client.PostSecretsBulk.
//
// Hard rules inside the executor:
//   - NO value bytes ever travel through this flow. core/providers
//     ListMetadata is metadata-only; the SecretBulkItem JSON shape
//     has no value field; the CP's bulk endpoint rejects values
//     at the schema level.
//   - Failure messages name the provider type + secret_ref count,
//     never individual refs (paths can leak organisational structure
//     in error telemetry).
package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/core/providers"
)

// BulkClient is the slice of *client.Client the DiscoverExecutor
// needs. Defined here so unit tests can swap in a fake.
type BulkClient interface {
	PostSecretsBulk(ctx context.Context, agentID, agentSecret string, body client.SecretBulkRequest) (*client.SecretBulkResponse, error)
}

// DiscoverExecutor implements Executor for job_type=discover jobs.
type DiscoverExecutor struct {
	AgentID         string
	AgentSecret     string
	ClusterName     string
	Client          BulkClient
	ResolveProvider ProviderResolver
}

// Execute runs one discover job to completion.
func (d DiscoverExecutor) Execute(ctx context.Context, job *client.Job) client.JobOutcome {
	if d.ClusterName == "" {
		return fail("cluster name is empty (set SB_CLUSTER_NAME)")
	}
	payload, err := parseDiscoverPayload(job.Payload)
	if err != nil {
		return fail("payload: " + err.Error())
	}

	provider, err := d.ResolveProvider(payload.TargetProviderType, payload.TargetProviderConfig)
	if err != nil {
		return fail("resolve provider: " + err.Error())
	}

	metas, err := provider.ListMetadata(ctx, providers.ProviderScope{
		Provider:      payload.TargetProviderType,
		Scope:         payload.Scope,
		LabelSelector: payload.LabelSelector,
	})
	if err != nil {
		return fail("list metadata: " + err.Error())
	}

	items := make([]client.SecretBulkItem, 0, len(metas))
	for _, m := range metas {
		labels := make(map[string]any, len(m.Labels))
		for k, v := range m.Labels {
			labels[k] = v
		}
		item := client.SecretBulkItem{
			SecretRef: m.Ref.Name,
			Labels:    labels,
			Version:   m.Version.ID,
			Checksum:  m.Checksum,
		}
		if !m.CreatedAt.IsZero() {
			t := m.CreatedAt
			item.CreatedAtSource = &t
		}
		if !m.UpdatedAt.IsZero() {
			t := m.UpdatedAt
			item.UpdatedAtSource = &t
		}
		items = append(items, item)
	}

	resp, err := d.Client.PostSecretsBulk(ctx, d.AgentID, d.AgentSecret, client.SecretBulkRequest{
		ClusterName:    d.ClusterName,
		ProviderType:   payload.TargetProviderType,
		ProviderConfig: payload.TargetProviderConfig,
		Items:          items,
	})
	if err != nil {
		return fail(fmt.Sprintf("post secrets bulk (%d items): %v", len(items), err))
	}

	out := client.JobOutcome{Status: client.StatusSucceeded}
	_ = resp // count + ids available for future per-batch audit if needed
	return out
}

// discoverPayload is the typed view of the JSON in a discover job's
// payload. Mirrors the shape the api emits (admin.POST /jobs with
// job_type=discover, or future scheduler).
type discoverPayload struct {
	TargetProviderType   string            `json:"target_provider_type"`
	TargetProviderConfig map[string]any    `json:"target_provider_config"`
	Scope                string            `json:"scope"`
	LabelSelector        map[string]string `json:"label_selector"`
}

func parseDiscoverPayload(raw map[string]any) (*discoverPayload, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	var p discoverPayload
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	if p.TargetProviderType == "" {
		return nil, errors.New("target_provider_type required")
	}
	return &p, nil
}
