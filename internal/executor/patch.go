// Package executor — patch.go: the PatchExecutor.
//
// PatchExecutor turns a claimed `patch`-type job into a provider write.
// Flow:
//
//  1. Parse job.Payload to extract request_id + target provider info +
//     the list of {wrap_id, key_name} pairs.
//  2. Resolve the right core/providers.Provider for target_provider_type.
//  3. Fetch every wrap via the CP's single-shot retrieval endpoint
//     (client.GetWrap). Each fetched plaintext is held in memory ONLY
//     until the bundle write succeeds, then zeroed.
//  4. Read the existing provider bundle (GetValue). PutValue would
//     otherwise overwrite the full bundle — patch semantic merges new
//     keys on top of the existing JSON map so untouched keys survive.
//  5. PutValue the merged bundle.
//
// Failure posture:
//   - Wrap fetch failures (NotFound / Gone / RequestNotApproved / etc.)
//     return JobOutcome{StatusFailed} with a short, non-sensitive error.
//     The CP marks the request as failed.
//   - Any plaintext that has already been fetched is zeroed before the
//     executor returns, regardless of outcome.
//   - Idempotency: the existing-bundle read+merge ensures a re-run of
//     the same job produces the same final bundle.
package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/core/providers"
)

// WrapClient is the slice of *client.Client the PatchExecutor needs.
// Defined here as an interface so unit tests can swap in a fake.
type WrapClient interface {
	GetWrap(ctx context.Context, agentID, agentSecret, wrapID string) (*client.Wrap, error)
}

// ProviderResolver maps a job's target_provider_type + config into a
// concrete core/providers.Provider. The resolver is wired in main —
// keeping the executor unaware of which providers are compiled in
// lets the unit tests plug a mock without dragging cloud SDKs.
type ProviderResolver func(providerType string, config map[string]any) (providers.Provider, error)

// NotConfiguredResolver is the placeholder resolver wired in main
// until the concrete provider resolvers (vault, awssm, ...) land.
// It returns a typed error so failed jobs carry an explicit reason.
func NotConfiguredResolver(providerType string, _ map[string]any) (providers.Provider, error) {
	return nil, fmt.Errorf("no provider resolver configured for type=%q (agent build missing provider wiring)", providerType)
}

// PatchExecutor implements Executor for job_type=patch jobs.
type PatchExecutor struct {
	AgentID      string
	AgentSecret  string
	Client       WrapClient
	ResolveProvider ProviderResolver
}

// Execute runs one patch job to completion.
func (p PatchExecutor) Execute(ctx context.Context, job *client.Job) client.JobOutcome {
	payload, err := parsePatchPayload(job.Payload)
	if err != nil {
		return fail("payload: " + err.Error())
	}

	provider, err := p.ResolveProvider(payload.TargetProviderType, payload.TargetProviderConfig)
	if err != nil {
		return fail("resolve provider: " + err.Error())
	}

	// Fetch every wrap. zero each plaintext at the end, no matter
	// what happens — including on the success path AFTER PutValue.
	bundleUpdates := make(map[string][]byte, len(payload.Wraps))
	defer func() {
		for _, b := range bundleUpdates {
			client.Zero(b)
		}
	}()

	for _, w := range payload.Wraps {
		got, err := p.Client.GetWrap(ctx, p.AgentID, p.AgentSecret, w.WrapID)
		if err != nil {
			return fail(fmt.Sprintf("fetch wrap %s (%s): %v", w.WrapID, w.KeyName, err))
		}
		// Trust the wrap's key_name over the payload's hint so a
		// schema-level invariant (wraps row carries its own key_name)
		// wins over an out-of-date job payload.
		name := got.KeyName
		if name == "" {
			name = w.KeyName
		}
		bundleUpdates[name] = got.Plaintext
	}

	ref := providers.SecretRef{
		Provider: payload.TargetProviderType,
		Name:     payload.TargetSecretRef,
	}

	// PATCH semantic: read existing bundle (if any), overlay updates,
	// write merged result. The merge keeps untouched keys safe and
	// makes re-runs idempotent.
	existing, err := readExistingBundle(ctx, provider, ref)
	if err != nil {
		return fail("read existing bundle: " + err.Error())
	}
	for k, v := range bundleUpdates {
		existing[k] = string(v)
	}
	merged, err := json.Marshal(existing)
	if err != nil {
		return fail("marshal merged bundle: " + err.Error())
	}

	if _, err := provider.PutValue(ctx, ref, providers.SecretValue{
		Bytes:       merged,
		ContentType: "application/json",
	}, providers.PutOptions{ContentType: "application/json"}); err != nil {
		return fail("put value: " + err.Error())
	}
	// Zero the merged bundle too — it carries every value we just
	// fetched, JSON-encoded.
	client.Zero(merged)

	return client.JobOutcome{Status: client.StatusSucceeded}
}

// patchPayload is the typed view of the JSON the api enqueues into
// the job's payload column. Mirrors RequestService.enqueuePatchJob in
// the api repo — keep the field names in lockstep with that source.
type patchPayload struct {
	RequestID            string         `json:"request_id"`
	TargetProviderType   string         `json:"target_provider_type"`
	TargetProviderConfig map[string]any `json:"target_provider_config"`
	TargetSecretRef      string         `json:"target_secret_ref"`
	TargetKeys           []string       `json:"target_keys"`
	Wraps                []wrapRef      `json:"wraps"`
}

type wrapRef struct {
	WrapID  string `json:"wrap_id"`
	KeyName string `json:"key_name"`
}

func parsePatchPayload(raw map[string]any) (*patchPayload, error) {
	// Round-trip through JSON so we get proper type coercion (Fiber's
	// JSON decoder lands everything as map[string]any with float64
	// numbers, []any arrays — easier to just re-decode into a typed
	// struct than write a hand-rolled type switch).
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	var p patchPayload
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	if p.TargetProviderType == "" {
		return nil, errors.New("target_provider_type required")
	}
	if p.TargetSecretRef == "" {
		return nil, errors.New("target_secret_ref required")
	}
	if len(p.Wraps) == 0 {
		return nil, errors.New("wraps array empty")
	}
	for i, w := range p.Wraps {
		if w.WrapID == "" {
			return nil, fmt.Errorf("wraps[%d].wrap_id empty", i)
		}
	}
	return &p, nil
}

// readExistingBundle reads the current bundle from the provider and
// unmarshals it as JSON map[string]string. Missing-bundle is treated
// as an empty map (the first write to a path is a valid patch).
//
// Note: GetValue may return JSON whose values are nested objects /
// arrays. We coerce everything to string for the merge so the
// downstream Marshal is well-defined. Providers that need richer
// types can override this by re-encoding before PutValue — for now
// flat string maps cover the patch flow's usage.
func readExistingBundle(ctx context.Context, p providers.Provider, ref providers.SecretRef) (map[string]string, error) {
	v, err := p.GetValue(ctx, ref)
	if err != nil {
		if errors.Is(err, providers.ErrNotFound) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	defer client.Zero(v.Bytes)

	var raw map[string]any
	if err := json.Unmarshal(v.Bytes, &raw); err != nil {
		// Non-JSON existing bundle — treat as opaque and overwrite.
		// Providers that store a raw blob (not a kv map) get a fresh
		// JSON bundle written. Acceptable; the patch flow's contract
		// is that target_secret_ref points at a kv-style secret.
		return map[string]string{}, nil
	}
	out := make(map[string]string, len(raw))
	for k, val := range raw {
		switch t := val.(type) {
		case string:
			out[k] = t
		default:
			// Best-effort stringify so the merge is well-defined.
			b, _ := json.Marshal(t)
			out[k] = string(b)
		}
	}
	return out, nil
}

func fail(msg string) client.JobOutcome {
	return client.JobOutcome{Status: client.StatusFailed, Error: msg}
}
