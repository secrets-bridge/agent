// Package executor — read.go: the ReadExecutor.
//
// ReadExecutor turns a claimed `read`-type job into one wrap per
// requested key on the CP. Flow:
//
//  1. Parse payload to extract request_id + target provider info +
//     target_keys (which keys the requester wants to see).
//  2. Resolve provider via the same ResolverByType that backs the
//     patch + discover flows.
//  3. provider.GetValue(ref) → SecretValue (JSON-encoded bundle).
//  4. Unmarshal the bundle into map[string]any. If target_keys is
//     empty, the agent sends one wrap per key in the bundle; if
//     non-empty, only the requested keys (skipping any that are
//     missing — the audit trail captures the omission).
//  5. For each selected key: client.PostWrap(...) encrypts the value
//     locally under a fresh CP-issued DEK and posts only the envelope
//     (Piece 8b). There is no plaintext-over-TLS path (AGT-02).
//  6. Plaintext is zeroed promptly after each POST.
//  7. Mark job complete (the existing claim/complete loop handles
//     this around the executor — Execute just returns succeeded /
//     failed).
//
// Hard rules:
//   - Plaintext never logged
//   - Plaintext zeroed after every PostWrap (including failures)
//   - Failure messages name the request_id + key_name + count, never
//     the value bytes
//   - GetValue → PostWrap is the value's only path through the agent;
//     it never lands on disk, never enters a queue, never crosses a
//     goroutine boundary other than the executor's
package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/core/providers"
)

// PostWrapClient is the slice of *client.Client the ReadExecutor
// needs. Defined here so unit tests can swap in a fake. PostWrap always
// sends the wire envelope (DEK from /dek, AES-GCM locally); it has no
// plaintext mode.
type PostWrapClient interface {
	PostWrap(ctx context.Context, agentID, agentSecret, requestID, keyName string, plaintext []byte) (*client.PostWrapResponse, error)
}

// ReadExecutor implements Executor for job_type=read jobs.
//
// AgentPublicKey/AgentPrivateKey are the keypair the agent registered with
// the CP. Main only wires them after registration succeeded, so an empty
// keypair means sealing is not active and the executor refuses the job
// instead of moving a value (AGT-02).
type ReadExecutor struct {
	AgentID         string
	AgentSecret     string
	AgentPublicKey  []byte
	AgentPrivateKey []byte
	Client          PostWrapClient
	ResolveProvider ProviderResolver
}

// Execute runs one read job to completion.
func (r ReadExecutor) Execute(ctx context.Context, job *client.Job) client.JobOutcome {
	payload, err := parseReadPayload(job.Payload)
	if err != nil {
		return fail("payload: " + err.Error())
	}
	if !sealingReady(r.AgentPublicKey, r.AgentPrivateKey) {
		return fail(errSealingNotActive)
	}
	if err := checkSecretRef(payload.TargetProviderType, payload.TargetSecretRef); err != nil {
		return fail("payload: " + err.Error())
	}

	provider, err := r.ResolveProvider(payload.TargetProviderType, payload.TargetProviderConfig)
	if err != nil {
		return fail("resolve provider: " + err.Error())
	}

	ref := providers.SecretRef{
		Provider: payload.TargetProviderType,
		Name:     payload.TargetSecretRef,
	}
	val, err := provider.GetValue(ctx, ref)
	if err != nil {
		return fail("get value: " + err.Error())
	}
	// Zero the raw bundle bytes after we've parsed them. We hold the
	// JSON-decoded map[string]any which carries the values too — it
	// gets zeroed key-by-key as we POST each wrap.
	defer client.Zero(val.Bytes)

	var bundle map[string]any
	if err := json.Unmarshal(val.Bytes, &bundle); err != nil {
		// Non-JSON value: treat the whole thing as one entry under
		// key "value". This matches Vault's PutValue convention
		// (raw blobs get wrapped as {"value": "<raw>"}) and gives the
		// requester a single wrap to retrieve.
		bundle = map[string]any{"value": string(val.Bytes)}
	}

	// Decide which keys to publish. Empty TargetKeys = "all of them".
	wantKeys := payload.TargetKeys
	if len(wantKeys) == 0 {
		wantKeys = make([]string, 0, len(bundle))
		for k := range bundle {
			wantKeys = append(wantKeys, k)
		}
	}

	// Count missing keys up front (key names only, no values) so a
	// failure reports complete counts.
	total := len(wantKeys)
	missing := 0
	for _, key := range wantKeys {
		if _, ok := bundle[key]; !ok {
			missing++
		}
	}

	// One failing key fails the whole job: a reveal that silently
	// leaves out keys would mislead the requester. Empty values are
	// not special: they are sealed and posted like any other value.
	posted := 0
	for _, key := range wantKeys {
		raw, ok := bundle[key]
		if !ok {
			continue
		}
		plain := bytesFromBundleValue(raw)
		_, err := r.Client.PostWrap(ctx, r.AgentID, r.AgentSecret,
			payload.RequestID, key, plain)
		if err != nil {
			reason := redactValue(err.Error(), plain)
			client.Zero(plain)
			out := fail(fmt.Sprintf("post wrap key=%q failed (after %d posted, %d missing, %d total): %s",
				key, posted, missing, total, reason))
			out.LogAttrs = readCounts(key, posted, missing, total)
			return out
		}
		client.Zero(plain)
		posted++
	}

	if posted == 0 && total > 0 {
		// Asked for specific keys, none present in the bundle. That's
		// a failure from the requester's perspective: they expected
		// values and got none.
		out := fail(fmt.Sprintf("none of the requested keys exist in bundle (asked %d, missing %d)",
			total, missing))
		out.LogAttrs = readCounts("", posted, missing, total)
		return out
	}
	return client.JobOutcome{Status: client.StatusSucceeded}
}

// readCounts is the local-only log context of a failed read: the key
// that failed (if any) and the counts. Key names and integers only.
func readCounts(key string, posted, missing, total int) []slog.Attr {
	attrs := make([]slog.Attr, 0, 4)
	if key != "" {
		attrs = append(attrs, slog.String("key", key))
	}
	return append(attrs,
		slog.Int("posted", posted),
		slog.Int("missing", missing),
		slog.Int("total", total))
}

// minRedactLen is the shortest value redactValue scrubs. Shorter values
// would match ordinary words in the error text and mangle it.
const minRedactLen = 4

// redactValue removes the value of the failing key from an error text
// before it is logged or sent to the CP. The agent posts only
// ciphertext, so the CP should never echo the value; this is a
// backstop in case an error body does, raw or JSON-escaped.
func redactValue(msg string, value []byte) string {
	if len(value) < minRedactLen {
		return msg
	}
	msg = strings.ReplaceAll(msg, string(value), "[redacted]")
	if esc, err := json.Marshal(string(value)); err == nil && len(esc) > 2 {
		msg = strings.ReplaceAll(msg, string(esc[1:len(esc)-1]), "[redacted]")
	}
	return msg
}

// readPayload is the typed view of the JSON in a read job's payload.
// Mirrors the shape RequestService.enqueueRequestJob emits in the
// api repo for read requests.
type readPayload struct {
	RequestID            string         `json:"request_id"`
	TargetProviderType   string         `json:"target_provider_type"`
	TargetProviderConfig map[string]any `json:"target_provider_config"`
	TargetSecretRef      string         `json:"target_secret_ref"`
	TargetKeys           []string       `json:"target_keys"`
}

func parseReadPayload(raw map[string]any) (*readPayload, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	var p readPayload
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	if p.RequestID == "" {
		return nil, errors.New("request_id required")
	}
	if p.TargetProviderType == "" {
		return nil, errors.New("target_provider_type required")
	}
	if p.TargetSecretRef == "" {
		return nil, errors.New("target_secret_ref required")
	}
	return &p, nil
}

// bytesFromBundleValue stringifies a JSON value into the byte
// representation we ship to the CP. Strings round-trip as-is;
// non-string values get JSON-encoded so the wrap carries something
// well-defined.
//
// Returns a FRESH slice (caller will zero it) — no aliasing with the
// caller's bundle map.
func bytesFromBundleValue(v any) []byte {
	if s, ok := v.(string); ok {
		return []byte(s)
	}
	b, _ := json.Marshal(v)
	return b
}
