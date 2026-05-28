package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SecretBulkItem is one entry in a discovery batch. Mirrors the
// internal/handlers/secrets.go BulkUpsertItem JSON shape in the api
// repo — keep the field names in lockstep.
//
// IMPORTANT: this struct carries NO secret value. Discovery only
// flows metadata (ref + labels + version + checksum). The CP refuses
// (and the schema doesn't have a column for) any value bytes.
type SecretBulkItem struct {
	SecretRef       string         `json:"secret_ref"`
	Labels          map[string]any `json:"labels,omitempty"`
	Version         string         `json:"version,omitempty"`
	Checksum        string         `json:"checksum,omitempty"`
	CreatedAtSource *time.Time     `json:"created_at_source,omitempty"`
	UpdatedAtSource *time.Time     `json:"updated_at_source,omitempty"`
}

// SecretBulkRequest is the JSON the agent POSTs.
type SecretBulkRequest struct {
	ClusterName    string           `json:"cluster_name"`
	ProviderType   string           `json:"provider_type"`
	ProviderConfig map[string]any   `json:"provider_config,omitempty"`
	Items          []SecretBulkItem `json:"items"`
}

// SecretBulkResponse is what the CP returns.
type SecretBulkResponse struct {
	UpsertedIDs []string `json:"upserted_ids"`
	Count       int      `json:"count"`
}

// PostSecretsBulk uploads a discovery batch to the CP.
//
// Chunking strategy: callers compose batches of arbitrary size. The
// CP's per-row upsert is cheap (single INSERT … ON CONFLICT) so a
// few-thousand-row batch is fine over a single HTTP POST.
// For very large clusters consider splitting in the caller.
func (c *Client) PostSecretsBulk(ctx context.Context, agentID, agentSecret string, body SecretBulkRequest) (*SecretBulkResponse, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("client: marshal secrets bulk: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/api/v1/agents/"+agentID+"/secrets/bulk", bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("client: build secrets bulk request: %w", err)
	}
	req.Header.Set("X-Agent-Secret", agentSecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: secrets bulk: %w", err)
	}
	defer drainAndClose(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		var out SecretBulkResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return nil, fmt.Errorf("client: decode secrets bulk response: %w", err)
		}
		return &out, nil
	case http.StatusUnauthorized:
		return nil, ErrUnauthorized
	case http.StatusNotFound:
		return nil, ErrNotFound
	default:
		return nil, &HTTPError{Status: resp.StatusCode, Body: readSnippet(resp.Body)}
	}
}
