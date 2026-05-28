package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Wrap is the agent's view of a CP wrap retrieval. Plaintext is the
// decoded value bytes — the agent MUST NOT log it, MUST zero it after
// use, and MUST NOT include it in error returns.
//
// ContentHash is the hex SHA-256 of the plaintext as reported by the
// CP. The agent should hash its decoded bytes locally and compare
// before writing to the provider — a mismatch means corruption in
// flight and the agent should fail the job rather than ship the wrong
// value.
type Wrap struct {
	WrapID      string
	RequestID   string
	KeyName     string
	Plaintext   []byte
	ByteLength  int
	ContentHash string
	Algorithm   string
}

// ErrWrapGone maps the CP's 410 — wrap was already consumed or has
// expired. Either way the wrap is unrecoverable.
var ErrWrapGone = errors.New("client: wrap is gone (already consumed or expired)")

// ErrRequestNotApproved maps the CP's 409 on this endpoint —
// the wrap exists but the owning request isn't approved yet. Surfaced
// separately so the agent can treat it as transient (retryable) where
// 410 is terminal.
var ErrRequestNotApproved = errors.New("client: wrap's owning request is not approved")

// ErrContentHashMismatch is returned when the locally computed hash
// of the decoded plaintext does not match the value the CP reported.
// Means corruption in flight; never ship the value to a provider.
var ErrContentHashMismatch = errors.New("client: content_hash mismatch — refusing to use plaintext")

// wrapResponse mirrors the WrapPayload JSON shape from
// internal/handlers/wraps.go in the api repo.
type wrapResponse struct {
	WrapID      string `json:"wrap_id"`
	RequestID   string `json:"request_id,omitempty"`
	KeyName     string `json:"key_name,omitempty"`
	Value       string `json:"value"`
	ByteLength  int    `json:"byte_length"`
	ContentHash string `json:"content_hash"`
	Algorithm   string `json:"algorithm"`
}

// GetWrap calls GET /api/v1/agents/:id/wraps/:wrap_id, decodes the
// base64 value, and verifies the content_hash. Caller MUST zero
// the returned Plaintext slice when done.
func (c *Client) GetWrap(ctx context.Context, agentID, agentSecret, wrapID string) (*Wrap, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.base+"/api/v1/agents/"+agentID+"/wraps/"+wrapID, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("client: build get-wrap request: %w", err)
	}
	req.Header.Set("X-Agent-Secret", agentSecret)
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: get-wrap: %w", err)
	}
	defer drainAndClose(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		// fall through to decode
	case http.StatusUnauthorized:
		return nil, ErrUnauthorized
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusGone:
		return nil, ErrWrapGone
	case http.StatusConflict:
		return nil, ErrRequestNotApproved
	default:
		return nil, &HTTPError{Status: resp.StatusCode, Body: readSnippet(resp.Body)}
	}

	var body wrapResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("client: decode wrap: %w", err)
	}
	pt, err := base64.StdEncoding.DecodeString(body.Value)
	if err != nil {
		return nil, fmt.Errorf("client: decode wrap value: %w", err)
	}
	// Integrity check before returning — defense against a flipped
	// byte in TLS-terminated proxies (or, more practically, an
	// implementation bug on the CP side that we want to fail loud).
	got := sha256.Sum256(pt)
	if hex.EncodeToString(got[:]) != body.ContentHash {
		// Zero before bailing so the bad bytes don't sit on the heap.
		Zero(pt)
		return nil, ErrContentHashMismatch
	}
	return &Wrap{
		WrapID:      body.WrapID,
		RequestID:   body.RequestID,
		KeyName:     body.KeyName,
		Plaintext:   pt,
		ByteLength:  body.ByteLength,
		ContentHash: body.ContentHash,
		Algorithm:   body.Algorithm,
	}, nil
}

// Zero overwrites b in place. Best-effort defense against casual
// post-use inspection of the heap.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
