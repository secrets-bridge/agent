// Package client is the typed HTTP client for the Secrets Bridge
// Control Plane API. It exposes ONLY the surface the agent uses:
// heartbeat today, job claim/complete in #2.
//
// Hard rule: this package depends on stdlib net/http only. No
// fiber/v3 (server-side framework), no go-redis, no pgx. The agent
// must stay trivially deployable inside customer boundaries.
package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ErrUnauthorized maps the CP's 401 response. A heartbeat that returns
// this is fatal — the identity has been revoked or the credential is
// wrong, and the agent must abort the loop rather than spin.
var ErrUnauthorized = errors.New("client: unauthorized")

// ErrNotFound maps the CP's 404 response.
var ErrNotFound = errors.New("client: not found")

// Client is a thin HTTP client over the CP API.
type Client struct {
	base string
	hc   *http.Client
}

// New constructs a Client bound to the given Control Plane base URL.
func New(base string) *Client {
	return &Client{
		base: base,
		hc:   &http.Client{Timeout: 30 * time.Second},
	}
}

// WithHTTPClient swaps the underlying http.Client. Useful for tests
// that inject httptest.Server transport or custom TLS config.
func (c *Client) WithHTTPClient(hc *http.Client) *Client {
	c.hc = hc
	return c
}

// Heartbeat tells the CP this agent is alive. Returns ErrUnauthorized
// when the identity has been revoked or the secret is rejected.
func (c *Client) Heartbeat(ctx context.Context, agentID, agentSecret string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/api/v1/agents/"+agentID+"/heartbeat", http.NoBody)
	if err != nil {
		return fmt.Errorf("client: build heartbeat request: %w", err)
	}
	req.Header.Set("X-Agent-Secret", agentSecret)

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("client: heartbeat: %w", err)
	}
	defer drainAndClose(resp.Body)

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusNotFound:
		return ErrNotFound
	default:
		return &HTTPError{Status: resp.StatusCode, Body: readSnippet(resp.Body)}
	}
}

// HTTPError is returned for unexpected (non-401/404) statuses.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("client: http %d: %s", e.Status, e.Body)
}

func drainAndClose(rc io.ReadCloser) {
	_, _ = io.Copy(io.Discard, rc)
	_ = rc.Close()
}

func readSnippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 512))
	return string(bytes.TrimSpace(b))
}
