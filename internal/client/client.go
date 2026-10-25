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
	"encoding/json"
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

// ErrKeyMismatch maps the CP's 409 {"error":"agent_key_mismatch"}: the
// X-Agent-Key-Fingerprint the agent sent is not the key the CP has bound
// to it (the key was rotated, or the agent runs with the wrong Secret).
// It is fatal; the agent must be restarted with the current credentials.
var ErrKeyMismatch = errors.New("client: agent_key_mismatch: this agent's private key is not the key bound on the control plane")

// headerKeyFingerprint carries the agent's public key fingerprint on every
// request under /agents/:id/*.
const headerKeyFingerprint = "X-Agent-Key-Fingerprint"

// Client is a thin HTTP client over the CP API.
type Client struct {
	base        string
	hc          *http.Client
	fingerprint string
}

// New constructs a Client bound to the given Control Plane base URL.
// The client never follows redirects (AGT-N-02).
func New(base string) *Client {
	return &Client{
		base: base,
		hc:   &http.Client{Timeout: 30 * time.Second, CheckRedirect: refuseRedirect},
	}
}

// WithHTTPClient swaps the underlying http.Client (custom TLS, or an
// httptest transport in tests). The Client keeps its own shallow copy with
// the no-redirect policy forced on, so a caller-supplied client that would
// follow redirects can't leak X-Agent-Secret to another host (AGT-N-02).
func (c *Client) WithHTTPClient(hc *http.Client) *Client {
	cp := *hc
	cp.CheckRedirect = refuseRedirect
	c.hc = &cp
	return c
}

// WithKeyFingerprint sets the public key fingerprint sent in
// X-Agent-Key-Fingerprint on every agent-authenticated request.
func (c *Client) WithKeyFingerprint(fp string) *Client {
	c.fingerprint = fp
	return c
}

// doAgent sends an agent-authenticated request: it sets X-Agent-Secret and
// X-Agent-Key-Fingerprint, and turns a 409 agent_key_mismatch into
// ErrKeyMismatch. Any other 409 is handed back with its body intact so the
// caller can map it (claim lost, request not approved).
func (c *Client) doAgent(req *http.Request, agentSecret string) (*http.Response, error) {
	req.Header.Set("X-Agent-Secret", agentSecret)
	if c.fingerprint != "" {
		req.Header.Set(headerKeyFingerprint, c.fingerprint)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusConflict {
		return resp, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxSmallResponse))
	_ = resp.Body.Close()
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error == "agent_key_mismatch" {
		return nil, ErrKeyMismatch
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

// HeartbeatReport is the OPTIONAL runtime body an agent may send on a
// heartbeat (api-2). Capabilities lists the job types the agent executes. When nil, the agent sends a bodyless heartbeat and the
// CP replies 204 (the legacy contract, unchanged). When non-nil, the CP
// records the fields and replies 200 with a HeartbeatResult. It carries NO
// credential material — the X-Agent-Secret stays in the header.
type HeartbeatReport struct {
	Status       string   `json:"status,omitempty"`
	AgentVersion string   `json:"agent_version,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// HeartbeatResult is the parsed 200 response for a heartbeat that carried a
// body. NextHeartbeatSeconds is the CP's suggested cadence (0 when the CP
// replied 204 or omitted it — the caller then falls back to its configured
// interval).
type HeartbeatResult struct {
	NextHeartbeatSeconds int `json:"next_heartbeat_seconds"`
}

// Heartbeat tells the CP this agent is alive. Returns ErrUnauthorized when
// the identity has been revoked or the secret is rejected.
//
// report == nil  → bodyless request → 204 → HeartbeatResult{} (Next 0).
// report != nil  → JSON body        → 200 → parsed HeartbeatResult.
func (c *Client) Heartbeat(ctx context.Context, agentID, agentSecret string, report *HeartbeatReport) (*HeartbeatResult, error) {
	var body io.Reader = http.NoBody
	if report != nil {
		payload, err := json.Marshal(report)
		if err != nil {
			return nil, fmt.Errorf("client: marshal heartbeat body: %w", err)
		}
		body = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/api/v1/agents/"+agentID+"/heartbeat", body)
	if err != nil {
		return nil, fmt.Errorf("client: build heartbeat request: %w", err)
	}
	if report != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.doAgent(req, agentSecret)
	if err != nil {
		return nil, fmt.Errorf("client: heartbeat: %w", err)
	}
	defer drainAndClose(resp.Body)

	switch resp.StatusCode {
	case http.StatusNoContent:
		return &HeartbeatResult{}, nil
	case http.StatusOK:
		var out HeartbeatResult
		// A 200 always carries the richer body; a decode failure (or an
		// oversized body) is non-fatal — treat it as "no suggested cadence".
		if err := decodeJSON(resp.Body, maxSmallResponse, &out); err != nil {
			return &HeartbeatResult{}, nil
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

// HTTPError is returned for unexpected (non-401/404) statuses.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	if e.Status >= 300 && e.Status < 400 {
		// The agent never follows redirects (AGT-N-02); a 3xx from the
		// CP is a misconfiguration or an attempt to move the agent's
		// credential somewhere else.
		return fmt.Sprintf("client: http %d: redirect refused", e.Status)
	}
	return fmt.Sprintf("client: http %d: %s", e.Status, e.Body)
}

// drainAndClose consumes a bounded amount of the body so the connection
// can be reused, then closes it. A body longer than maxDrain just costs
// the connection.
func drainAndClose(rc io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, maxDrain))
	_ = rc.Close()
}

func readSnippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 512))
	return string(bytes.TrimSpace(b))
}
