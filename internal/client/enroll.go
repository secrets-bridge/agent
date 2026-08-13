package client

// Agent-side of the enrollment contract (api-1). On first boot the agent
// exchanges a one-time enrollment token for its persistent credential:
//
//	POST /api/v1/agents/enroll
//	  body: { enrollment_token, agent_name, provider_type, cluster_name,
//	          agent_version, region }
//	  201:  { agent_id, provider_connection_id, agent_token,
//	          heartbeat_interval_seconds, job_poll_interval_seconds }
//
// The endpoint is token-only (session-exempt on the CP): the token travels
// in the BODY, never a header. The returned agent_token is the persistent
// X-Agent-Secret and is returned exactly ONCE.
//
// Redaction: this file never logs, prints, or wraps the enrollment token or
// the returned agent_token into an error. Rejections surface only the CP's
// safe error CODE (e.g. "enrollment_token_invalid"), never the token.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// ErrEnrollmentRejected is a PERMANENT enrollment failure (HTTP 4xx): the
// token is invalid, expired, already consumed, revoked, or the
// provider/cluster does not match the token's binding. Retrying with the
// same token will not succeed — the agent should fail loudly rather than
// spin. Reason carries the CP's safe error code (no token material).
type ErrEnrollmentRejected struct {
	Status int
	Reason string // CP error code, e.g. "enrollment_token_invalid"
}

func (e *ErrEnrollmentRejected) Error() string {
	return fmt.Sprintf("client: enrollment rejected (%d): %s", e.Status, e.Reason)
}

// EnrollRequest is the body POSTed to /agents/enroll. It carries the
// one-time token plus the agent's self-described identity metadata.
type EnrollRequest struct {
	EnrollmentToken string   `json:"enrollment_token"`
	AgentName       string   `json:"agent_name"`
	ProviderType    string   `json:"provider_type,omitempty"`
	ClusterName     string   `json:"cluster_name,omitempty"`
	AgentVersion    string   `json:"agent_version,omitempty"`
	Region          string   `json:"region,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
}

// EnrollResult is the parsed 201 response. AgentToken is the persistent
// credential — the caller must persist it safely and MUST NOT log it.
type EnrollResult struct {
	AgentID                  string `json:"agent_id"`
	ProviderConnectionID     string `json:"provider_connection_id"`
	AgentToken               string `json:"agent_token"`
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
	JobPollIntervalSeconds   int    `json:"job_poll_interval_seconds"`
}

// enrollErrorBody is the CP's metadata-only rejection shape ({"error":...}).
type enrollErrorBody struct {
	Error string `json:"error"`
}

// Enroll exchanges a one-time enrollment token for a persistent credential.
//
// On a 4xx rejection it returns *ErrEnrollmentRejected (permanent). On a
// transient failure (5xx / network) it returns a generic error the caller
// may retry. The enrollment token is never included in any returned error.
func (c *Client) Enroll(ctx context.Context, in EnrollRequest) (*EnrollResult, error) {
	payload, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("client: marshal enroll request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/api/v1/agents/enroll", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("client: build enroll request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		// Redaction: %w here wraps a transport error, never the request
		// body — the token is not part of the error surface.
		return nil, fmt.Errorf("client: enroll: %w", err)
	}
	defer drainAndClose(resp.Body)

	switch {
	case resp.StatusCode == http.StatusCreated:
		var out EnrollResult
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return nil, fmt.Errorf("client: decode enroll response: %w", err)
		}
		if out.AgentID == "" || out.AgentToken == "" {
			return nil, errors.New("client: enroll response missing agent_id or agent_token")
		}
		return &out, nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// Permanent rejection. Surface only the safe error code.
		return nil, &ErrEnrollmentRejected{Status: resp.StatusCode, Reason: enrollReason(resp.Body)}
	default:
		// Transient (5xx) or unexpected — retryable. Body is the CP's
		// metadata-only error, safe to snippet.
		return nil, &HTTPError{Status: resp.StatusCode, Body: readSnippet(resp.Body)}
	}
}

// enrollReason extracts the CP's {"error":"<code>"} value. Falls back to a
// generic label so a malformed body never blocks the caller — and never
// echoes anything token-shaped.
func enrollReason(r io.Reader) string {
	var body enrollErrorBody
	if err := json.NewDecoder(r).Decode(&body); err == nil && body.Error != "" {
		return body.Error
	}
	return "enrollment_rejected"
}
