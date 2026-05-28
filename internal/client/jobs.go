package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ErrNoJobs maps the CP's 204 No Content response on the claim
// endpoint. The agent treats it as "queue empty; sleep and retry".
var ErrNoJobs = errors.New("client: no jobs in queue")

// Job is the agent's view of a claimed sync_job. Payload is opaque to
// the client layer; the executor interprets it per job type.
type Job struct {
	ID             string         `json:"id"`
	JobType        string         `json:"job_type"`
	Payload        map[string]any `json:"payload"`
	CorrelationID  string         `json:"correlation_id"`
	ClaimExpiresAt string         `json:"claim_expires_at"`
}

// JobOutcome is the body of the complete request. Status is one of
// "succeeded" / "failed"; Error carries operator-visible context on
// failure.
type JobOutcome struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

const (
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
)

// ClaimJob asks the CP for the next runnable job. Returns ErrNoJobs
// when the queue is empty.
func (c *Client) ClaimJob(ctx context.Context, agentID, agentSecret string) (*Job, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/api/v1/agents/"+agentID+"/jobs/claim", http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("client: build claim request: %w", err)
	}
	req.Header.Set("X-Agent-Secret", agentSecret)
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: claim: %w", err)
	}
	defer drainAndClose(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		var j Job
		if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
			return nil, fmt.Errorf("client: decode job: %w", err)
		}
		return &j, nil
	case http.StatusNoContent:
		return nil, ErrNoJobs
	case http.StatusUnauthorized:
		return nil, ErrUnauthorized
	case http.StatusNotFound:
		return nil, ErrNotFound
	default:
		return nil, &HTTPError{Status: resp.StatusCode, Body: readSnippet(resp.Body)}
	}
}

// CompleteJob reports the outcome of an executed job. Idempotent on
// the CP side — a duplicate call for an already-completed row returns
// 204 without error.
func (c *Client) CompleteJob(ctx context.Context, agentID, agentSecret, jobID string, outcome JobOutcome) error {
	body, err := json.Marshal(outcome)
	if err != nil {
		return fmt.Errorf("client: marshal outcome: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/api/v1/agents/"+agentID+"/jobs/"+jobID+"/complete",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("client: build complete request: %w", err)
	}
	req.Header.Set("X-Agent-Secret", agentSecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("client: complete: %w", err)
	}
	defer drainAndClose(resp.Body)

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusConflict:
		// 409 means the claim has rotated to a different agent. The
		// caller should abandon any side-effects and stop processing.
		return ErrClaimLost
	default:
		return &HTTPError{Status: resp.StatusCode, Body: readSnippet(resp.Body)}
	}
}

// ErrClaimLost maps 409 on Complete — another agent owns the row now,
// almost certainly because our lease expired. Caller must abandon
// any side-effects.
var ErrClaimLost = errors.New("client: claim lost (lease expired or stolen)")

// Parsed claim_expires_at as time.Time, with a zero value when the
// CP omitted it (which shouldn't happen for a successful claim but
// keeps the consumer robust).
func (j *Job) ClaimDeadline() time.Time {
	if j.ClaimExpiresAt == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, j.ClaimExpiresAt)
	if err != nil {
		return time.Time{}
	}
	return t
}
