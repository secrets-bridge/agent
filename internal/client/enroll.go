package client

// Operator-side enrollment and key rotation (schema_version "2").
//
// Enrollment is two steps with proof of possession of the wire key:
//
//	POST /api/v1/agents/enroll/challenge
//	  { schema_version, enrollment_token, public_key, public_key_algorithm }
//	  200 { challenge_id, sealed_challenge, expires_at }
//	POST /api/v1/agents/enroll
//	  { schema_version, enrollment_token, challenge_id, challenge_response,
//	    name, cluster_name, provider_type, region }
//	  201 { agent_id, agent_secret, public_key_fingerprint,
//	        public_key_version, heartbeat_interval_seconds,
//	        claim_interval_seconds }
//
// Key rotation runs the same challenge against the agent's current
// credential and a one-time rotation token:
//
//	POST /api/v1/agents/:id/key-rotation/challenge
//	POST /api/v1/agents/:id/key-rotation
//
// Only the CLI subcommands call these. The token, the challenge plaintext
// and the returned agent secret travel as Secret byte slices so the
// caller can zero them; none of them appear in an error.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/secrets-bridge/agent/internal/sealing"
)

// SchemaVersion is the only enrollment schema the CP accepts.
const SchemaVersion = "2"

// Secret is a byte slice that encodes as a JSON string. It lets a token
// or credential go through encoding/json without becoming an immutable Go
// string, so the caller can Zero it after use.
type Secret []byte

// MarshalJSON writes s as a JSON string.
func (s Secret) MarshalJSON() ([]byte, error) {
	// Encoding through a string would leave an immutable copy on the heap.
	// The values are base64 or UUID text, so quoting is enough; anything
	// that would need escaping is refused.
	for _, b := range s {
		if b < 0x20 || b == '"' || b == '\\' || b >= 0x7f {
			return nil, errors.New("client: secret contains a byte that needs JSON escaping")
		}
	}
	out := make([]byte, 0, len(s)+2)
	out = append(out, '"')
	out = append(out, s...)
	out = append(out, '"')
	return out, nil
}

// UnmarshalJSON reads a JSON string without escapes into s.
func (s *Secret) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("client: secret is not a JSON string")
	}
	inner := data[1 : len(data)-1]
	if bytes.IndexByte(inner, '\\') >= 0 {
		return errors.New("client: secret contains a JSON escape")
	}
	*s = append((*s)[:0], inner...)
	return nil
}

// Zero overwrites the secret in place.
func (s Secret) Zero() { Zero(s) }

// ErrEnrollmentRejected is a permanent enroll or rotation failure (HTTP
// 4xx): enrollment_rejected, invalid_public_key,
// unsupported_schema_version, or rate limiting. Reason is the CP's error
// code, never token material.
type ErrEnrollmentRejected struct {
	Status int
	Reason string
}

func (e *ErrEnrollmentRejected) Error() string {
	return fmt.Sprintf("client: rejected by the control plane (%d): %s", e.Status, e.Reason)
}

// Challenge is the CP's sealed proof-of-possession challenge.
type Challenge struct {
	ChallengeID string
	Sealed      *sealing.Envelope
	ExpiresAt   string
}

type challengeRequest struct {
	SchemaVersion      string `json:"schema_version"`
	EnrollmentToken    Secret `json:"enrollment_token,omitempty"`
	RotationToken      Secret `json:"rotation_token,omitempty"`
	PublicKey          string `json:"public_key"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
}

type challengeResponse struct {
	ChallengeID     string                `json:"challenge_id"`
	SealedChallenge *sealedEnvelopeOnWire `json:"sealed_challenge"`
	ExpiresAt       string                `json:"expires_at"`
}

// EnrollRequest is the body of POST /agents/enroll.
type EnrollRequest struct {
	SchemaVersion     string `json:"schema_version"`
	EnrollmentToken   Secret `json:"enrollment_token"`
	ChallengeID       string `json:"challenge_id"`
	ChallengeResponse Secret `json:"challenge_response"`
	Name              string `json:"name"`
	ClusterName       string `json:"cluster_name,omitempty"`
	ProviderType      string `json:"provider_type,omitempty"`
	Region            string `json:"region,omitempty"`
}

// EnrollResult is the 201 body. AgentSecret is returned only this once;
// the caller hands it to the operator and zeroes it.
type EnrollResult struct {
	AgentID                  string `json:"agent_id"`
	AgentSecret              Secret `json:"agent_secret"`
	PublicKeyFingerprint     string `json:"public_key_fingerprint"`
	PublicKeyVersion         int    `json:"public_key_version"`
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
	ClaimIntervalSeconds     int    `json:"claim_interval_seconds"`
}

// RotateKeyRequest is the body of POST /agents/:id/key-rotation.
type RotateKeyRequest struct {
	SchemaVersion     string `json:"schema_version"`
	RotationToken     Secret `json:"rotation_token"`
	ChallengeID       string `json:"challenge_id"`
	ChallengeResponse Secret `json:"challenge_response"`
}

// RotateKeyResult is the success body of POST /agents/:id/key-rotation.
type RotateKeyResult struct {
	AgentID              string `json:"agent_id"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	PublicKeyVersion     int    `json:"public_key_version"`
}

// EnrollChallenge asks the CP for a challenge sealed to pub.
func (c *Client) EnrollChallenge(ctx context.Context, token Secret, pub []byte) (*Challenge, error) {
	body := challengeRequest{
		SchemaVersion:      SchemaVersion,
		EnrollmentToken:    token,
		PublicKey:          base64.StdEncoding.EncodeToString(pub),
		PublicKeyAlgorithm: sealing.PublicKeyAlgorithm,
	}
	var out challengeResponse
	if err := c.postEnrollment(ctx, "/api/v1/agents/enroll/challenge", "", body, &out, http.StatusOK); err != nil {
		return nil, err
	}
	return out.toChallenge()
}

// Enroll completes enrollment with the opened challenge.
func (c *Client) Enroll(ctx context.Context, in EnrollRequest) (*EnrollResult, error) {
	in.SchemaVersion = SchemaVersion
	var out EnrollResult
	if err := c.postEnrollment(ctx, "/api/v1/agents/enroll", "", in, &out, http.StatusCreated); err != nil {
		return nil, err
	}
	if out.AgentID == "" || len(out.AgentSecret) == 0 || out.PublicKeyFingerprint == "" {
		out.AgentSecret.Zero()
		return nil, errors.New("client: enroll response is missing agent_id, agent_secret or public_key_fingerprint")
	}
	return &out, nil
}

// KeyRotationChallenge asks the CP for a challenge sealed to the new key.
// It authenticates with the agent's current secret.
func (c *Client) KeyRotationChallenge(ctx context.Context, agentID, agentSecret string, token Secret, newPub []byte) (*Challenge, error) {
	body := challengeRequest{
		SchemaVersion:      SchemaVersion,
		RotationToken:      token,
		PublicKey:          base64.StdEncoding.EncodeToString(newPub),
		PublicKeyAlgorithm: sealing.PublicKeyAlgorithm,
	}
	var out challengeResponse
	if err := c.postEnrollment(ctx, "/api/v1/agents/"+agentID+"/key-rotation/challenge", agentSecret, body, &out, http.StatusOK); err != nil {
		return nil, err
	}
	return out.toChallenge()
}

// RotateKey completes the rotation with the opened challenge.
func (c *Client) RotateKey(ctx context.Context, agentID, agentSecret string, in RotateKeyRequest) (*RotateKeyResult, error) {
	in.SchemaVersion = SchemaVersion
	var out RotateKeyResult
	if err := c.postEnrollment(ctx, "/api/v1/agents/"+agentID+"/key-rotation", agentSecret, in, &out, http.StatusOK, http.StatusCreated); err != nil {
		return nil, err
	}
	if out.PublicKeyFingerprint == "" {
		return nil, errors.New("client: rotation response is missing public_key_fingerprint")
	}
	return &out, nil
}

// postEnrollment POSTs body and decodes the response into out when the
// status is one of ok. With an agentSecret it is an agent-authenticated
// call; without one it is token-only. The request buffer is zeroed after
// the call because it holds a token.
func (c *Client) postEnrollment(ctx context.Context, path, agentSecret string, body, out any, ok ...int) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return errors.New("client: marshal enrollment request")
	}
	defer Zero(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("client: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	var resp *http.Response
	if agentSecret != "" {
		resp, err = c.doAgent(req, agentSecret)
	} else {
		resp, err = c.hc.Do(req)
	}
	if err != nil {
		if errors.Is(err, ErrKeyMismatch) {
			return err
		}
		return fmt.Errorf("client: %s: %w", path, transportReason(err))
	}
	defer drainAndClose(resp.Body)

	for _, s := range ok {
		if resp.StatusCode == s {
			if err := decodeJSON(resp.Body, maxSmallResponse, out); err != nil {
				return fmt.Errorf("client: decode %s response: %w", path, err)
			}
			return nil
		}
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return &ErrEnrollmentRejected{Status: resp.StatusCode, Reason: "rate_limited"}
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return &ErrEnrollmentRejected{Status: resp.StatusCode, Reason: enrollReason(resp.Body)}
	default:
		return &HTTPError{Status: resp.StatusCode, Body: readSnippet(resp.Body)}
	}
}

// transportReason drops a *url.Error's URL from a transport error. The
// token is in the body, never the URL; this only keeps errors short.
func transportReason(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err
	}
	return err
}

func (r *challengeResponse) toChallenge() (*Challenge, error) {
	if r.ChallengeID == "" || r.SealedChallenge == nil {
		return nil, errors.New("client: challenge response is missing challenge_id or sealed_challenge")
	}
	env, err := r.SealedChallenge.decode()
	if err != nil {
		return nil, err
	}
	return &Challenge{ChallengeID: r.ChallengeID, Sealed: env, ExpiresAt: r.ExpiresAt}, nil
}

// decode turns the base64 wire envelope into a sealing.Envelope.
func (w *sealedEnvelopeOnWire) decode() (*sealing.Envelope, error) {
	ct, err := base64.StdEncoding.DecodeString(w.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("client: decode sealed ciphertext: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(w.Nonce)
	if err != nil {
		return nil, fmt.Errorf("client: decode sealed nonce: %w", err)
	}
	ephPub, err := base64.StdEncoding.DecodeString(w.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("client: decode sealed eph pub: %w", err)
	}
	return &sealing.Envelope{Algorithm: w.Algorithm, Ciphertext: ct, Nonce: nonce, EphemeralPublicKey: ephPub}, nil
}

// enrollReason extracts the CP's {"error":"<code>"} value, or a generic
// label when the body is not that shape.
func enrollReason(r io.Reader) string {
	var body struct {
		Error string `json:"error"`
	}
	if err := decodeJSON(r, maxSmallResponse, &body); err == nil && body.Error != "" && len(body.Error) <= 64 {
		return body.Error
	}
	return "enrollment_rejected"
}
