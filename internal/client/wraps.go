package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/secrets-bridge/agent/internal/sealing"
)

// bytesReader is a small alias so PostWrap doesn't need to import
// bytes at the call site. Returns an io.Reader of the given bytes.
func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

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
// internal/handlers/wraps.go in the api repo. The agent only accepts the
// Sealed (wire-envelope, Piece 8b) shape; Value (legacy plaintext over
// TLS) is decoded only so a response carrying it can be refused.
type wrapResponse struct {
	WrapID      string                `json:"wrap_id"`
	RequestID   string                `json:"request_id,omitempty"`
	KeyName     string                `json:"key_name,omitempty"`
	Value       string                `json:"value,omitempty"`
	Sealed      *sealedEnvelopeOnWire `json:"sealed,omitempty"`
	ByteLength  int                   `json:"byte_length"`
	ContentHash string                `json:"content_hash"`
	Algorithm   string                `json:"algorithm"`
}

// sealedEnvelopeOnWire is the JSON shape of the wire-envelope as it
// arrives from the CP. All byte fields base64.
type sealedEnvelopeOnWire struct {
	Algorithm          string `json:"algorithm"`
	Ciphertext         string `json:"ciphertext"`
	Nonce              string `json:"nonce"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
}

// GetWrap calls GET /api/v1/agents/:id/wraps/:wrap_id and returns the
// opened plaintext + verified content_hash.
//
// Sealed only (AGT-02): agentPubKey + agentPrivKey (the agent's static
// X25519 keypair, registered with the CP at boot) are required, and the
// call is refused before any request is sent when they are missing, so a
// single-use wrap is never consumed by a caller that could only read it
// unsealed. The CP response must carry a `sealed` envelope; a plaintext
// `value` is refused as a downgrade whether or not it also carries a seal.
//
// Caller MUST zero the returned Plaintext slice when done.
func (c *Client) GetWrap(ctx context.Context, agentID, agentSecret, wrapID string, agentPubKey, agentPrivKey []byte) (*Wrap, error) {
	if len(agentPubKey) == 0 || len(agentPrivKey) == 0 {
		return nil, errors.New("client: no keypair; refusing to fetch a wrap that could only be read unsealed")
	}
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
	if err := decodeJSON(resp.Body, maxWrapResponse, &body); err != nil {
		return nil, fmt.Errorf("client: decode wrap: %w", err)
	}

	pt, err := decodeWrapValue(&body, agentPubKey, agentPrivKey)
	if err != nil {
		return nil, err
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

// decodeWrapValue opens the sealed envelope in a wrap response.
//
// There is no unsealed path (AGT-02). A plaintext `value` is refused
// whether it comes alone (a MITM or a misbehaving CP stripping the
// envelope) or next to a seal, and a caller without a keypair is refused
// too.
func decodeWrapValue(body *wrapResponse, agentPubKey, agentPrivKey []byte) ([]byte, error) {
	switch {
	case body.Sealed != nil && body.Value != "":
		return nil, errors.New("client: CP returned BOTH sealed and value — unexpected; refusing to choose")
	case body.Value != "":
		return nil, errors.New("client: CP returned an unsealed value; refusing silent downgrade to plaintext")
	case body.Sealed == nil:
		return nil, errors.New("client: CP response carries no sealed envelope")
	case len(agentPubKey) == 0 || len(agentPrivKey) == 0:
		return nil, errors.New("client: CP returned a sealed envelope but caller has no keypair; refusing to fall back to unsealed")
	}
	ct, err := base64.StdEncoding.DecodeString(body.Sealed.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("client: decode sealed ciphertext: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(body.Sealed.Nonce)
	if err != nil {
		return nil, fmt.Errorf("client: decode sealed nonce: %w", err)
	}
	ephPub, err := base64.StdEncoding.DecodeString(body.Sealed.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("client: decode sealed eph pub: %w", err)
	}
	return sealing.Open(&sealing.Envelope{
		Algorithm:          body.Sealed.Algorithm,
		Ciphertext:         ct,
		Nonce:              nonce,
		EphemeralPublicKey: ephPub,
	}, agentPrivKey, agentPubKey)
}

// Zero overwrites b in place. Best-effort defense against casual
// post-use inspection of the heap.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SetPublicKeyRequest is the body the agent PUTs to register its
// X25519 public key. Idempotent on the CP side.
type SetPublicKeyRequest struct {
	PublicKey          string `json:"public_key"`           // base64
	PublicKeyAlgorithm string `json:"public_key_algorithm"` // "x25519"
}

// SetPublicKey PUTs the agent's static X25519 public key to the CP so
// future GetWrap responses come sealed. Idempotent — repeated calls
// with the same key are no-ops. Returns nil on 204; ErrUnauthorized
// on 401; ErrNotFound on 404; HTTPError otherwise.
func (c *Client) SetPublicKey(ctx context.Context, agentID, agentSecret string, publicKey []byte, algorithm string) error {
	body, err := json.Marshal(SetPublicKeyRequest{
		PublicKey:          base64.StdEncoding.EncodeToString(publicKey),
		PublicKeyAlgorithm: algorithm,
	})
	if err != nil {
		return fmt.Errorf("client: marshal public-key body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		c.base+"/api/v1/agents/"+agentID+"/public-key", bytesReader(body))
	if err != nil {
		return fmt.Errorf("client: build public-key request: %w", err)
	}
	req.Header.Set("X-Agent-Secret", agentSecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("client: set public key: %w", err)
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

// PostWrapRequest is the JSON body of POST /api/v1/agents/:id/wraps.
// Used by the agent's ReadExecutor: after GetValue returns the bundle,
// the agent splits by key and POSTs one wrap per key here.
//
// The agent only ever sends Envelope: it called /agents/:id/dek for a
// fresh KMS DEK, AES-256-GCM-encrypted the plaintext locally with that
// DEK, and posts the ciphertext + nonce + DEK ciphertext. Plaintext never
// crosses the wire. The api still accepts a legacy base64 `value` from
// old agents; this agent has no code path that sends one (AGT-02).
type PostWrapRequest struct {
	RequestID string            `json:"request_id"`
	KeyName   string            `json:"key_name"`
	Envelope  *PostWrapEnvelope `json:"envelope"`
}

// PostWrapEnvelope mirrors api's CreateWrapEnvelope: the agent-side
// wire-envelope shape posted to the wrap-creation endpoint. All byte
// fields are base64.
type PostWrapEnvelope struct {
	Algorithm     string `json:"algorithm"`      // "aes-256-gcm"
	Ciphertext    string `json:"ciphertext"`     // AES-GCM(dek, plaintext)
	Nonce         string `json:"nonce"`          // GCM nonce
	DEKCiphertext string `json:"dek_ciphertext"` // KMS-wrapped DEK from /dek
	DEKKMSKeyID   string `json:"dek_kms_key_id,omitempty"`
}

// DEK is the data key the CP hands the agent for one wire-envelope
// POST (Piece 8b). Caller MUST zero Plaintext after encrypting; the
// Ciphertext field is the KMS-wrapped form that goes back to the CP
// inside the wrap-creation envelope.
type DEK struct {
	Algorithm  string
	Plaintext  []byte
	Ciphertext []byte
	KMSKeyID   string
}

// dekResponse mirrors handlers.DEKResponse on the api side.
type dekResponse struct {
	Algorithm  string `json:"algorithm"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
	KMSKeyID   string `json:"kms_key_id"`
}

// IssueDEK calls POST /api/v1/agents/:id/dek. The returned DEK
// is single-use in spirit — agents should call IssueDEK once per
// wrap they're about to POST, to keep the blast radius of a
// compromised DEK to a single value.
func (c *Client) IssueDEK(ctx context.Context, agentID, agentSecret string) (*DEK, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/api/v1/agents/"+agentID+"/dek", http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("client: build dek request: %w", err)
	}
	req.Header.Set("X-Agent-Secret", agentSecret)
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: dek: %w", err)
	}
	defer drainAndClose(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		var body dekResponse
		if err := decodeJSON(resp.Body, maxSmallResponse, &body); err != nil {
			return nil, fmt.Errorf("client: decode dek: %w", err)
		}
		pt, err := base64.StdEncoding.DecodeString(body.Plaintext)
		if err != nil {
			return nil, fmt.Errorf("client: decode dek plaintext: %w", err)
		}
		ct, err := base64.StdEncoding.DecodeString(body.Ciphertext)
		if err != nil {
			Zero(pt)
			return nil, fmt.Errorf("client: decode dek ciphertext: %w", err)
		}
		return &DEK{
			Algorithm:  body.Algorithm,
			Plaintext:  pt,
			Ciphertext: ct,
			KMSKeyID:   body.KMSKeyID,
		}, nil
	case http.StatusUnauthorized:
		return nil, ErrUnauthorized
	case http.StatusNotFound:
		return nil, ErrNotFound
	default:
		return nil, &HTTPError{Status: resp.StatusCode, Body: readSnippet(resp.Body)}
	}
}

// PostWrapResponse mirrors the CP's CreateResponse.
type PostWrapResponse struct {
	WrapID      string `json:"wrap_id"`
	RequestID   string `json:"request_id"`
	KeyName     string `json:"key_name"`
	ByteLength  int    `json:"byte_length"`
	ContentHash string `json:"content_hash"`
	ExpiresAt   string `json:"expires_at"`
}

// PostWrap POSTs a wrap to the CP during the read flow.
//
// The agent calls /agents/:id/dek for a fresh KMS DEK, AES-256-GCM-
// encrypts the plaintext locally, and sends the ciphertext + nonce + DEK
// ciphertext. The DEK plaintext is zeroed before the function returns.
// Plaintext NEVER crosses the wire, and there is no fallback that would
// send it (AGT-02).
//
// The caller's plaintext slice is its responsibility to zero.
func (c *Client) PostWrap(ctx context.Context, agentID, agentSecret, requestID, keyName string, plaintext []byte) (*PostWrapResponse, error) {
	dek, err := c.IssueDEK(ctx, agentID, agentSecret)
	if err != nil {
		return nil, fmt.Errorf("client: issue dek: %w", err)
	}
	// Zero the DEK plaintext as soon as encryption is done — it must
	// never sit on the heap past this call.
	ct, nonce, encErr := sealing.EncryptForCP(plaintext, dek.Plaintext)
	Zero(dek.Plaintext)
	if encErr != nil {
		return nil, fmt.Errorf("client: encrypt for cp: %w", encErr)
	}
	reqBody := PostWrapRequest{
		RequestID: requestID,
		KeyName:   keyName,
		Envelope: &PostWrapEnvelope{
			Algorithm:     "aes-256-gcm",
			Ciphertext:    base64.StdEncoding.EncodeToString(ct),
			Nonce:         base64.StdEncoding.EncodeToString(nonce),
			DEKCiphertext: base64.StdEncoding.EncodeToString(dek.Ciphertext),
			DEKKMSKeyID:   dek.KMSKeyID,
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("client: marshal post-wrap: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/api/v1/agents/"+agentID+"/wraps", bytesReader(body))
	if err != nil {
		return nil, fmt.Errorf("client: build post-wrap request: %w", err)
	}
	req.Header.Set("X-Agent-Secret", agentSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: post-wrap: %w", err)
	}
	defer drainAndClose(resp.Body)

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		var out PostWrapResponse
		if err := decodeJSON(resp.Body, maxSmallResponse, &out); err != nil {
			return nil, fmt.Errorf("client: decode post-wrap response: %w", err)
		}
		return &out, nil
	case http.StatusUnauthorized:
		return nil, ErrUnauthorized
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusConflict:
		return nil, ErrRequestNotApproved
	default:
		return nil, &HTTPError{Status: resp.StatusCode, Body: readSnippet(resp.Body)}
	}
}
