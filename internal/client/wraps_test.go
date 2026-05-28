package client_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/hkdf"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/agent/internal/sealing"
)

func newServer(t *testing.T, h http.HandlerFunc) (*client.Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := client.New(srv.URL).WithHTTPClient(srv.Client())
	return c, srv
}

func TestGetWrap_HappyPath_VerifiesContentHash(t *testing.T) {
	plaintext := []byte("hunter2")
	sum := sha256.Sum256(plaintext)
	hashHex := hex.EncodeToString(sum[:])
	body := `{"wrap_id":"w","request_id":"r","key_name":"DB_PASSWORD","value":"` +
		base64.StdEncoding.EncodeToString(plaintext) +
		`","byte_length":7,"content_hash":"` + hashHex + `","algorithm":"AES-256-GCM"}`

	c, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s want GET", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/wraps/w") {
			t.Errorf("path = %s want suffix /wraps/w", r.URL.Path)
		}
		if r.Header.Get("X-Agent-Secret") != "s" {
			t.Errorf("missing X-Agent-Secret header")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})

	got, err := c.GetWrap(t.Context(), "agent-x", "s", "w", nil, nil)
	if err != nil {
		t.Fatalf("GetWrap: %v", err)
	}
	if string(got.Plaintext) != "hunter2" {
		t.Fatalf("plaintext = %q want hunter2", got.Plaintext)
	}
	if got.KeyName != "DB_PASSWORD" {
		t.Fatalf("key_name = %q", got.KeyName)
	}
}

func TestGetWrap_ContentHashMismatch(t *testing.T) {
	// Send a hash that won't match the bytes.
	body := `{"wrap_id":"w","value":"` + base64.StdEncoding.EncodeToString([]byte("hunter2")) +
		`","byte_length":7,"content_hash":"deadbeef","algorithm":"AES-256-GCM"}`
	c, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	_, err := c.GetWrap(t.Context(), "a", "s", "w", nil, nil)
	if !errors.Is(err, client.ErrContentHashMismatch) {
		t.Fatalf("got %v want ErrContentHashMismatch", err)
	}
}

func TestGetWrap_StatusMapping(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusUnauthorized, client.ErrUnauthorized},
		{http.StatusNotFound, client.ErrNotFound},
		{http.StatusGone, client.ErrWrapGone},
		{http.StatusConflict, client.ErrRequestNotApproved},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			c, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			})
			_, err := c.GetWrap(t.Context(), "a", "s", "w", nil, nil)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}

func TestGetWrap_SealedEnvelope_RoundTrip(t *testing.T) {
	// CP-side: generate agent's keypair as if it had been registered,
	// then seal a payload against the agent's public key. The agent
	// decrypts via the sealing package and we assert the round-trip.
	curve := ecdh.X25519()
	agentKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	agentPub := agentKey.PublicKey().Bytes()
	agentPriv := agentKey.Bytes()

	plaintext := []byte("hunter2-via-seal")
	envBytes, envNonce, ephPub := fakeSealForTest(t, plaintext, agentPub)

	sum := sha256.Sum256(plaintext)
	hashHex := hex.EncodeToString(sum[:])
	body := map[string]any{
		"wrap_id":      "w-sealed",
		"key_name":     "DB_PASSWORD",
		"byte_length":  len(plaintext),
		"content_hash": hashHex,
		"algorithm":    "AES-256-GCM",
		"sealed": map[string]string{
			"algorithm":            sealing.Algorithm,
			"ciphertext":           base64.StdEncoding.EncodeToString(envBytes),
			"nonce":                base64.StdEncoding.EncodeToString(envNonce),
			"ephemeral_public_key": base64.StdEncoding.EncodeToString(ephPub),
		},
	}
	c, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(body)
	})
	got, err := c.GetWrap(t.Context(), "agent", "s", "w-sealed", agentPub, agentPriv)
	if err != nil {
		t.Fatalf("GetWrap: %v", err)
	}
	if string(got.Plaintext) != string(plaintext) {
		t.Fatalf("plaintext = %q want %q", got.Plaintext, plaintext)
	}
}

func TestGetWrap_SealedButNoKeypair_RefusesSilentDowngrade(t *testing.T) {
	// Even though we'll fail to decrypt without the keypair, the CP
	// returned a sealed envelope — the client must refuse loud rather
	// than silently fall back to legacy.
	body := map[string]any{
		"wrap_id":      "w",
		"byte_length":  4,
		"content_hash": hex.EncodeToString(sha256.New().Sum(nil)),
		"algorithm":    "AES-256-GCM",
		"sealed": map[string]string{
			"algorithm":            sealing.Algorithm,
			"ciphertext":           base64.StdEncoding.EncodeToString([]byte("ct")),
			"nonce":                base64.StdEncoding.EncodeToString(make([]byte, 12)),
			"ephemeral_public_key": base64.StdEncoding.EncodeToString(make([]byte, 32)),
		},
	}
	c, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(body)
	})
	_, err := c.GetWrap(t.Context(), "agent", "s", "w", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no keypair") {
		t.Fatalf("got %v want refusal mentioning no keypair", err)
	}
}

func TestPostWrap_LegacyValuePath(t *testing.T) {
	// useEnvelope=false → POST body carries `value` (base64 plaintext)
	// and NO envelope. /dek must NOT be called.
	var dekCalled atomic.Bool
	var capturedBody []byte
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agents/a/dek", func(w http.ResponseWriter, _ *http.Request) {
		dekCalled.Store(true)
		http.Error(w, "should not be called", http.StatusInternalServerError)
	})
	mux.HandleFunc("POST /api/v1/agents/a/wraps", func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"wrap_id":"w","request_id":"r","key_name":"K","byte_length":7,"content_hash":"x","expires_at":"2026-05-28T00:00:00Z"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := client.New(srv.URL).WithHTTPClient(srv.Client())

	out, err := c.PostWrap(t.Context(), "a", "s", "r", "K", []byte("hunter2"), false)
	if err != nil {
		t.Fatalf("PostWrap: %v", err)
	}
	if out.WrapID != "w" {
		t.Fatalf("WrapID = %q", out.WrapID)
	}
	if dekCalled.Load() {
		t.Fatal("DEK was issued on the legacy path — must not happen")
	}
	var body client.PostWrapRequest
	if err := json.Unmarshal(capturedBody, &body); err != nil {
		t.Fatalf("decode posted body: %v", err)
	}
	if body.Envelope != nil {
		t.Fatalf("envelope was sent on legacy path: %+v", body.Envelope)
	}
	if body.Value == "" {
		t.Fatal("value field was empty on legacy path")
	}
	decoded, _ := base64.StdEncoding.DecodeString(body.Value)
	if string(decoded) != "hunter2" {
		t.Fatalf("value decodes to %q", decoded)
	}
}

func TestPostWrap_EnvelopePath(t *testing.T) {
	// useEnvelope=true → /dek is called first, then /wraps carries the
	// envelope. The captured ciphertext, when decrypted with the same
	// DEK plaintext, must recover the original plaintext.
	dekPlain := make([]byte, 32)
	if _, err := rand.Read(dekPlain); err != nil {
		t.Fatalf("rand: %v", err)
	}
	dekCipher := []byte("opaque-kms-ciphertext-bytes")
	plaintext := []byte("the-actual-api-key-from-provider")

	var dekCalled atomic.Bool
	var capturedBody []byte
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agents/a/dek", func(w http.ResponseWriter, _ *http.Request) {
		dekCalled.Store(true)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"algorithm":   "aes-256-gcm",
			"plaintext":   base64.StdEncoding.EncodeToString(dekPlain),
			"ciphertext":  base64.StdEncoding.EncodeToString(dekCipher),
			"kms_key_id":  "local:test-key",
		})
	})
	mux.HandleFunc("POST /api/v1/agents/a/wraps", func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"wrap_id":"w","request_id":"r","key_name":"K","byte_length":32,"content_hash":"x","expires_at":"2026-05-28T00:00:00Z"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := client.New(srv.URL).WithHTTPClient(srv.Client())

	if _, err := c.PostWrap(t.Context(), "a", "s", "r", "K", plaintext, true); err != nil {
		t.Fatalf("PostWrap: %v", err)
	}
	if !dekCalled.Load() {
		t.Fatal("DEK was NOT issued on the envelope path")
	}
	var body client.PostWrapRequest
	if err := json.Unmarshal(capturedBody, &body); err != nil {
		t.Fatalf("decode posted body: %v", err)
	}
	if body.Value != "" {
		t.Fatalf("value field was sent on envelope path: %q", body.Value)
	}
	if body.Envelope == nil {
		t.Fatal("envelope was not sent")
	}
	if body.Envelope.Algorithm != "aes-256-gcm" {
		t.Fatalf("algorithm = %q", body.Envelope.Algorithm)
	}
	if body.Envelope.DEKKMSKeyID != "local:test-key" {
		t.Fatalf("kms_key_id = %q", body.Envelope.DEKKMSKeyID)
	}
	gotDEKCipher, _ := base64.StdEncoding.DecodeString(body.Envelope.DEKCiphertext)
	if string(gotDEKCipher) != string(dekCipher) {
		t.Fatalf("dek_ciphertext round-trip wrong")
	}
	if strings.Contains(string(capturedBody), string(plaintext)) {
		t.Fatal("plaintext leaked into the POST body")
	}
	// Verify the ciphertext actually decrypts back to plaintext with the DEK.
	ct, _ := base64.StdEncoding.DecodeString(body.Envelope.Ciphertext)
	nonce, _ := base64.StdEncoding.DecodeString(body.Envelope.Nonce)
	block, err := aes.NewCipher(dekPlain)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	decoded, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("aes-gcm open: %v", err)
	}
	if string(decoded) != string(plaintext) {
		t.Fatalf("round-trip = %q want %q", decoded, plaintext)
	}
}

// fakeSealForTest mirrors api/pkg/sealing.Seal so the GetWrap sealed-
// envelope test can build a payload the agent will accept.
func fakeSealForTest(t *testing.T, plaintext, recipientPub []byte) (ciphertext, nonce, ephPub []byte) {
	t.Helper()
	curve := ecdh.X25519()
	ephKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	rcpt, err := curve.NewPublicKey(recipientPub)
	if err != nil {
		t.Fatalf("rcpt pub: %v", err)
	}
	shared, err := ephKey.ECDH(rcpt)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	ephPubBytes := ephKey.PublicKey().Bytes()
	salt := append(append([]byte{}, ephPubBytes...), recipientPub...)
	aesKey := hkdfDeriveForTest(t, shared, salt)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, ephPubBytes
}

// hkdfDeriveForTest reproduces the sealing package's HKDF-SHA256 with
// the same info constant so we can exercise the round-trip in tests.
func hkdfDeriveForTest(t *testing.T, shared, salt []byte) []byte {
	t.Helper()
	out := make([]byte, 32)
	kdf := hkdf.New(func() hash.Hash { return sha256.New() }, shared, salt, []byte("secrets-bridge.wrap.v1"))
	if _, err := io.ReadFull(kdf, out); err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	return out
}
