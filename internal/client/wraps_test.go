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

// testKeypair returns a fresh X25519 keypair standing in for the one the
// agent registered with the CP.
func testKeypair(t *testing.T) (pub, priv []byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return k.PublicKey().Bytes(), k.Bytes()
}

// sealedWrapBody builds a CP wrap response sealed to recipientPub, with
// the given content_hash.
func sealedWrapBody(t *testing.T, plaintext, recipientPub []byte, contentHash string) map[string]any {
	t.Helper()
	ct, nonce, ephPub := fakeSealForTest(t, plaintext, recipientPub)
	return map[string]any{
		"wrap_id":                   "w",
		"request_id":                "r",
		"key_name":                  "DB_PASSWORD",
		"byte_length":               len(plaintext),
		"content_hash":              contentHash,
		"algorithm":                 "AES-256-GCM",
		"recipient_key_fingerprint": sealing.Fingerprint(recipientPub),
		"sealed": map[string]string{
			"algorithm":            sealing.Algorithm,
			"ciphertext":           base64.StdEncoding.EncodeToString(ct),
			"nonce":                base64.StdEncoding.EncodeToString(nonce),
			"ephemeral_public_key": base64.StdEncoding.EncodeToString(ephPub),
		},
	}
}

func TestGetWrap_HappyPath_VerifiesContentHash(t *testing.T) {
	pub, priv := testKeypair(t)
	plaintext := []byte("hunter2")
	sum := sha256.Sum256(plaintext)
	body := sealedWrapBody(t, plaintext, pub, hex.EncodeToString(sum[:]))

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
		_ = json.NewEncoder(w).Encode(body)
	})

	got, err := c.GetWrap(t.Context(), "agent-x", "s", "w", pub, priv)
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
	// Send a hash that won't match the opened bytes.
	pub, priv := testKeypair(t)
	body := sealedWrapBody(t, []byte("hunter2"), pub, "deadbeef")
	c, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(body)
	})
	_, err := c.GetWrap(t.Context(), "a", "s", "w", pub, priv)
	if !errors.Is(err, client.ErrContentHashMismatch) {
		t.Fatalf("got %v want ErrContentHashMismatch", err)
	}
}

// skills#116: a wrap sealed to another key, or with no recipient
// fingerprint, is refused before the envelope is opened.
func TestGetWrap_RecipientFingerprintMustBeOurs(t *testing.T) {
	pub, priv := testKeypair(t)
	otherPub, _ := testKeypair(t)
	plaintext := []byte("hunter2")
	sum := sha256.Sum256(plaintext)
	for name, fp := range map[string]any{
		"other key": sealing.Fingerprint(otherPub),
		"missing":   nil,
		"empty":     "",
		"uppercase": strings.ToUpper(sealing.Fingerprint(pub)),
	} {
		t.Run(name, func(t *testing.T) {
			body := sealedWrapBody(t, plaintext, pub, hex.EncodeToString(sum[:]))
			if fp == nil {
				delete(body, "recipient_key_fingerprint")
			} else {
				body["recipient_key_fingerprint"] = fp
			}
			c, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(body)
			})
			got, err := c.GetWrap(t.Context(), "a", "s", "w", pub, priv)
			if !errors.Is(err, client.ErrWrongRecipientKey) {
				t.Fatalf("got (%v, %v) want ErrWrongRecipientKey", got, err)
			}
		})
	}
}

// Every agent-authenticated call sends X-Agent-Key-Fingerprint, and a 409
// agent_key_mismatch maps to ErrKeyMismatch while other 409s keep their
// meaning.
func TestClient_KeyFingerprintHeaderAndMismatch(t *testing.T) {
	var seen atomic.Value
	mismatch := atomic.Bool{}
	c, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Header.Get("X-Agent-Key-Fingerprint"))
		if mismatch.Load() {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"agent_key_mismatch"}`))
			return
		}
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"request_not_approved"}`))
	})
	c.WithKeyFingerprint("sha256:abc")
	pub, priv := testKeypair(t)
	if _, err := c.GetWrap(t.Context(), "a", "s", "w", pub, priv); !errors.Is(err, client.ErrRequestNotApproved) {
		t.Fatalf("plain 409 = %v want ErrRequestNotApproved", err)
	}
	if seen.Load() != "sha256:abc" {
		t.Fatalf("X-Agent-Key-Fingerprint = %v", seen.Load())
	}
	mismatch.Store(true)
	calls := map[string]func() error{
		"heartbeat": func() error { _, err := c.Heartbeat(t.Context(), "a", "s", nil); return err },
		"claim":     func() error { _, err := c.ClaimJob(t.Context(), "a", "s"); return err },
		"complete":  func() error { return c.CompleteJob(t.Context(), "a", "s", "j", client.JobOutcome{Status: "failed"}) },
		"wrap":      func() error { _, err := c.GetWrap(t.Context(), "a", "s", "w", pub, priv); return err },
		"dek":       func() error { _, err := c.IssueDEK(t.Context(), "a", "s"); return err },
		"post-wrap": func() error { _, err := c.PostWrap(t.Context(), "a", "s", "r", "K", []byte("x")); return err },
		"bulk": func() error {
			_, err := c.PostSecretsBulk(t.Context(), "a", "s", client.SecretBulkRequest{ClusterName: "c"})
			return err
		},
	}
	for name, call := range calls {
		seen.Store("")
		if err := call(); !errors.Is(err, client.ErrKeyMismatch) {
			t.Errorf("%s: got %v want ErrKeyMismatch", name, err)
		}
		if seen.Load() != "sha256:abc" {
			t.Errorf("%s: X-Agent-Key-Fingerprint = %v", name, seen.Load())
		}
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
			_, err := c.GetWrap(t.Context(), "a", "s", "w", make([]byte, 32), make([]byte, 32))
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
		"wrap_id":                   "w-sealed",
		"key_name":                  "DB_PASSWORD",
		"byte_length":               len(plaintext),
		"content_hash":              hashHex,
		"algorithm":                 "AES-256-GCM",
		"recipient_key_fingerprint": sealing.Fingerprint(agentPub),
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
	// A caller without a keypair can't open a sealed wrap, and fetching
	// it anyway would consume the single-use wrap on the CP. The client
	// refuses loud before sending anything.
	var hits atomic.Int32
	c, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	_, err := c.GetWrap(t.Context(), "agent", "s", "w", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no keypair") {
		t.Fatalf("got %v want refusal mentioning no keypair", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("wrap requested without a keypair (%d calls)", hits.Load())
	}
}

func TestGetWrap_ValueWithKeypair_RefusesSilentDowngrade(t *testing.T) {
	// AGT-02: the agent holds a registered keypair, but the CP returns a
	// plaintext value-only response (no sealed envelope). That's a
	// downgrade — GetWrap must refuse rather than accept plaintext off
	// the wire, even though the content_hash would otherwise verify.
	plaintext := []byte("hunter2")
	sum := sha256.Sum256(plaintext)
	pub := make([]byte, 32)
	body := `{"wrap_id":"w","value":"` + base64.StdEncoding.EncodeToString(plaintext) +
		`","byte_length":7,"content_hash":"` + hex.EncodeToString(sum[:]) + `","algorithm":"AES-256-GCM",` +
		`"recipient_key_fingerprint":"` + sealing.Fingerprint(pub) + `"}`
	c, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	// A non-empty key is enough here: the value branch never reaches
	// sealing.Open, so 32-byte dummies are sufficient.
	priv := make([]byte, 32)
	_, err := c.GetWrap(t.Context(), "a", "s", "w", pub, priv)
	if err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("got %v want silent-downgrade refusal", err)
	}
}

func TestPostWrap_DEKFailureNeverFallsBackToPlaintext(t *testing.T) {
	// AGT-02: if the DEK can't be issued the post fails. There is no
	// plaintext `value` fallback, so /wraps must never be called.
	var wrapsCalled atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agents/a/dek", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "kms unavailable", http.StatusServiceUnavailable)
	})
	mux.HandleFunc("POST /api/v1/agents/a/wraps", func(w http.ResponseWriter, _ *http.Request) {
		wrapsCalled.Store(true)
		w.WriteHeader(http.StatusCreated)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := client.New(srv.URL).WithHTTPClient(srv.Client())

	if _, err := c.PostWrap(t.Context(), "a", "s", "r", "K", []byte("hunter2")); err == nil {
		t.Fatal("PostWrap succeeded without a DEK")
	}
	if wrapsCalled.Load() {
		t.Fatal("wrap posted without the envelope")
	}
}

func TestPostWrap_EnvelopePath(t *testing.T) {
	// /dek is called first, then /wraps carries the envelope. The captured ciphertext, when decrypted with the same
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
			"algorithm":  "aes-256-gcm",
			"plaintext":  base64.StdEncoding.EncodeToString(dekPlain),
			"ciphertext": base64.StdEncoding.EncodeToString(dekCipher),
			"kms_key_id": "local:test-key",
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

	if _, err := c.PostWrap(t.Context(), "a", "s", "r", "K", plaintext); err != nil {
		t.Fatalf("PostWrap: %v", err)
	}
	if !dekCalled.Load() {
		t.Fatal("DEK was NOT issued on the envelope path")
	}
	var body client.PostWrapRequest
	if err := json.Unmarshal(capturedBody, &body); err != nil {
		t.Fatalf("decode posted body: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(capturedBody, &raw); err != nil {
		t.Fatalf("decode posted body: %v", err)
	}
	if _, ok := raw["value"]; ok {
		t.Fatalf("value field was sent: %v", raw["value"])
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

// agent#39 / api#286: an empty value is sealed and posted like any
// other. The envelope carries a GCM tag that opens to zero bytes.
func TestPostWrap_EmptyPlaintextIsSealedNormally(t *testing.T) {
	dekPlain := make([]byte, 32)
	if _, err := rand.Read(dekPlain); err != nil {
		t.Fatalf("rand: %v", err)
	}
	var capturedBody []byte
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agents/a/dek", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"algorithm":  "aes-256-gcm",
			"plaintext":  base64.StdEncoding.EncodeToString(dekPlain),
			"ciphertext": base64.StdEncoding.EncodeToString([]byte("kms-ct")),
		})
	})
	mux.HandleFunc("POST /api/v1/agents/a/wraps", func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"wrap_id":"w","request_id":"r","key_name":"EMPTY","byte_length":0}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := client.New(srv.URL).WithHTTPClient(srv.Client())

	if _, err := c.PostWrap(t.Context(), "a", "s", "r", "EMPTY", []byte{}); err != nil {
		t.Fatalf("PostWrap(empty): %v", err)
	}
	var body client.PostWrapRequest
	if err := json.Unmarshal(capturedBody, &body); err != nil {
		t.Fatalf("decode posted body: %v", err)
	}
	if body.KeyName != "EMPTY" || body.Envelope == nil || body.Envelope.Algorithm != "aes-256-gcm" {
		t.Fatalf("not a normal sealed wrap: %s", capturedBody)
	}
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
	if len(ct) != gcm.Overhead() {
		t.Fatalf("ciphertext len = %d want %d (tag only)", len(ct), gcm.Overhead())
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if len(pt) != 0 {
		t.Fatalf("opened %d bytes want 0", len(pt))
	}
}
