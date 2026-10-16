package sealing_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/hkdf"

	"github.com/secrets-bridge/agent/internal/sealing"
)

// sealForTest is an independent mirror of api/pkg/sealing.Seal: X25519
// with a fresh ephemeral key, HKDF-SHA256 over salt = eph_pub||recipient_pub
// with info "secrets-bridge.wrap.v1", then AES-256-GCM. Writing it out here
// (instead of calling package code) locks the wire scheme in the tests.
func sealForTest(t *testing.T, plaintext, recipientPub []byte) *sealing.Envelope {
	t.Helper()
	curve := ecdh.X25519()
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ephemeral key: %v", err)
	}
	rcpt, err := curve.NewPublicKey(recipientPub)
	if err != nil {
		t.Fatalf("recipient key: %v", err)
	}
	shared, err := eph.ECDH(rcpt)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	ephPub := eph.PublicKey().Bytes()
	salt := append(append([]byte{}, ephPub...), recipientPub...)
	key := make([]byte, 32)
	kdf := hkdf.New(func() hash.Hash { return sha256.New() }, shared, salt, []byte("secrets-bridge.wrap.v1"))
	if _, err := io.ReadFull(kdf, key); err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return &sealing.Envelope{
		Algorithm:          sealing.Algorithm,
		Ciphertext:         gcm.Seal(nil, nonce, plaintext, nil),
		Nonce:              nonce,
		EphemeralPublicKey: ephPub,
	}
}

func recipient(t *testing.T) (pub, priv []byte) {
	t.Helper()
	pub, priv, err := sealing.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	return pub, priv
}

func TestOpen_RoundTrip(t *testing.T) {
	pub, priv := recipient(t)
	want := []byte("fake-db-password")
	got, err := sealing.Open(sealForTest(t, want, pub), priv, pub)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("round-trip plaintext mismatch")
	}
}

// AGT-N-05: a malformed envelope from the CP (or a proxy in front of it)
// must come back as an error. gcm.Open panics on a nonce of the wrong
// length, and that panic used to kill the whole agent.
func TestOpen_MalformedEnvelopeErrorsWithoutPanic(t *testing.T) {
	pub, priv := recipient(t)
	good := func() *sealing.Envelope { return sealForTest(t, []byte("fake-value"), pub) }

	cases := map[string]func(e *sealing.Envelope){
		"empty nonce":         func(e *sealing.Envelope) { e.Nonce = nil },
		"short nonce":         func(e *sealing.Envelope) { e.Nonce = e.Nonce[:4] },
		"long nonce":          func(e *sealing.Envelope) { e.Nonce = append(e.Nonce, 0, 0, 0, 0) },
		"empty ciphertext":    func(e *sealing.Envelope) { e.Ciphertext = nil },
		"truncated tag":       func(e *sealing.Envelope) { e.Ciphertext = e.Ciphertext[:8] },
		"short ephemeral key": func(e *sealing.Envelope) { e.EphemeralPublicKey = e.EphemeralPublicKey[:16] },
		"tampered ciphertext": func(e *sealing.Envelope) { e.Ciphertext[0] ^= 0xff },
		"wrong algorithm":     func(e *sealing.Envelope) { e.Algorithm = "x25519-hkdf-aes-cbc" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			env := good()
			mutate(env)
			var got []byte
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("Open panicked on a malformed envelope: %v", r)
					}
				}()
				got, err = sealing.Open(env, priv, pub)
			}()
			if err == nil {
				t.Fatalf("Open accepted a malformed envelope (%d bytes out)", len(got))
			}
			if strings.Contains(err.Error(), "fake-value") {
				t.Fatalf("error carries plaintext: %v", err)
			}
		})
	}
}

func TestOpen_BadRecipientKeys(t *testing.T) {
	pub, priv := recipient(t)
	env := sealForTest(t, []byte("fake-value"), pub)

	if _, err := sealing.Open(nil, priv, pub); err == nil {
		t.Fatal("nil envelope accepted")
	}
	if _, err := sealing.Open(env, priv[:16], pub); err == nil {
		t.Fatal("short private key accepted")
	}
	if _, err := sealing.Open(env, priv, pub[:16]); err == nil {
		t.Fatal("short public key accepted")
	}
	otherPub, otherPriv := recipient(t)
	if _, err := sealing.Open(env, otherPriv, otherPub); err == nil {
		t.Fatal("envelope opened with the wrong recipient key")
	}
	// Right private key, wrong public key in the HKDF salt.
	if _, err := sealing.Open(env, priv, otherPub); err == nil {
		t.Fatal("envelope opened with a mismatched recipient public key")
	}
}

func TestEncryptForCP_RoundTripAndKeyLength(t *testing.T) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	ct, nonce, err := sealing.EncryptForCP([]byte("fake-value"), dek)
	if err != nil {
		t.Fatalf("EncryptForCP: %v", err)
	}
	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	if len(nonce) != gcm.NonceSize() {
		t.Fatalf("nonce length %d", len(nonce))
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil || string(pt) != "fake-value" {
		t.Fatalf("round-trip failed: %v", err)
	}
	if bytes.Contains(ct, []byte("fake-value")) {
		t.Fatal("ciphertext contains the plaintext")
	}
	for _, n := range []int{0, 16, 31, 33} {
		if _, _, err := sealing.EncryptForCP([]byte("x"), make([]byte, n)); err == nil {
			t.Fatalf("EncryptForCP accepted a %d-byte key", n)
		}
	}
}

func TestGenerateKeypair_PublicMatchesPrivate(t *testing.T) {
	pub, priv := recipient(t)
	if len(pub) != 32 || len(priv) != 32 {
		t.Fatalf("key lengths pub=%d priv=%d", len(pub), len(priv))
	}
	derived, err := sealing.PublicFromPrivate(priv)
	if err != nil {
		t.Fatalf("PublicFromPrivate: %v", err)
	}
	if !bytes.Equal(derived, pub) {
		t.Fatal("derived public key differs")
	}
	if _, err := sealing.PublicFromPrivate(priv[:31]); err == nil {
		t.Fatal("PublicFromPrivate accepted a short key")
	}
}

func TestZero(t *testing.T) {
	b := []byte("fake-value")
	sealing.Zero(b)
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatal("Zero left bytes behind")
	}
	sealing.Zero(nil)
}
