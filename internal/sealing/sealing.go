// Package sealing implements the agent side of the wire-envelope
// encryption introduced in api Piece 8b.
//
// The CP seals retrieval responses to the agent's registered X25519
// public key. The agent decrypts locally with its private key —
// the private key NEVER leaves the agent process.
//
// Scheme (must mirror api's pkg/sealing):
//
//	shared = X25519(agent_priv, eph_pub)
//	aes_key = HKDF-SHA256(shared, salt=eph_pub||agent_pub, info="secrets-bridge.wrap.v1")
//	plaintext = AES-256-GCM-Open(aes_key, ciphertext, nonce)
//
// The agent never seals — only opens. Sealing happens server-side
// where the CP holds the KMS and the runtime trust anchor.
package sealing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Algorithm is the scheme this package implements. Must match
// api/pkg/sealing.Algorithm so the agent rejects any other scheme
// it might receive (a misconfigured CP or a future rotation that
// hasn't reached the agent yet).
const Algorithm = "x25519-hkdf-aes-gcm"

// hkdfInfo MUST match api/pkg/sealing's hkdfInfo. Any drift here
// breaks the round-trip silently with an authentication failure
// at AES-GCM open time.
var hkdfInfo = []byte("secrets-bridge.wrap.v1")

// Envelope mirrors api/pkg/sealing.Envelope — same bytes, agent-side
// representation. Constructed by the client after JSON+base64 decode.
type Envelope struct {
	Ciphertext         []byte
	Nonce              []byte
	EphemeralPublicKey []byte
	Algorithm          string
}

// Open decrypts a sealed envelope using the agent's static X25519
// keypair. Caller is responsible for zeroing the returned plaintext.
//
// recipientPub is the agent's static public key — passed in because
// it's part of the HKDF salt. Strictly speaking the package could
// derive it from recipientPriv via X25519 scalar mult of base point,
// but having the caller pass both avoids re-computing on every call
// and matches api/pkg/sealing's interface.
func Open(env *Envelope, recipientPriv, recipientPub []byte) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("sealing: envelope is nil")
	}
	if env.Algorithm != Algorithm {
		return nil, fmt.Errorf("sealing: unknown algorithm %q", env.Algorithm)
	}
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(recipientPriv)
	if err != nil {
		return nil, fmt.Errorf("sealing: parse recipient private key: %w", err)
	}
	ephPub, err := curve.NewPublicKey(env.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("sealing: parse ephemeral public key: %w", err)
	}
	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("sealing: ecdh: %w", err)
	}
	defer Zero(shared)

	aesKey, err := deriveAESKey(shared, env.EphemeralPublicKey, recipientPub)
	if err != nil {
		return nil, err
	}
	defer Zero(aesKey)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("sealing: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("sealing: gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, env.Nonce, env.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("sealing: open: %w", err)
	}
	return plaintext, nil
}

// GenerateKeypair returns a fresh X25519 keypair. Used by the agent
// at startup when no private key has been persisted yet.
func GenerateKeypair() (pub, priv []byte, err error) {
	curve := ecdh.X25519()
	p, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("sealing: generate keypair: %w", err)
	}
	return p.PublicKey().Bytes(), p.Bytes(), nil
}

// PublicFromPrivate derives the public key from a stored private key.
// Used after the agent loads its private key from file / env so it
// has the public key to send to the CP on registration.
func PublicFromPrivate(priv []byte) ([]byte, error) {
	curve := ecdh.X25519()
	p, err := curve.NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("sealing: parse private key: %w", err)
	}
	return p.PublicKey().Bytes(), nil
}

// EncryptForCP is a small helper for the AES-GCM wire-envelope POST
// path (read flow). The agent calls /agents/:id/dek to get a fresh
// data key, then encrypts the payload with that key here. The key
// is provided by the caller and zeroed by the caller after.
//
// Returns (ciphertext, nonce, error). The nonce is freshly random.
func EncryptForCP(plaintext, dataKey []byte) (ciphertext, nonce []byte, err error) {
	if len(dataKey) != 32 {
		return nil, nil, fmt.Errorf("sealing: data key must be 32 bytes, got %d", len(dataKey))
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sealing: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("sealing: gcm: %w", err)
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("sealing: random nonce: %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// deriveAESKey mirrors api/pkg/sealing.deriveAESKey. Any drift here
// breaks the round-trip silently.
func deriveAESKey(shared, ephPub, recipientPub []byte) ([]byte, error) {
	salt := make([]byte, 0, len(ephPub)+len(recipientPub))
	salt = append(salt, ephPub...)
	salt = append(salt, recipientPub...)
	kdf := hkdf.New(func() hash.Hash { return sha256.New() }, shared, salt, hkdfInfo)
	out := make([]byte, 32)
	if _, err := io.ReadFull(kdf, out); err != nil {
		return nil, fmt.Errorf("sealing: hkdf: %w", err)
	}
	return out, nil
}

// Zero overwrites b in place. Same posture as client.Zero — best
// effort defense against post-use heap inspection.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
