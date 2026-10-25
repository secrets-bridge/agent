// Package sealtest seals payloads the way the control plane does
// (api/pkg/sealing.Seal), for tests that stand in for the CP. Only test
// files may import it; the no-runtime-keygen guard enforces that.
package sealtest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/secrets-bridge/agent/internal/sealing"
)

// Seal encrypts plaintext to recipientPub with a fresh ephemeral X25519
// key, HKDF-SHA256 (salt eph_pub||recipient_pub, info
// "secrets-bridge.wrap.v1") and AES-256-GCM.
func Seal(plaintext, recipientPub []byte) (*sealing.Envelope, error) {
	curve := ecdh.X25519()
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	rcpt, err := curve.NewPublicKey(recipientPub)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(rcpt)
	if err != nil {
		return nil, err
	}
	ephPub := eph.PublicKey().Bytes()
	salt := append(append([]byte{}, ephPub...), recipientPub...)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(func() hash.Hash { return sha256.New() }, shared, salt, []byte("secrets-bridge.wrap.v1")), key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &sealing.Envelope{
		Algorithm:          sealing.Algorithm,
		Ciphertext:         gcm.Seal(nil, nonce, plaintext, nil),
		Nonce:              nonce,
		EphemeralPublicKey: ephPub,
	}, nil
}

// Wire returns env in the JSON shape the CP sends (base64 fields).
func Wire(env *sealing.Envelope) map[string]string {
	return map[string]string{
		"algorithm":            env.Algorithm,
		"ciphertext":           base64.StdEncoding.EncodeToString(env.Ciphertext),
		"nonce":                base64.StdEncoding.EncodeToString(env.Nonce),
		"ephemeral_public_key": base64.StdEncoding.EncodeToString(env.EphemeralPublicKey),
	}
}
