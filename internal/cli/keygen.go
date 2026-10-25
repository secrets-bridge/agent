package cli

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/secrets-bridge/agent/internal/identity"
)

// generateWireKey creates a fresh X25519 wire key with crypto/rand. It is
// the only place in the module that generates a key; the runtime never
// does (the no-runtime-keygen guard enforces this).
func generateWireKey() (*identity.KeyPair, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}
	return identity.KeyPairFromPrivate(k.Bytes())
}
