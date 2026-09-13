package main

import (
	"errors"
	"testing"

	"github.com/secrets-bridge/agent/internal/identity"
)

// AGT-02: prove the boot-path decision — a persistent keypair whose
// public-key registration fails is fatal (no silent downgrade), while an
// ephemeral keypair keeps the legacy plaintext-over-TLS fallback.
func TestSealingDecision(t *testing.T) {
	regErr := errors.New("cp unreachable")
	cases := []struct {
		name           string
		source         identity.KeyPairSource
		regErr         error
		wantSealActive bool
		wantFatal      bool
	}{
		{"registered-env", identity.KeyPairSourceEnv, nil, true, false},
		{"registered-file", identity.KeyPairSourceFileLoaded, nil, true, false},
		{"registered-ephemeral", identity.KeyPairSourceEphemeral, nil, true, false},
		{"failed-env-is-fatal", identity.KeyPairSourceEnv, regErr, false, true},
		{"failed-file-is-fatal", identity.KeyPairSourceFileLoaded, regErr, false, true},
		{"failed-file-generated-is-fatal", identity.KeyPairSourceFileGenerated, regErr, false, true},
		{"failed-ephemeral-falls-back", identity.KeyPairSourceEphemeral, regErr, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sealActive, fatal := sealingDecision(tc.source, tc.regErr)
			if sealActive != tc.wantSealActive || fatal != tc.wantFatal {
				t.Fatalf("sealingDecision(%q, err=%v) = (seal=%v, fatal=%v) want (seal=%v, fatal=%v)",
					tc.source, tc.regErr, sealActive, fatal, tc.wantSealActive, tc.wantFatal)
			}
		})
	}
}
