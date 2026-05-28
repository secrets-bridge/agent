package executor_test

import (
	"context"
	"strings"
	"testing"

	"github.com/secrets-bridge/agent/internal/executor"
	"github.com/secrets-bridge/core/providers/vault"
)

func TestVaultResolver_WrongType(t *testing.T) {
	r := executor.VaultResolver(t.Context())
	_, err := r("aws-sm", nil)
	if err == nil || !strings.Contains(err.Error(), "providerType=") {
		t.Fatalf("got %v want providerType mismatch error", err)
	}
}

func TestVaultResolver_TokenAuth_PayloadAddress(t *testing.T) {
	// Token auth via env + address via payload. Should construct
	// successfully without any HTTP calls.
	t.Setenv(executor.EnvVaultToken, "test-token")
	r := executor.VaultResolver(t.Context())
	p, err := r(vault.Kind, map[string]any{
		vault.ConfigAddress: "http://localhost:8200",
	})
	if err != nil {
		t.Fatalf("VaultResolver: %v", err)
	}
	if p == nil {
		t.Fatal("provider is nil")
	}
}

func TestVaultResolver_TokenAuth_EnvAddress(t *testing.T) {
	t.Setenv(executor.EnvVaultAddr, "http://localhost:8200")
	t.Setenv(executor.EnvVaultToken, "test-token")
	r := executor.VaultResolver(t.Context())
	if _, err := r(vault.Kind, nil); err != nil {
		t.Fatalf("VaultResolver: %v", err)
	}
}

func TestVaultResolver_PayloadAddressOverridesEnv(t *testing.T) {
	t.Setenv(executor.EnvVaultAddr, "http://envvar:8200")
	t.Setenv(executor.EnvVaultToken, "test-token")
	r := executor.VaultResolver(t.Context())
	// Payload address should win — we can't easily inspect the
	// resulting Vault client's address, but we CAN verify it
	// constructs without error using a payload address that would
	// otherwise be invalid alone.
	if _, err := r(vault.Kind, map[string]any{
		vault.ConfigAddress: "http://payload:8200",
	}); err != nil {
		t.Fatalf("VaultResolver: %v", err)
	}
}

func TestVaultResolver_TokenInPayloadIsRefused(t *testing.T) {
	t.Setenv(executor.EnvVaultAddr, "http://localhost:8200")
	r := executor.VaultResolver(t.Context())
	_, err := r(vault.Kind, map[string]any{vault.ConfigToken: "leaked-via-payload"})
	if err == nil || !strings.Contains(err.Error(), "MUST NOT be passed via job payload") {
		t.Fatalf("got %v want refusal of payload token", err)
	}
}

func TestVaultResolver_MissingAddress(t *testing.T) {
	// No env, no payload address → error.
	r := executor.VaultResolver(t.Context())
	_, err := r(vault.Kind, map[string]any{vault.ConfigAuthMethod: "token"})
	if err == nil || !strings.Contains(err.Error(), "address not configured") {
		t.Fatalf("got %v want address-required error", err)
	}
}

func TestVaultResolver_NoAuthConfigured(t *testing.T) {
	t.Setenv(executor.EnvVaultAddr, "http://localhost:8200")
	r := executor.VaultResolver(t.Context())
	_, err := r(vault.Kind, nil)
	if err == nil || !strings.Contains(err.Error(), "no auth configured") {
		t.Fatalf("got %v want no-auth-configured error", err)
	}
}

func TestResolverByType_KnownProviderRoutesToVault(t *testing.T) {
	t.Setenv(executor.EnvVaultAddr, "http://localhost:8200")
	t.Setenv(executor.EnvVaultToken, "tok")
	r := executor.ResolverByType(context.Background())
	if _, err := r(vault.Kind, nil); err != nil {
		t.Fatalf("ResolverByType(vault): %v", err)
	}
}

func TestResolverByType_UnknownProviderFallsBack(t *testing.T) {
	r := executor.ResolverByType(context.Background())
	_, err := r("aws-sm", nil)
	// Falls through to NotConfiguredResolver which has a distinctive
	// error message — verify we ended up there.
	if err == nil || !strings.Contains(err.Error(), "no provider resolver configured") {
		t.Fatalf("got %v want NotConfiguredResolver fall-through", err)
	}
}
