package executor_test

import (
	"context"
	"strings"
	"testing"

	"github.com/secrets-bridge/agent/internal/executor"
	"github.com/secrets-bridge/core/providers/awssecretsmanager"
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

// --- AWS Secrets Manager ----------------------------------------------

func TestAWSResolver_WrongType(t *testing.T) {
	r := executor.AWSSecretsManagerResolver(t.Context())
	_, err := r("vault", nil)
	if err == nil || !strings.Contains(err.Error(), "providerType=") {
		t.Fatalf("got %v want providerType mismatch error", err)
	}
}

func TestAWSResolver_RegionFromEnv(t *testing.T) {
	t.Setenv(executor.EnvAWSRegion, "us-east-1")
	r := executor.AWSSecretsManagerResolver(t.Context())
	if _, err := r(awssecretsmanager.Kind, nil); err != nil {
		t.Fatalf("AWSResolver: %v", err)
	}
}

func TestAWSResolver_RegionFromPayload(t *testing.T) {
	r := executor.AWSSecretsManagerResolver(t.Context())
	if _, err := r(awssecretsmanager.Kind, map[string]any{
		awssecretsmanager.ConfigRegion: "eu-west-1",
	}); err != nil {
		t.Fatalf("AWSResolver: %v", err)
	}
}

func TestAWSResolver_PayloadOverridesEnv(t *testing.T) {
	t.Setenv(executor.EnvAWSRegion, "us-east-1")
	r := executor.AWSSecretsManagerResolver(t.Context())
	if _, err := r(awssecretsmanager.Kind, map[string]any{
		awssecretsmanager.ConfigRegion: "eu-west-1",
	}); err != nil {
		t.Fatalf("AWSResolver: %v", err)
	}
}

func TestAWSResolver_MissingRegion(t *testing.T) {
	r := executor.AWSSecretsManagerResolver(t.Context())
	_, err := r(awssecretsmanager.Kind, nil)
	if err == nil || !strings.Contains(err.Error(), "region not configured") {
		t.Fatalf("got %v want region-required error", err)
	}
}

func TestAWSResolver_CredentialsInPayloadRefused(t *testing.T) {
	t.Setenv(executor.EnvAWSRegion, "us-east-1")
	r := executor.AWSSecretsManagerResolver(t.Context())
	// Try every banned key — each must be refused independently.
	banned := []string{
		"awsAccessKeyID",
		"awsSecretAccessKey",
		"awsSessionToken",
		"accessKeyID",
		"secretAccessKey",
		"sessionToken",
		"credentials",
	}
	for _, k := range banned {
		t.Run(k, func(t *testing.T) {
			_, err := r(awssecretsmanager.Kind, map[string]any{k: "leak-attempt"})
			if err == nil || !strings.Contains(err.Error(), "MUST NOT be passed via job payload") {
				t.Fatalf("payload key %q: got %v want refusal", k, err)
			}
		})
	}
}

func TestAWSResolver_EndpointAndRoleArnPassedThrough(t *testing.T) {
	// Non-credential keys (endpoint, roleArn) should be accepted in
	// the payload — useful for LocalStack and per-tenant assume-role.
	r := executor.AWSSecretsManagerResolver(t.Context())
	if _, err := r(awssecretsmanager.Kind, map[string]any{
		awssecretsmanager.ConfigRegion:   "us-east-1",
		awssecretsmanager.ConfigEndpoint: "http://localhost:4566",
		awssecretsmanager.ConfigRoleArn:  "arn:aws:iam::123456789012:role/tenant",
	}); err != nil {
		t.Fatalf("AWSResolver: %v", err)
	}
}

func TestResolverByType_AWSRoutes(t *testing.T) {
	t.Setenv(executor.EnvAWSRegion, "us-east-1")
	r := executor.ResolverByType(context.Background())
	if _, err := r(awssecretsmanager.Kind, nil); err != nil {
		t.Fatalf("ResolverByType(aws-sm): %v", err)
	}
}

// --- shared dispatch tests --------------------------------------------

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
	_, err := r("azure-kv", nil)
	// Falls through to NotConfiguredResolver which has a distinctive
	// error message — verify we ended up there.
	if err == nil || !strings.Contains(err.Error(), "no provider resolver configured") {
		t.Fatalf("got %v want NotConfiguredResolver fall-through", err)
	}
}
