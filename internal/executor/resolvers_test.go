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

func TestVaultResolver_TokenAuth_EnvAddress(t *testing.T) {
	// Address + token both from env — the only accepted source for
	// connection identity. Should construct without any HTTP calls.
	t.Setenv(executor.EnvVaultAddr, "http://localhost:8200")
	t.Setenv(executor.EnvVaultToken, "test-token")
	r := executor.VaultResolver(t.Context())
	p, err := r(vault.Kind, nil)
	if err != nil {
		t.Fatalf("VaultResolver: %v", err)
	}
	if p == nil {
		t.Fatal("provider is nil")
	}
}

func TestVaultResolver_KVMountFromPayloadAccepted(t *testing.T) {
	// kvMount/kvPrefix are per-request KV-layout keys, NOT connection
	// identity — they're the only keys the payload may carry.
	t.Setenv(executor.EnvVaultAddr, "http://localhost:8200")
	t.Setenv(executor.EnvVaultToken, "test-token")
	r := executor.VaultResolver(t.Context())
	if _, err := r(vault.Kind, map[string]any{
		vault.ConfigKVMount:  "secret",
		vault.ConfigKVPrefix: "billing",
	}); err != nil {
		t.Fatalf("VaultResolver: %v", err)
	}
}

// AGT-01: connection-steering keys must be refused in the job payload,
// not just credential literals. A requester-controlled address is an SSRF
// / exfil primitive.
func TestVaultResolver_PayloadAddressRefused(t *testing.T) {
	t.Setenv(executor.EnvVaultAddr, "http://envvar:8200")
	t.Setenv(executor.EnvVaultToken, "test-token")
	r := executor.VaultResolver(t.Context())
	_, err := r(vault.Kind, map[string]any{
		vault.ConfigAddress: "http://attacker.example:8200",
	})
	if err == nil || !strings.Contains(err.Error(), "connection-steering key") {
		t.Fatalf("got %v want refusal of payload address", err)
	}
}

// AGT-01: the full set of Vault connection-steering keys must be refused
// in the payload — address, namespace, authMethod, kubernetesRole,
// kubernetesMountPath, kubernetesTokenPath.
func TestVaultResolver_AllSteeringKeysRefused(t *testing.T) {
	t.Setenv(executor.EnvVaultAddr, "http://localhost:8200")
	t.Setenv(executor.EnvVaultToken, "test-token")
	r := executor.VaultResolver(t.Context())
	steering := []string{
		vault.ConfigAddress,
		vault.ConfigNamespace,
		vault.ConfigAuthMethod,
		vault.ConfigKubernetesRole,
		vault.ConfigKubernetesMountPath,
		vault.ConfigKubernetesTokenPath,
	}
	for _, k := range steering {
		t.Run(k, func(t *testing.T) {
			_, err := r(vault.Kind, map[string]any{k: "attacker-controlled"})
			if err == nil || !strings.Contains(err.Error(), "connection-steering key") {
				t.Fatalf("payload key %q: got %v want steering refusal", k, err)
			}
		})
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

// AGT-01: an unrecognised payload key is refused too, so a new steering
// key added to core can't silently pass through.
func TestVaultResolver_UnknownPayloadKeyRefused(t *testing.T) {
	t.Setenv(executor.EnvVaultAddr, "http://localhost:8200")
	t.Setenv(executor.EnvVaultToken, "test-token")
	r := executor.VaultResolver(t.Context())
	_, err := r(vault.Kind, map[string]any{"someFutureConnectionKey": "x"})
	if err == nil || !strings.Contains(err.Error(), "not accepted in the job payload") {
		t.Fatalf("got %v want refusal of unknown payload key", err)
	}
}

func TestVaultResolver_MissingAddress(t *testing.T) {
	// Token via env, but no address anywhere → error.
	t.Setenv(executor.EnvVaultToken, "test-token")
	r := executor.VaultResolver(t.Context())
	_, err := r(vault.Kind, nil)
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

// AGT-01: region is connection identity — it must be pinned from env,
// never accepted from the payload.
func TestAWSResolver_RegionInPayloadRefused(t *testing.T) {
	t.Setenv(executor.EnvAWSRegion, "us-east-1")
	r := executor.AWSSecretsManagerResolver(t.Context())
	_, err := r(awssecretsmanager.Kind, map[string]any{
		awssecretsmanager.ConfigRegion: "eu-west-1",
	})
	if err == nil || !strings.Contains(err.Error(), "connection-steering key") {
		t.Fatalf("got %v want refusal of payload region", err)
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

// AGT-01: endpoint + roleArn are connection identity — refused in the
// payload. endpoint pins from SB_AWS_ENDPOINT, roleArn from SB_AWS_ROLE_ARN.
func TestAWSResolver_EndpointAndRoleArnInPayloadRefused(t *testing.T) {
	t.Setenv(executor.EnvAWSRegion, "us-east-1")
	r := executor.AWSSecretsManagerResolver(t.Context())
	for _, k := range []string{awssecretsmanager.ConfigEndpoint, awssecretsmanager.ConfigRoleArn} {
		t.Run(k, func(t *testing.T) {
			_, err := r(awssecretsmanager.Kind, map[string]any{k: "attacker-controlled"})
			if err == nil || !strings.Contains(err.Error(), "connection-steering key") {
				t.Fatalf("payload key %q: got %v want steering refusal", k, err)
			}
		})
	}
}

// AGT-01: connection identity pins from env; endpoint + roleArn from
// SB_AWS_* env vars are accepted and produce a usable provider.
func TestAWSResolver_EndpointAndRoleArnFromEnvAccepted(t *testing.T) {
	t.Setenv(executor.EnvAWSRegion, "us-east-1")
	t.Setenv(executor.EnvAWSEndpoint, "http://localhost:4566")
	t.Setenv(executor.EnvAWSRoleArn, "arn:aws:iam::123456789012:role/tenant")
	r := executor.AWSSecretsManagerResolver(t.Context())
	if _, err := r(awssecretsmanager.Kind, nil); err != nil {
		t.Fatalf("AWSResolver: %v", err)
	}
}

// AGT-01: any unrecognised payload key is refused for aws-sm — the target
// secret travels in target_secret_ref, not target_provider_config.
func TestAWSResolver_UnknownPayloadKeyRefused(t *testing.T) {
	t.Setenv(executor.EnvAWSRegion, "us-east-1")
	r := executor.AWSSecretsManagerResolver(t.Context())
	_, err := r(awssecretsmanager.Kind, map[string]any{"someFutureKey": "x"})
	if err == nil || !strings.Contains(err.Error(), "not accepted in the job payload") {
		t.Fatalf("got %v want refusal of unknown payload key", err)
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
