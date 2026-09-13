package executor

import (
	"strings"
	"testing"

	"github.com/secrets-bridge/core/providers/awssecretsmanager"
	"github.com/secrets-bridge/core/providers/vault"
)

// These tests exercise mergeVaultConfig / mergeAWSConfig directly (package
// executor, not executor_test) so they can assert the RESOLVED config —
// in particular that connection identity comes only from env and the
// kubernetes ServiceAccount token path is hard-pinned to the well-known
// mount, never taken from env or payload (AGT-01).

func TestMergeVaultConfig_K8sAuthHardPinsTokenPath(t *testing.T) {
	t.Setenv(EnvVaultAddr, "http://vault:8200")
	t.Setenv(EnvVaultKubernetesRole, "sb-agent")

	out, err := mergeVaultConfig(nil)
	if err != nil {
		t.Fatalf("mergeVaultConfig: %v", err)
	}
	if got := out[vault.ConfigAuthMethod]; got != "kubernetes" {
		t.Fatalf("authMethod = %v want kubernetes", got)
	}
	if got := out[vault.ConfigKubernetesTokenPath]; got != kubernetesSATokenPath {
		t.Fatalf("kubernetesTokenPath = %v want hard-pinned %q", got, kubernetesSATokenPath)
	}
}

// Even if an operator sets SB_VAULT env for the token path via some future
// var, the merged config must carry ONLY the hard-pinned constant. There
// is intentionally no env var for the token path, so this asserts the
// constant survives regardless of a payload attempt.
func TestMergeVaultConfig_PayloadCannotSetTokenPath(t *testing.T) {
	t.Setenv(EnvVaultAddr, "http://vault:8200")
	t.Setenv(EnvVaultKubernetesRole, "sb-agent")

	_, err := mergeVaultConfig(map[string]any{
		vault.ConfigKubernetesTokenPath: "/etc/attacker/token",
	})
	if err == nil || !strings.Contains(err.Error(), "connection-steering key") {
		t.Fatalf("got %v want steering refusal for payload token path", err)
	}
}

func TestMergeVaultConfig_TokenAuthDerivedFromEnv(t *testing.T) {
	t.Setenv(EnvVaultAddr, "http://vault:8200")
	t.Setenv(EnvVaultToken, "s.tok")

	out, err := mergeVaultConfig(map[string]any{vault.ConfigKVMount: "secret"})
	if err != nil {
		t.Fatalf("mergeVaultConfig: %v", err)
	}
	if out[vault.ConfigAuthMethod] != "token" {
		t.Fatalf("authMethod = %v want token", out[vault.ConfigAuthMethod])
	}
	// The allowlisted KV key survives; no token path is set for token auth.
	if out[vault.ConfigKVMount] != "secret" {
		t.Fatalf("kvMount = %v want secret", out[vault.ConfigKVMount])
	}
	if _, ok := out[vault.ConfigKubernetesTokenPath]; ok {
		t.Fatalf("token auth must not set a kubernetes token path")
	}
}

func TestMergeVaultConfig_EnvKVMountFallbackAndPayloadOverride(t *testing.T) {
	t.Setenv(EnvVaultAddr, "http://vault:8200")
	t.Setenv(EnvVaultToken, "s.tok")
	t.Setenv(EnvVaultKVMount, "env-mount")

	// No payload → env fallback.
	out, err := mergeVaultConfig(nil)
	if err != nil {
		t.Fatalf("mergeVaultConfig: %v", err)
	}
	if out[vault.ConfigKVMount] != "env-mount" {
		t.Fatalf("kvMount = %v want env-mount", out[vault.ConfigKVMount])
	}

	// Payload kvMount (a non-identity routing key) overrides the env.
	out, err = mergeVaultConfig(map[string]any{vault.ConfigKVMount: "payload-mount"})
	if err != nil {
		t.Fatalf("mergeVaultConfig: %v", err)
	}
	if out[vault.ConfigKVMount] != "payload-mount" {
		t.Fatalf("kvMount = %v want payload-mount", out[vault.ConfigKVMount])
	}
}

func TestMergeAWSConfig_IdentityFromEnvOnly(t *testing.T) {
	t.Setenv(EnvAWSRegion, "us-east-1")
	t.Setenv(EnvAWSRoleArn, "arn:aws:iam::123456789012:role/agent")
	t.Setenv(EnvAWSEndpoint, "http://localhost:4566")

	out, err := mergeAWSConfig(nil)
	if err != nil {
		t.Fatalf("mergeAWSConfig: %v", err)
	}
	if out[awssecretsmanager.ConfigRegion] != "us-east-1" {
		t.Fatalf("region = %v want us-east-1", out[awssecretsmanager.ConfigRegion])
	}
	if out[awssecretsmanager.ConfigRoleArn] != "arn:aws:iam::123456789012:role/agent" {
		t.Fatalf("roleArn not pinned from env: %v", out[awssecretsmanager.ConfigRoleArn])
	}
	if out[awssecretsmanager.ConfigEndpoint] != "http://localhost:4566" {
		t.Fatalf("endpoint not pinned from env: %v", out[awssecretsmanager.ConfigEndpoint])
	}
}
