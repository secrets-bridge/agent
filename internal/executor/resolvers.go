// Package executor — resolvers.go: concrete provider resolvers.
//
// Each resolver translates the `target_provider_config` map embedded
// in a patch job's payload (plus agent-level env vars for sensitive
// connection material like Vault tokens) into a fully constructed
// core/providers.Provider.
//
// The split between job-payload config and agent env vars is
// deliberate:
//
//   - Connection ADDRESSES (vault URL, AWS region) come from the job
//     payload — they're metadata, not sensitive, and they vary per
//     request.
//   - AUTH CREDENTIALS (vault token, AWS keys) come from agent env
//     vars or in-cluster identity (k8s auth, instance role). The
//     job payload MUST NOT carry credentials — that's a hard rule.
package executor

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/secrets-bridge/core/providers"
	"github.com/secrets-bridge/core/providers/vault"
)

// Env vars the Vault resolver consults when the job-payload config
// doesn't carry a connection address or token. Documented here in one
// place so the helm chart / k8s manifests can mirror them.
const (
	EnvVaultAddr           = "SB_VAULT_ADDR"
	EnvVaultToken          = "SB_VAULT_TOKEN"
	EnvVaultNamespace      = "SB_VAULT_NAMESPACE"
	EnvVaultKVMount        = "SB_VAULT_KV_MOUNT"
	EnvVaultKVPrefix       = "SB_VAULT_KV_PREFIX"
	EnvVaultKubernetesRole = "SB_VAULT_KUBERNETES_ROLE"
)

// VaultResolver implements ProviderResolver for providerType="vault".
//
// Config precedence (highest → lowest):
//  1. job payload `target_provider_config`
//  2. agent process env vars (SB_VAULT_*)
//  3. provider defaults (kv mount=kv, k8s auth method)
//
// Auth selection:
//   - If `token` is set (in payload OR SB_VAULT_TOKEN), use token auth
//   - Else if SB_VAULT_KUBERNETES_ROLE is set (or payload kubernetesRole),
//     use k8s auth
//   - Else error — no auth configured
func VaultResolver(ctx context.Context) ProviderResolver {
	return func(providerType string, config map[string]any) (providers.Provider, error) {
		if providerType != vault.Kind {
			return nil, fmt.Errorf("vault resolver received providerType=%q", providerType)
		}
		merged, err := mergeVaultConfig(config)
		if err != nil {
			return nil, err
		}
		return vault.New(ctx, merged)
	}
}

func mergeVaultConfig(payload map[string]any) (providers.Config, error) {
	out := providers.Config{}

	// Start with env-var fallbacks; payload values override.
	setIfEnv := func(key, env string) {
		if v := os.Getenv(env); v != "" {
			out[key] = v
		}
	}
	setIfEnv(vault.ConfigAddress, EnvVaultAddr)
	setIfEnv(vault.ConfigToken, EnvVaultToken)
	setIfEnv(vault.ConfigNamespace, EnvVaultNamespace)
	setIfEnv(vault.ConfigKVMount, EnvVaultKVMount)
	setIfEnv(vault.ConfigKVPrefix, EnvVaultKVPrefix)
	setIfEnv(vault.ConfigKubernetesRole, EnvVaultKubernetesRole)

	for k, v := range payload {
		// Refuse credential keys in the payload — the api should never
		// be sending us a vault token. Defense in depth in case a
		// future PR forgets this rule.
		if k == vault.ConfigToken {
			return nil, errors.New("vault: token MUST NOT be passed via job payload (use agent env var)")
		}
		out[k] = v
	}

	// Pick auth method based on what's present. Vault's New() defaults
	// to kubernetes auth when the key is absent, which is wrong for
	// dev / token use — set it explicitly here so the behavior is
	// predictable.
	if _, hasMethod := out[vault.ConfigAuthMethod]; !hasMethod {
		if _, hasToken := out[vault.ConfigToken]; hasToken {
			out[vault.ConfigAuthMethod] = "token"
		} else if _, hasRole := out[vault.ConfigKubernetesRole]; hasRole {
			out[vault.ConfigAuthMethod] = "kubernetes"
		} else {
			return nil, errors.New("vault: no auth configured — set SB_VAULT_TOKEN or SB_VAULT_KUBERNETES_ROLE")
		}
	}

	if _, ok := out[vault.ConfigAddress]; !ok {
		return nil, errors.New("vault: address not configured — set SB_VAULT_ADDR or payload.target_provider_config.address")
	}
	return out, nil
}

// ResolverByType builds a ProviderResolver that dispatches on
// providerType. Currently registers `vault`; AWS Secrets Manager and
// the other providers slot in here as they're added. Unknown types
// fall back to NotConfiguredResolver so jobs fail loud rather than
// silently no-op.
func ResolverByType(ctx context.Context) ProviderResolver {
	resolvers := map[string]ProviderResolver{
		vault.Kind: VaultResolver(ctx),
	}
	return func(providerType string, config map[string]any) (providers.Provider, error) {
		if r, ok := resolvers[providerType]; ok {
			return r(providerType, config)
		}
		return NotConfiguredResolver(providerType, config)
	}
}
