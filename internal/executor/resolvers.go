// Package executor — resolvers.go: concrete provider resolvers.
//
// Each resolver translates the `target_provider_config` map embedded
// in a patch job's payload into a fully constructed
// core/providers.Provider, combined with agent-level connection identity.
//
// Trust boundary (AGT-01 hardening):
//
//   - CONNECTION IDENTITY — where the agent connects (vault address, AWS
//     region/endpoint) and as whom it connects (roleArn, kubernetes
//     role/mount/token path, auth method) — is PINNED from agent env or
//     a vetted local source. It is NEVER read from the job payload. A
//     requester who could steer these turns the agent into an SSRF,
//     arbitrary-file-read, and credential-exfil primitive.
//   - AUTH CREDENTIALS (vault token, AWS keys) come from agent env vars
//     or in-cluster identity (k8s auth, instance role). The job payload
//     MUST NOT carry credentials — that's a hard rule.
//   - The job payload may carry ONLY a small allowlist of non-identity,
//     per-request routing keys (e.g. Vault kvMount/kvPrefix). Every other
//     key — connection-steering, credential, or unrecognised — is
//     refused so the job fails loud rather than silently connecting
//     somewhere the requester chose.
package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/secrets-bridge/core/providers"
	"github.com/secrets-bridge/core/providers/awssecretsmanager"
	"github.com/secrets-bridge/core/providers/vault"
)

// Env vars the Vault resolver consults for connection identity. These
// are the ONLY source for connection-steering material — the job payload
// can never override them. Documented here in one place so the helm
// chart / k8s manifests can mirror them.
const (
	EnvVaultAddr                = "SB_VAULT_ADDR"
	EnvVaultToken               = "SB_VAULT_TOKEN"
	EnvVaultNamespace           = "SB_VAULT_NAMESPACE"
	EnvVaultKVMount             = "SB_VAULT_KV_MOUNT"
	EnvVaultKVPrefix            = "SB_VAULT_KV_PREFIX"
	EnvVaultKubernetesRole      = "SB_VAULT_KUBERNETES_ROLE"
	EnvVaultKubernetesMountPath = "SB_VAULT_KUBERNETES_MOUNT_PATH"
)

// kubernetesSATokenPath is the projected ServiceAccount token path the
// agent hard-pins for Vault kubernetes auth. It is NEVER taken from the
// job payload OR an env var: a requester- (or operator-) controlled token
// path would let the agent be pointed at an arbitrary local file, read
// it, and POST its contents to Vault during login — the AGT-01
// arbitrary-file-read / credential-exfil primitive. The standard
// projected-token mount is the only vetted source.
const kubernetesSATokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // not a credential; a well-known mount path

// vaultSteeringKeys identify WHERE and as WHOM the agent connects. They
// are pinned from agent env and MUST NOT appear in the job payload
// (AGT-01). The credential literal (token) is refused separately with a
// dedicated message.
var vaultSteeringKeys = map[string]struct{}{
	vault.ConfigAddress:             {},
	vault.ConfigNamespace:           {},
	vault.ConfigAuthMethod:          {},
	vault.ConfigKubernetesRole:      {},
	vault.ConfigKubernetesMountPath: {},
	vault.ConfigKubernetesTokenPath: {},
}

// vaultPayloadAllowlist are the ONLY keys a job payload may carry for the
// Vault resolver. They select the KV path layout of the TARGET secret —
// not the connection identity — so they're safe to vary per request.
// Any key outside this set is refused.
var vaultPayloadAllowlist = map[string]struct{}{
	vault.ConfigKVMount:  {},
	vault.ConfigKVPrefix: {},
}

// Env vars the AWS Secrets Manager resolver consults. Credentials
// themselves come from the standard AWS SDK chain (env vars like
// AWS_ACCESS_KEY_ID / AWS_SESSION_TOKEN, shared config, IRSA, instance
// role) — secrets-bridge does NOT introduce new credential env vars.
// SB_AWS_* exists only for the non-credential knobs (region, endpoint,
// optional assume-role).
const (
	EnvAWSRegion   = "SB_AWS_REGION"
	EnvAWSRoleArn  = "SB_AWS_ROLE_ARN"
	EnvAWSEndpoint = "SB_AWS_ENDPOINT" // LocalStack / VPC endpoint override
	// EnvAWSTagFilter is a JSON object of {tag: value} pairs. Every AWS
	// tag listed MUST be present (with the same value) on a secret for
	// it to survive ListMetadata filtering. Intended for "this agent is
	// locked to environment X" — paired with the IAM tag condition on
	// the read side for defense in depth. Empty/unset = no filter.
	EnvAWSTagFilter = "SB_AWS_TAG_FILTER"
)

// VaultResolver implements ProviderResolver for providerType="vault".
//
// Connection identity (address, namespace, auth method, kubernetes
// role/mount/token path) comes ONLY from agent env vars (SB_VAULT_*).
// The job payload may carry ONLY the KV routing keys in
// vaultPayloadAllowlist (kvMount/kvPrefix). Any other payload key —
// including any connection-steering key or the token literal — is
// refused (AGT-01).
//
// Auth selection (driven entirely by the PINNED env config):
//   - If SB_VAULT_TOKEN is set, use token auth.
//   - Else if SB_VAULT_KUBERNETES_ROLE is set, use k8s auth with the
//     hard-pinned ServiceAccount token path.
//   - Else error — no auth configured.
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

	// Connection identity + credential: pinned from agent env ONLY. The
	// payload can never steer any of these (AGT-01).
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
	setIfEnv(vault.ConfigKubernetesMountPath, EnvVaultKubernetesMountPath)

	// Validate + apply the payload. Only the vetted, non-identity keys
	// in vaultPayloadAllowlist are accepted (they may override the env
	// KV-layout fallbacks); credential literals and connection-steering
	// keys are refused, and anything unrecognised is refused too so a
	// new steering key added to core can't silently pass through.
	for k, v := range payload {
		switch {
		case k == vault.ConfigToken:
			return nil, errors.New("vault: token MUST NOT be passed via job payload (use agent env var)")
		case isKey(vaultSteeringKeys, k):
			return nil, fmt.Errorf("vault: connection-steering key %q MUST NOT be passed via job payload (pinned from agent env)", k)
		case isKey(vaultPayloadAllowlist, k):
			out[k] = v
		default:
			return nil, fmt.Errorf("vault: key %q is not accepted in the job payload", k)
		}
	}

	// Auth method is derived entirely from the PINNED env config, never
	// the payload. Vault's New() defaults to kubernetes auth when the key
	// is absent, so set it explicitly for predictable behavior.
	switch {
	case hasKey(out, vault.ConfigToken):
		out[vault.ConfigAuthMethod] = "token"
	case hasKey(out, vault.ConfigKubernetesRole):
		out[vault.ConfigAuthMethod] = "kubernetes"
		// Hard-pin the ServiceAccount token path — never env, never
		// payload — so the agent can only ever read the well-known
		// projected-token mount during login (AGT-01).
		out[vault.ConfigKubernetesTokenPath] = kubernetesSATokenPath
	default:
		return nil, errors.New("vault: no auth configured — set SB_VAULT_TOKEN or SB_VAULT_KUBERNETES_ROLE")
	}

	if !hasKey(out, vault.ConfigAddress) {
		return nil, errors.New("vault: address not configured — set SB_VAULT_ADDR")
	}
	return out, nil
}

// isKey reports whether k is present in set.
func isKey(set map[string]struct{}, k string) bool {
	_, ok := set[k]
	return ok
}

// hasKey reports whether the resolved config carries key k.
func hasKey(c providers.Config, k string) bool {
	_, ok := c[k]
	return ok
}

// AWSSecretsManagerResolver implements ProviderResolver for
// providerType="aws-sm".
//
// Connection identity (region, endpoint, roleArn) comes ONLY from agent
// env vars (SB_AWS_*). The job payload may carry ONLY the narrowing
// ListMetadata tagFilter (awsPayloadAllowlist); any other key —
// credential, connection-steering, or unrecognised — is refused (AGT-01).
//
// Credentials are NEVER passed via this resolver: the underlying
// core/providers/awssecretsmanager provider relies on the AWS SDK's
// default credential chain (env vars, shared config, IRSA, instance
// role). Operators wire whichever credential source matches their
// deployment posture; the agent doesn't model auth.
func AWSSecretsManagerResolver(ctx context.Context) ProviderResolver {
	return func(providerType string, config map[string]any) (providers.Provider, error) {
		if providerType != awssecretsmanager.Kind {
			return nil, fmt.Errorf("aws-sm resolver received providerType=%q", providerType)
		}
		merged, err := mergeAWSConfig(config)
		if err != nil {
			return nil, err
		}
		return awssecretsmanager.New(ctx, merged)
	}
}

// awsCredentialKeys are credential-looking keys the resolver REFUSES in
// the job payload — credentials must never travel from the CP to the
// agent over the wire. Defense in depth.
var awsCredentialKeys = map[string]struct{}{
	"awsAccessKeyID":     {},
	"awsSecretAccessKey": {},
	"awsSessionToken":    {},
	"accessKeyID":        {},
	"secretAccessKey":    {},
	"sessionToken":       {},
	"credentials":        {},
}

// awsSteeringKeys identify WHERE and as WHOM the agent connects. They are
// pinned from agent env (SB_AWS_*) and MUST NOT appear in the job payload
// (AGT-01).
var awsSteeringKeys = map[string]struct{}{
	awssecretsmanager.ConfigRegion:   {},
	awssecretsmanager.ConfigRoleArn:  {},
	awssecretsmanager.ConfigEndpoint: {},
}

// awsPayloadAllowlist are the ONLY keys a job payload may carry for the
// aws-sm resolver. tagFilter is a ListMetadata NARROWING filter (used by
// admin-enqueued discover jobs), not connection identity — it selects
// which secrets are visible, not where/as-whom the agent connects. Every
// other payload key — credential, steering, or unrecognised — is refused.
var awsPayloadAllowlist = map[string]struct{}{
	awssecretsmanager.ConfigTagFilter: {},
}

func mergeAWSConfig(payload map[string]any) (providers.Config, error) {
	out := providers.Config{}

	setIfEnv := func(key, env string) {
		if v := os.Getenv(env); v != "" {
			out[key] = v
		}
	}
	setIfEnv(awssecretsmanager.ConfigRegion, EnvAWSRegion)
	setIfEnv(awssecretsmanager.ConfigRoleArn, EnvAWSRoleArn)
	setIfEnv(awssecretsmanager.ConfigEndpoint, EnvAWSEndpoint)

	// SB_AWS_TAG_FILTER is JSON-encoded (e.g.
	// `{"EnvironmentName":"tenant-a-uat"}`). Parse loudly so a typo
	// in chart values doesn't silently disable the safety net.
	if raw := os.Getenv(EnvAWSTagFilter); raw != "" {
		var parsed map[string]string
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			return nil, fmt.Errorf("aws-sm: %s must be a JSON object of {tag: value} pairs: %w", EnvAWSTagFilter, err)
		}
		if len(parsed) > 0 {
			out[awssecretsmanager.ConfigTagFilter] = parsed
		}
	}

	// Validate + apply the payload. Only the vetted, non-identity keys in
	// awsPayloadAllowlist are accepted; credential literals and
	// connection-steering keys are refused, and anything unrecognised is
	// refused too so a new steering key added to core can't silently pass
	// through (AGT-01).
	for k, v := range payload {
		switch {
		case isKey(awsCredentialKeys, k):
			return nil, fmt.Errorf("aws-sm: %q MUST NOT be passed via job payload (use SDK credential chain)", k)
		case isKey(awsSteeringKeys, k):
			return nil, fmt.Errorf("aws-sm: connection-steering key %q MUST NOT be passed via job payload (pinned from agent env)", k)
		case isKey(awsPayloadAllowlist, k):
			out[k] = v
		default:
			return nil, fmt.Errorf("aws-sm: key %q is not accepted in the job payload", k)
		}
	}

	if !hasKey(out, awssecretsmanager.ConfigRegion) {
		return nil, errors.New("aws-sm: region not configured — set SB_AWS_REGION")
	}
	return out, nil
}

// ResolverByType builds a ProviderResolver that dispatches on
// providerType. Registers vault and aws-sm; the other providers slot
// in here as they're added. Unknown types fall back to
// NotConfiguredResolver so jobs fail loud rather than silently no-op.
func ResolverByType(ctx context.Context) ProviderResolver {
	resolvers := map[string]ProviderResolver{
		vault.Kind:             VaultResolver(ctx),
		awssecretsmanager.Kind: AWSSecretsManagerResolver(ctx),
	}
	return func(providerType string, config map[string]any) (providers.Provider, error) {
		if r, ok := resolvers[providerType]; ok {
			return r(providerType, config)
		}
		return NotConfiguredResolver(providerType, config)
	}
}
