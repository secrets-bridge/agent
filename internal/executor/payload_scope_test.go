package executor

import (
	"strings"
	"testing"

	"github.com/secrets-bridge/core/providers/awssecretsmanager"
	"github.com/secrets-bridge/core/providers/vault"
)

// AGT-N-01: a job payload must never move the agent to a different Vault
// mount or prefix. kvMount/kvPrefix are accepted only as an echo of the
// agent's own pinned value; anything else fails the job.

func vaultTokenEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvVaultAddr, "http://vault.example.com:8200")
	t.Setenv(EnvVaultToken, "test-token")
}

func TestMergeVaultConfig_PayloadKVMountOverrideRefused(t *testing.T) {
	vaultTokenEnv(t)
	t.Setenv(EnvVaultKVMount, "team-a-kv")

	for _, mount := range []string{"other-kv", "../other-kv", ""} {
		t.Run(mount, func(t *testing.T) {
			_, err := mergeVaultConfig(map[string]any{vault.ConfigKVMount: mount})
			if err == nil {
				t.Fatalf("payload kvMount %q was accepted; it must not change the pinned mount", mount)
			}
			if strings.Contains(err.Error(), mount) && mount != "" {
				t.Fatalf("error echoes the payload value: %v", err)
			}
		})
	}
}

func TestMergeVaultConfig_PayloadKVMountRefusedWhenEnvUnset(t *testing.T) {
	// With SB_VAULT_KV_MOUNT unset the agent is pinned to core's default
	// mount ("kv"); a payload naming another mount is still a widening.
	vaultTokenEnv(t)
	_, err := mergeVaultConfig(map[string]any{vault.ConfigKVMount: "other-kv"})
	if err == nil {
		t.Fatal("payload kvMount accepted while the agent has no SB_VAULT_KV_MOUNT; the default mount must stay pinned")
	}
}

func TestMergeVaultConfig_PayloadKVPrefixTraversalRefused(t *testing.T) {
	vaultTokenEnv(t)
	t.Setenv(EnvVaultKVPrefix, "team-a")

	for _, prefix := range []string{"../../other-kv/data/team-b", "team-b", "team-a/../team-b", ""} {
		t.Run(prefix, func(t *testing.T) {
			_, err := mergeVaultConfig(map[string]any{vault.ConfigKVPrefix: prefix})
			if err == nil {
				t.Fatalf("payload kvPrefix %q was accepted; it must not change the pinned prefix", prefix)
			}
		})
	}
}

func TestMergeVaultConfig_PayloadKVPrefixRefusedWhenEnvUnset(t *testing.T) {
	vaultTokenEnv(t)
	_, err := mergeVaultConfig(map[string]any{vault.ConfigKVPrefix: "../../other-kv/data/team-b"})
	if err == nil {
		t.Fatal("payload kvPrefix accepted while the agent has no SB_VAULT_KV_PREFIX")
	}
}

func TestMergeVaultConfig_PayloadKVNonStringRefused(t *testing.T) {
	vaultTokenEnv(t)
	t.Setenv(EnvVaultKVMount, "kv")
	for _, v := range []any{42, nil, map[string]any{"x": "y"}} {
		if _, err := mergeVaultConfig(map[string]any{vault.ConfigKVMount: v}); err == nil {
			t.Fatalf("non-string payload kvMount %T accepted", v)
		}
	}
}

// A legit job either omits the keys or echoes the agent's own values (the
// UI sends kvMount, a provider-connection scope may send kvPrefix).
func TestMergeVaultConfig_LegitPayloadsStillWork(t *testing.T) {
	vaultTokenEnv(t)
	t.Setenv(EnvVaultKVMount, "secret")
	t.Setenv(EnvVaultKVPrefix, "team-a")

	cases := map[string]map[string]any{
		"no payload":    nil,
		"empty payload": {},
		"echo mount":    {vault.ConfigKVMount: "secret"},
		"echo both":     {vault.ConfigKVMount: "secret", vault.ConfigKVPrefix: "team-a"},
		"echo slashes":  {vault.ConfigKVMount: "/secret/", vault.ConfigKVPrefix: "team-a/"},
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := mergeVaultConfig(payload)
			if err != nil {
				t.Fatalf("legit payload refused: %v", err)
			}
			if out[vault.ConfigKVMount] != "secret" || out[vault.ConfigKVPrefix] != "team-a" {
				t.Fatalf("resolved mount/prefix = %v/%v want secret/team-a",
					out[vault.ConfigKVMount], out[vault.ConfigKVPrefix])
			}
		})
	}
}

func TestMergeVaultConfig_DefaultMountPinnedWhenEnvUnset(t *testing.T) {
	vaultTokenEnv(t)
	out, err := mergeVaultConfig(map[string]any{vault.ConfigKVMount: "kv"})
	if err != nil {
		t.Fatalf("echo of the default mount refused: %v", err)
	}
	if out[vault.ConfigKVMount] != "kv" {
		t.Fatalf("kvMount = %v want the pinned default kv", out[vault.ConfigKVMount])
	}
	if _, ok := out[vault.ConfigKVPrefix]; ok {
		t.Fatalf("kvPrefix set without SB_VAULT_KV_PREFIX: %v", out[vault.ConfigKVPrefix])
	}
}

// AGT-N-03: a payload tagFilter can only add constraints on top of
// SB_AWS_TAG_FILTER. It can't replace it, clear it, or contradict it.

func tagFilterOf(t *testing.T, cfg map[string]any) map[string]string {
	t.Helper()
	raw, ok := cfg[awssecretsmanager.ConfigTagFilter]
	if !ok {
		return nil
	}
	switch m := raw.(type) {
	case map[string]string:
		return m
	case map[string]any:
		out := map[string]string{}
		for k, v := range m {
			s, _ := v.(string)
			out[k] = s
		}
		return out
	default:
		t.Fatalf("tagFilter has type %T", raw)
		return nil
	}
}

func TestMergeAWSConfig_PayloadTagFilterCannotClearEnv(t *testing.T) {
	t.Setenv(EnvAWSRegion, "us-east-1")
	t.Setenv(EnvAWSTagFilter, `{"EnvironmentName":"tenant-a-uat"}`)

	for name, pf := range map[string]any{
		"empty map":        map[string]any{},
		"empty typed map":  map[string]string{},
		"unrelated narrow": map[string]any{"Project": "project-alpha"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := mergeAWSConfig(map[string]any{awssecretsmanager.ConfigTagFilter: pf})
			if err != nil {
				t.Fatalf("mergeAWSConfig: %v", err)
			}
			got := tagFilterOf(t, cfg)
			if got["EnvironmentName"] != "tenant-a-uat" {
				t.Fatalf("env tag filter dropped by payload: %v", got)
			}
		})
	}
}

func TestMergeAWSConfig_PayloadTagFilterNarrowsEnv(t *testing.T) {
	t.Setenv(EnvAWSRegion, "us-east-1")
	t.Setenv(EnvAWSTagFilter, `{"EnvironmentName":"tenant-a-uat"}`)
	cfg, err := mergeAWSConfig(map[string]any{
		awssecretsmanager.ConfigTagFilter: map[string]any{"Project": "project-alpha"},
	})
	if err != nil {
		t.Fatalf("mergeAWSConfig: %v", err)
	}
	got := tagFilterOf(t, cfg)
	if len(got) != 2 || got["EnvironmentName"] != "tenant-a-uat" || got["Project"] != "project-alpha" {
		t.Fatalf("tagFilter = %v want env AND payload", got)
	}
}

func TestMergeAWSConfig_PayloadTagFilterConflictRefused(t *testing.T) {
	t.Setenv(EnvAWSRegion, "us-east-1")
	t.Setenv(EnvAWSTagFilter, `{"EnvironmentName":"tenant-a-uat"}`)
	_, err := mergeAWSConfig(map[string]any{
		awssecretsmanager.ConfigTagFilter: map[string]any{"EnvironmentName": "tenant-b-prod"},
	})
	if err == nil {
		t.Fatal("payload tagFilter that contradicts SB_AWS_TAG_FILTER was accepted")
	}
	if strings.Contains(err.Error(), "tenant-b-prod") {
		t.Fatalf("error echoes the payload value: %v", err)
	}
}

func TestMergeAWSConfig_PayloadTagFilterEchoAccepted(t *testing.T) {
	t.Setenv(EnvAWSRegion, "us-east-1")
	t.Setenv(EnvAWSTagFilter, `{"EnvironmentName":"tenant-a-uat"}`)
	cfg, err := mergeAWSConfig(map[string]any{
		awssecretsmanager.ConfigTagFilter: map[string]any{"EnvironmentName": "tenant-a-uat"},
	})
	if err != nil {
		t.Fatalf("echo of the env filter refused: %v", err)
	}
	if got := tagFilterOf(t, cfg); len(got) != 1 || got["EnvironmentName"] != "tenant-a-uat" {
		t.Fatalf("tagFilter = %v", got)
	}
}

func TestMergeAWSConfig_PayloadTagFilterMalformedRefused(t *testing.T) {
	t.Setenv(EnvAWSRegion, "us-east-1")
	t.Setenv(EnvAWSTagFilter, `{"EnvironmentName":"tenant-a-uat"}`)
	for name, pf := range map[string]any{
		"string":           "EnvironmentName=tenant-b-prod",
		"non-string value": map[string]any{"Project": 7},
		"null":             nil,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := mergeAWSConfig(map[string]any{awssecretsmanager.ConfigTagFilter: pf}); err == nil {
				t.Fatalf("malformed payload tagFilter %T accepted", pf)
			}
		})
	}
}

func TestMergeAWSConfig_PayloadTagFilterWithoutEnv(t *testing.T) {
	// No env filter: the payload filter still applies (it can only narrow
	// what the IAM role can already enumerate).
	t.Setenv(EnvAWSRegion, "us-east-1")
	cfg, err := mergeAWSConfig(map[string]any{
		awssecretsmanager.ConfigTagFilter: map[string]any{"Project": "project-alpha"},
	})
	if err != nil {
		t.Fatalf("mergeAWSConfig: %v", err)
	}
	if got := tagFilterOf(t, cfg); got["Project"] != "project-alpha" {
		t.Fatalf("tagFilter = %v", got)
	}

	// An empty payload map with no env filter means no filter at all.
	cfg, err = mergeAWSConfig(map[string]any{awssecretsmanager.ConfigTagFilter: map[string]any{}})
	if err != nil {
		t.Fatalf("mergeAWSConfig: %v", err)
	}
	if _, ok := cfg[awssecretsmanager.ConfigTagFilter]; ok {
		t.Fatalf("empty filters produced a tagFilter key: %v", cfg[awssecretsmanager.ConfigTagFilter])
	}
}
