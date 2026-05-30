package executor

import (
	"strings"
	"testing"

	"github.com/secrets-bridge/core/providers/awssecretsmanager"
)

// Internal test — needs to inspect the merged providers.Config that
// mergeAWSConfig builds, which is unexported. Lives in package executor
// (not executor_test) so we can call the helper directly.

func TestMergeAWSConfig_TagFilterFromEnv(t *testing.T) {
	t.Setenv(EnvAWSRegion, "us-east-1")
	t.Setenv(EnvAWSTagFilter, `{"EnvironmentName":"E-Government-Uat","Project":"Pension"}`)

	cfg, err := mergeAWSConfig(nil)
	if err != nil {
		t.Fatalf("mergeAWSConfig: %v", err)
	}
	raw, ok := cfg[awssecretsmanager.ConfigTagFilter]
	if !ok {
		t.Fatalf("expected Config[%q] to be set", awssecretsmanager.ConfigTagFilter)
	}
	parsed, ok := raw.(map[string]string)
	if !ok {
		t.Fatalf("expected map[string]string, got %T", raw)
	}
	if parsed["EnvironmentName"] != "E-Government-Uat" || parsed["Project"] != "Pension" {
		t.Errorf("unexpected tagFilter: %+v", parsed)
	}
}

func TestMergeAWSConfig_TagFilterEmptyEnvIsAbsent(t *testing.T) {
	t.Setenv(EnvAWSRegion, "us-east-1")
	// EnvAWSTagFilter unset.
	cfg, err := mergeAWSConfig(nil)
	if err != nil {
		t.Fatalf("mergeAWSConfig: %v", err)
	}
	if _, ok := cfg[awssecretsmanager.ConfigTagFilter]; ok {
		t.Fatal("expected no tagFilter key when env is unset")
	}
}

func TestMergeAWSConfig_TagFilterEmptyJSONObjectIsAbsent(t *testing.T) {
	t.Setenv(EnvAWSRegion, "us-east-1")
	t.Setenv(EnvAWSTagFilter, `{}`)
	cfg, err := mergeAWSConfig(nil)
	if err != nil {
		t.Fatalf("mergeAWSConfig: %v", err)
	}
	if _, ok := cfg[awssecretsmanager.ConfigTagFilter]; ok {
		t.Fatal("expected no tagFilter key when env is an empty JSON object")
	}
}

func TestMergeAWSConfig_TagFilterBadJSONFailsLoud(t *testing.T) {
	t.Setenv(EnvAWSRegion, "us-east-1")
	t.Setenv(EnvAWSTagFilter, `not-json`)
	_, err := mergeAWSConfig(nil)
	if err == nil {
		t.Fatal("expected error on malformed SB_AWS_TAG_FILTER, got nil")
	}
	if !strings.Contains(err.Error(), EnvAWSTagFilter) {
		t.Errorf("error should name the env var: %v", err)
	}
}

func TestMergeAWSConfig_PayloadTagFilterOverridesEnv(t *testing.T) {
	// Discovery jobs may layer their own narrowing filter in the
	// payload. Payload wins per the documented precedence; the
	// provider AND's both filters internally.
	t.Setenv(EnvAWSRegion, "us-east-1")
	t.Setenv(EnvAWSTagFilter, `{"EnvironmentName":"E-Government-Uat"}`)
	cfg, err := mergeAWSConfig(map[string]any{
		awssecretsmanager.ConfigTagFilter: map[string]any{
			"Project": "Pension",
		},
	})
	if err != nil {
		t.Fatalf("mergeAWSConfig: %v", err)
	}
	got := cfg[awssecretsmanager.ConfigTagFilter]
	if m, ok := got.(map[string]any); !ok || m["Project"] != "Pension" {
		t.Errorf("expected payload to override env, got %T %+v", got, got)
	}
}
