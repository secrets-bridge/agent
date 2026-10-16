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
	t.Setenv(EnvAWSTagFilter, `{"EnvironmentName":"tenant-a-uat","Project":"project-alpha"}`)

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
	if parsed["EnvironmentName"] != "tenant-a-uat" || parsed["Project"] != "project-alpha" {
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

func TestMergeAWSConfig_PayloadTagFilterIsANDedWithEnv(t *testing.T) {
	// Discovery jobs may layer their own narrowing filter in the payload.
	// It is ANDed with the env filter; it never replaces it (AGT-N-03).
	t.Setenv(EnvAWSRegion, "us-east-1")
	t.Setenv(EnvAWSTagFilter, `{"EnvironmentName":"tenant-a-uat"}`)
	cfg, err := mergeAWSConfig(map[string]any{
		awssecretsmanager.ConfigTagFilter: map[string]any{
			"Project": "project-alpha",
		},
	})
	if err != nil {
		t.Fatalf("mergeAWSConfig: %v", err)
	}
	got, ok := cfg[awssecretsmanager.ConfigTagFilter].(map[string]string)
	if !ok || got["EnvironmentName"] != "tenant-a-uat" || got["Project"] != "project-alpha" || len(got) != 2 {
		t.Errorf("expected env AND payload filter, got %T %+v", cfg[awssecretsmanager.ConfigTagFilter], cfg[awssecretsmanager.ConfigTagFilter])
	}
}
