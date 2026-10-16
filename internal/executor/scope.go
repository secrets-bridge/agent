package executor

// scope.go: the job payload must never widen what the agent can reach in
// its provider (AGT-N-01). For Vault the reach is the KV mount + prefix the
// operator pinned in agent env. A payload may echo those values (the UI
// sends kvMount, a provider-connection scope can carry kvPrefix) but any
// value that differs, a secret ref that climbs out with "..", or a
// discover scope outside the prefix fails the job before Vault is called.

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/secrets-bridge/core/providers/vault"
)

// defaultVaultKVMount mirrors core/providers/vault's default mount. The
// agent pins it explicitly so an unset SB_VAULT_KV_MOUNT still means one
// known mount, not "whatever the payload says".
const defaultVaultKVMount = "kv"

// pinnedVaultKVMount is the KV v2 mount this agent is allowed to use.
func pinnedVaultKVMount() string {
	if m := strings.Trim(os.Getenv(EnvVaultKVMount), "/"); m != "" {
		return m
	}
	return defaultVaultKVMount
}

// pinnedVaultKVPrefix is the path prefix every ref is joined under ("" =
// the whole mount).
func pinnedVaultKVPrefix() string {
	return strings.Trim(os.Getenv(EnvVaultKVPrefix), "/")
}

// requireVaultKVEcho accepts a payload kvMount/kvPrefix only when it names
// the agent's own pinned value. The error is value-free on purpose: it says
// which key, never what either side holds.
func requireVaultKVEcho(key string, v any) error {
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("vault: payload %q must be a string", key)
	}
	pinned := pinnedVaultKVPrefix()
	if key == vault.ConfigKVMount {
		pinned = pinnedVaultKVMount()
	}
	if strings.Trim(s, "/") != pinned {
		return fmt.Errorf("vault: payload %q does not match this agent's configured value; a job cannot change the KV mount or prefix", key)
	}
	return nil
}

// errRefEscapes is returned for a Vault secret ref that would climb out of
// the pinned mount/prefix once joined into a KV path.
var errRefEscapes = errors.New("vault: target_secret_ref must not contain '.' or '..' path segments")

// checkSecretRef refuses a target_secret_ref that core's path.Join would
// resolve outside the agent's pinned Vault mount/prefix. Other providers
// address secrets by opaque name/ARN, so nothing to check there.
func checkSecretRef(providerType, ref string) error {
	if providerType != vault.Kind {
		return nil
	}
	if hasDotSegment(ref) {
		return errRefEscapes
	}
	return nil
}

// checkDiscoverScope enforces that a Vault discover job lists only the
// pinned prefix. core's Vault ListMetadata uses ProviderScope.Scope in
// place of kvPrefix, so a payload scope is accepted only as an echo of the
// pinned prefix (or empty). AWS ignores Scope when listing.
func checkDiscoverScope(providerType, scope string) error {
	if providerType != vault.Kind || scope == "" {
		return nil
	}
	if strings.Trim(scope, "/") != pinnedVaultKVPrefix() {
		return errors.New("vault: discover scope does not match this agent's configured kv prefix; a job cannot list outside it")
	}
	return nil
}

func hasDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}
