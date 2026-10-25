// Package identity reads the agent's credentials from a read-only
// directory. It is the only way the runtime gets them.
//
// The directory (SB_AGENT_CREDENTIALS_DIR, default /etc/secrets-bridge/agent)
// holds three files, usually a Kubernetes Secret mounted read-only:
//
//	agent_id      the agent UUID
//	agent_secret  the X-Agent-Secret bearer credential (32 bytes, base64url)
//	private_key   the X25519 wire key (32 bytes, base64)
//
// Every file must be present and well-formed, and none may carry a group
// write or execute bit or any bit for others (mode & 0o037). Group read is
// allowed: a non-root pod reads a Secret volume through fsGroup, and the
// kubelet then sets 0440 root:fsGroup. The mode is checked on the file the
// path resolves to, so the `..data` symlinks of a Secret volume work.
//
// This package never writes, never creates a directory and never generates
// a key. The enroll and rotate-key subcommands produce the files; the
// operator stores them in a secret store or a Kubernetes Secret.
package identity

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/secrets-bridge/agent/internal/sealing"
)

// DefaultCredentialsDir is where the chart mounts the agent Secret.
const DefaultCredentialsDir = "/etc/secrets-bridge/agent"

// File names inside the credentials directory. They are also the keys of
// the Kubernetes Secret and of the enroll bundle.
const (
	FileAgentID     = "agent_id"
	FileAgentSecret = "agent_secret"
	FilePrivateKey  = "private_key"
)

// forbiddenModeBits are the permission bits a credential file must not
// carry: group write and execute, and anything for others.
const forbiddenModeBits os.FileMode = 0o037

// maxCredentialFileSize caps each read. The real files are under 100 bytes.
const maxCredentialFileSize = 4 << 10

// Identity is the agent credential: the id and the bearer secret.
type Identity struct {
	AgentID     string
	AgentSecret string
}

// KeyPair is the agent's X25519 wire key. Private never leaves the
// process; Fingerprint is what the CP has bound to the agent.
type KeyPair struct {
	Public      []byte
	Private     []byte
	Fingerprint string
}

// ErrInsecureMode is returned for a credential file whose mode is too open.
var ErrInsecureMode = errors.New("identity: credential file mode is too open")

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Load reads and validates all three files in dir.
func Load(dir string) (Identity, *KeyPair, error) {
	id, err := LoadIdentity(dir)
	if err != nil {
		return Identity{}, nil, err
	}
	kp, err := LoadKeyPair(dir)
	if err != nil {
		return Identity{}, nil, err
	}
	return id, kp, nil
}

// LoadIdentity reads and validates agent_id and agent_secret.
func LoadIdentity(dir string) (Identity, error) {
	rawID, err := ReadCredentialFile(dir, FileAgentID)
	if err != nil {
		return Identity{}, err
	}
	agentID := string(rawID)
	zero(rawID)
	if err := ValidateAgentID(agentID); err != nil {
		return Identity{}, err
	}

	rawSecret, err := ReadCredentialFile(dir, FileAgentSecret)
	if err != nil {
		return Identity{}, err
	}
	defer zero(rawSecret)
	if err := ValidateAgentSecret(rawSecret); err != nil {
		return Identity{}, err
	}
	return Identity{AgentID: agentID, AgentSecret: string(rawSecret)}, nil
}

// ValidateAgentID checks that id is a UUID.
func ValidateAgentID(id string) error {
	if !uuidPattern.MatchString(id) {
		return fmt.Errorf("identity: %s is not a UUID", FileAgentID)
	}
	return nil
}

// ValidateAgentSecret checks the shape the CP mints: 32 random bytes,
// base64url without padding.
func ValidateAgentSecret(secret []byte) error {
	buf := make([]byte, base64.RawURLEncoding.DecodedLen(len(secret)))
	defer zero(buf)
	n, err := base64.RawURLEncoding.Decode(buf, secret)
	if err != nil || n != 32 {
		return fmt.Errorf("identity: %s must be 32 bytes in base64url", FileAgentSecret)
	}
	return nil
}

// LoadKeyPair reads private_key and derives the public key and fingerprint.
func LoadKeyPair(dir string) (*KeyPair, error) {
	raw, err := ReadCredentialFile(dir, FilePrivateKey)
	if err != nil {
		return nil, err
	}
	defer zero(raw)
	priv := make([]byte, base64.StdEncoding.DecodedLen(len(raw)))
	n, err := base64.StdEncoding.Decode(priv, raw)
	if err != nil || n != 32 {
		zero(priv)
		return nil, fmt.Errorf("identity: %s must be 32 bytes in base64", FilePrivateKey)
	}
	kp, err := KeyPairFromPrivate(priv[:n])
	if err != nil {
		zero(priv)
		return nil, err
	}
	return kp, nil
}

// KeyPairFromPrivate derives the public key and fingerprint from a 32-byte
// X25519 private key. It keeps priv; the caller must not reuse it.
func KeyPairFromPrivate(priv []byte) (*KeyPair, error) {
	if len(priv) != 32 {
		return nil, fmt.Errorf("identity: private key must be 32 bytes, got %d", len(priv))
	}
	if bytes.Equal(priv, make([]byte, 32)) {
		return nil, errors.New("identity: private key is all zeros")
	}
	pub, err := sealing.PublicFromPrivate(priv)
	if err != nil {
		return nil, fmt.Errorf("identity: derive public key: %w", err)
	}
	if err := sealing.ValidatePublicKey(pub); err != nil {
		return nil, err
	}
	return &KeyPair{Public: pub, Private: priv, Fingerprint: sealing.Fingerprint(pub)}, nil
}

// ReadCredentialFile opens dir/name read-only and returns its contents
// with surrounding whitespace removed.
//
// os.Open follows symlinks and Stat on the open descriptor describes the
// target, so the mode check applies to the file the data comes from, never
// to a symlink (whose own mode is always 0777). The file must be regular,
// non-empty and must not carry any bit in forbiddenModeBits.
func ReadCredentialFile(dir, name string) ([]byte, error) {
	path := filepath.Join(dir, name)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("identity: %s is missing from the credentials directory %q", name, dir)
		}
		return nil, fmt.Errorf("identity: open %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("identity: stat %s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("identity: %s is not a regular file", name)
	}
	if perm := info.Mode().Perm(); perm&forbiddenModeBits != 0 {
		return nil, fmt.Errorf("%w: %s has mode %#o; group write or execute and any access for others are refused "+
			"(use 0400, or 0440 with fsGroup; on Kubernetes set the Secret volume defaultMode: 0400)", ErrInsecureMode, name, perm)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxCredentialFileSize+1))
	if err != nil {
		zero(data)
		return nil, fmt.Errorf("identity: read %s: %w", name, err)
	}
	if len(data) > maxCredentialFileSize {
		zero(data)
		return nil, fmt.Errorf("identity: %s is larger than %d bytes", name, maxCredentialFileSize)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		zero(data)
		return nil, fmt.Errorf("identity: %s is empty", name)
	}
	out := append([]byte(nil), trimmed...)
	zero(data)
	return out, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
