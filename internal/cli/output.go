package cli

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/agent/internal/identity"
)

// This file is the only non-test code in the module allowed to create or
// write a file (the runtime-no-writes guard enforces this). It holds the
// operator's credential bundle output.

// Output formats.
const (
	formatJSON      = "json"
	formatEnv       = "env"
	formatK8sSecret = "k8s-secret"
)

// bundle is what enroll and rotate-key hand to the operator.
type bundle struct {
	AgentID     string
	AgentSecret []byte
	PrivateKey  []byte // raw 32 bytes; rendered as base64
	Fingerprint string
}

// k8sSecretHeader opens the k8s-secret manifest. Client-side kubectl apply
// copies the whole object, stringData included, into the
// kubectl.kubernetes.io/last-applied-configuration annotation, so the
// plaintext agent_secret and private_key would sit outside .data, where
// tools that treat metadata as non-sensitive can expose them. Server-side
// apply keeps no such copy.
const k8sSecretHeader = "# Secrets Bridge agent credentials; never commit this manifest.\n" +
	"# Apply with: kubectl apply --server-side --field-manager=secrets-bridge-agent -f -\n" +
	"# Do not use client-side kubectl apply (without --server-side): it stores the\n" +
	"# plaintext agent_secret and private_key in the\n" +
	"# kubectl.kubernetes.io/last-applied-configuration annotation.\n"

// k8sName matches a DNS-1123 subdomain, the rule for Secret and namespace
// names.
var k8sName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

func validFormat(f string) bool {
	return f == formatJSON || f == formatEnv || f == formatK8sSecret
}

// render returns the bundle in the requested format. The caller zeroes
// the result after writing it.
func (b *bundle) render(format, secretName, namespace string) ([]byte, error) {
	key := make([]byte, base64.StdEncoding.EncodedLen(len(b.PrivateKey)))
	base64.StdEncoding.Encode(key, b.PrivateKey)
	defer client.Zero(key)

	fields := []struct {
		name  string
		value []byte
	}{
		{identity.FileAgentID, []byte(b.AgentID)},
		{identity.FileAgentSecret, b.AgentSecret},
		{identity.FilePrivateKey, key},
		{"public_key_fingerprint", []byte(b.Fingerprint)},
	}
	for _, f := range fields {
		for _, c := range f.value {
			if c < 0x21 || c == '"' || c == '\\' || c >= 0x7f {
				return nil, fmt.Errorf("%s contains an unexpected character", f.name)
			}
		}
	}

	out := make([]byte, 0, 512)
	switch format {
	case formatJSON:
		out = append(out, '{')
		for i, f := range fields {
			if i > 0 {
				out = append(out, ',')
			}
			out = append(out, '"')
			out = append(out, f.name...)
			out = append(out, `":"`...)
			out = append(out, f.value...)
			out = append(out, '"')
		}
		out = append(out, "}\n"...)
	case formatEnv:
		for _, f := range fields {
			out = append(out, f.name...)
			out = append(out, '=')
			out = append(out, f.value...)
			out = append(out, '\n')
		}
	case formatK8sSecret:
		if !k8sName.MatchString(secretName) {
			return nil, errors.New("--secret-name is not a valid Kubernetes name")
		}
		if namespace != "" && !k8sName.MatchString(namespace) {
			return nil, errors.New("--namespace is not a valid Kubernetes name")
		}
		out = append(out, k8sSecretHeader...)
		out = append(out, "apiVersion: v1\nkind: Secret\nmetadata:\n  name: "...)
		out = append(out, secretName...)
		out = append(out, '\n')
		if namespace != "" {
			out = append(out, "  namespace: "...)
			out = append(out, namespace...)
			out = append(out, '\n')
		}
		out = append(out, "type: Opaque\nstringData:\n"...)
		for _, f := range fields {
			out = append(out, "  "...)
			out = append(out, f.name...)
			out = append(out, `: "`...)
			out = append(out, f.value...)
			out = append(out, "\"\n"...)
		}
	default:
		return nil, fmt.Errorf("unknown --format %q", format)
	}
	return out, nil
}

// output is where the bundle goes: stdout, or a file created up front.
type output struct {
	w    io.Writer
	file *os.File
	path string
	done bool
}

// openOutput prepares the destination before the control plane is called,
// so a bad path fails without spending the one-time token. A file is
// created with O_EXCL and mode 0600: an existing file (or a symlink at the
// path) is never overwritten.
func openOutput(path string, stdout io.Writer) (*output, error) {
	if path == "-" {
		return &output{w: stdout}, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("--output %q already exists; refusing to overwrite it", path)
		}
		return nil, fmt.Errorf("--output: %w", err)
	}
	return &output{w: f, file: f, path: path}, nil
}

// write writes data and, for a file, syncs and closes it.
func (o *output) write(data []byte) error {
	if _, err := o.w.Write(data); err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}
	if o.file != nil {
		if err := o.file.Sync(); err != nil {
			return fmt.Errorf("sync bundle: %w", err)
		}
		if err := o.file.Close(); err != nil {
			return fmt.Errorf("close bundle: %w", err)
		}
	}
	o.done = true
	return nil
}

// abort removes a file that was created but never completed.
func (o *output) abort() {
	if o.file == nil || o.done {
		return
	}
	_ = o.file.Close()
	_ = os.Remove(o.path)
}
