// Package cli implements the operator-side subcommands of the agent
// binary: enroll and rotate-key. They run on the operator's machine (or a
// CI job inside the customer boundary), generate the X25519 wire key
// locally, prove possession of it to the control plane, and hand the
// resulting credential bundle to the operator's secret store. The private
// key never leaves that boundary.
//
// Nothing secret is written to stderr: only the agent_id, the public key
// fingerprint and progress messages. The token is read from a file or
// stdin, never from argv, and every secret buffer is zeroed after use.
package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/agent/internal/identity"
	"github.com/secrets-bridge/agent/internal/sealing"
	"github.com/secrets-bridge/agent/internal/transport"
)

// Usage is the top-level help for the agent binary.
const Usage = `Usage:
  secrets-bridge-agent                 run the agent (reads SB_AGENT_CREDENTIALS_DIR)
  secrets-bridge-agent enroll [flags]  enroll a new agent with a one-time token
  secrets-bridge-agent rotate-key [flags]
                                       replace the agent's wire key with a rotation token

Run "secrets-bridge-agent <command> -h" for the flags of a command.
`

// timeout bounds a whole enroll or rotate-key run. The CP's challenge
// lives for 120s.
var timeout = 90 * time.Second

// maxTokenSize caps a token read from a file or stdin.
const maxTokenSize = 4 << 10

const defaultSecretName = "secrets-bridge-agent"

// common holds the flags both subcommands share.
type common struct {
	endpoint      string
	caFile        string
	tlsServerName string
	insecure      bool
	output        string
	format        string
	secretName    string
	namespace     string
}

func (c *common) register(fs *flag.FlagSet) {
	// The transport flags default from the same env vars as the runtime,
	// so a container that runs the agent can run the subcommands too.
	fs.StringVar(&c.endpoint, "cp-endpoint", os.Getenv("SB_CP_ENDPOINT"), "control plane base URL, https:// (required; also SB_CP_ENDPOINT)")
	fs.StringVar(&c.caFile, "cp-ca-file", os.Getenv("SB_CP_CA_FILE"), "PEM CA bundle to trust for the control plane certificate (also SB_CP_CA_FILE)")
	fs.StringVar(&c.tlsServerName, "cp-tls-server-name", os.Getenv("SB_CP_TLS_SERVER_NAME"), "override the TLS server name used to verify the control plane (also SB_CP_TLS_SERVER_NAME)")
	fs.BoolVar(&c.insecure, "insecure-transport", envTrue("SB_INSECURE_TRANSPORT"), "allow plain http:// to the control plane (dev only; also SB_INSECURE_TRANSPORT)")
	fs.StringVar(&c.output, "output", "", `where to write the bundle: a new file (created 0600, never overwritten) or "-" for stdout (required)`)
	fs.StringVar(&c.format, "format", formatJSON, "bundle format: json, env or k8s-secret")
	fs.StringVar(&c.secretName, "secret-name", defaultSecretName, "Secret name for --format k8s-secret")
	fs.StringVar(&c.namespace, "namespace", "", "Secret namespace for --format k8s-secret (optional)")
}

func (c *common) validate() error {
	if c.output == "" {
		return errors.New("--output is required (a new file path, or - for stdout)")
	}
	if !validFormat(c.format) {
		return fmt.Errorf("--format must be json, env or k8s-secret, got %q", c.format)
	}
	if c.format == formatK8sSecret && !k8sName.MatchString(c.secretName) {
		return errors.New("--secret-name is not a valid Kubernetes name")
	}
	if c.format == formatK8sSecret && c.namespace != "" && !k8sName.MatchString(c.namespace) {
		return errors.New("--namespace is not a valid Kubernetes name")
	}
	if _, err := transport.ValidateEndpoint(c.endpoint, c.insecure); err != nil {
		return err
	}
	return nil
}

func (c *common) client() (*client.Client, error) {
	hc, err := transport.NewHTTPClient(transport.Options{
		CPEndpoint:        c.endpoint,
		InsecureTransport: c.insecure,
		CAFile:            c.caFile,
		TLSServerName:     c.tlsServerName,
	})
	if err != nil {
		return nil, err
	}
	return client.New(c.endpoint).WithHTTPClient(hc), nil
}

// Enroll runs "secrets-bridge-agent enroll". It returns the exit code.
func Enroll(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	c.register(fs)
	var tokenFile, name, clusterName, providerType, region string
	fs.StringVar(&tokenFile, "token-file", "", `file holding the one-time enrollment token, or "-" for stdin (required)`)
	fs.StringVar(&name, "name", "", "agent name (required)")
	fs.StringVar(&clusterName, "cluster-name", "", "cluster the agent runs in")
	fs.StringVar(&providerType, "provider-type", "", "provider type, e.g. aws-sm or vault (required)")
	fs.StringVar(&region, "region", "", "provider region")
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, "Usage: secrets-bridge-agent enroll --cp-endpoint URL --token-file PATH|- --name NAME --provider-type TYPE --output PATH|- [flags]\n\n"+
			"Generates an X25519 wire key locally, proves possession of it to the control plane with the\n"+
			"one-time enrollment token, and writes the credential bundle (agent_id, agent_secret,\n"+
			"private_key, public_key_fingerprint) for your secret store. The private key never leaves\n"+
			"this machine.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return usageExit(err)
	}
	if fs.NArg() != 0 {
		return fail(stderr, errors.New("unexpected positional argument, not echoed (the token is read from --token-file only)"))
	}
	if err := c.validate(); err != nil {
		return fail(stderr, err)
	}
	switch {
	case tokenFile == "":
		return fail(stderr, errors.New("--token-file is required (a file path, or - for stdin)"))
	case name == "":
		return fail(stderr, errors.New("--name is required"))
	case providerType == "":
		return fail(stderr, errors.New("--provider-type is required"))
	}

	cp, err := c.client()
	if err != nil {
		return fail(stderr, err)
	}
	token, err := readToken(tokenFile, stdin)
	if err != nil {
		return fail(stderr, err)
	}
	defer token.Zero()

	out, err := openOutput(c.output, stdout)
	if err != nil {
		return fail(stderr, err)
	}
	defer out.abort()

	kp, err := generateWireKey()
	if err != nil {
		return fail(stderr, err)
	}
	defer client.Zero(kp.Private)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch, err := cp.EnrollChallenge(ctx, token, kp.Public)
	if err != nil {
		return fail(stderr, fmt.Errorf("enrollment challenge: %w", err))
	}
	resp, err := openChallenge(ch, kp)
	if err != nil {
		return fail(stderr, err)
	}
	defer resp.Zero()

	res, err := cp.Enroll(ctx, client.EnrollRequest{
		EnrollmentToken:   token,
		ChallengeID:       ch.ChallengeID,
		ChallengeResponse: resp,
		Name:              name,
		ClusterName:       clusterName,
		ProviderType:      providerType,
		Region:            region,
	})
	if err != nil {
		return fail(stderr, fmt.Errorf("enroll: %w", err))
	}
	defer res.AgentSecret.Zero()

	if res.PublicKeyFingerprint != kp.Fingerprint {
		return fail(stderr, fmt.Errorf("the control plane bound fingerprint %s to agent %s, but the local key is %s; "+
			"no bundle was written; revoke that agent and enroll again", res.PublicKeyFingerprint, res.AgentID, kp.Fingerprint))
	}
	if err := identity.ValidateAgentID(res.AgentID); err != nil {
		return fail(stderr, fmt.Errorf("enroll response: %w", err))
	}
	if err := identity.ValidateAgentSecret(res.AgentSecret); err != nil {
		return fail(stderr, fmt.Errorf("enroll response: %w", err))
	}

	b := &bundle{AgentID: res.AgentID, AgentSecret: res.AgentSecret, PrivateKey: kp.Private, Fingerprint: kp.Fingerprint}
	if err := writeBundle(out, b, &c); err != nil {
		return fail(stderr, err)
	}
	_, _ = fmt.Fprintf(stderr, "enrolled agent_id=%s public_key_fingerprint=%s public_key_version=%d; bundle written to %s\n",
		res.AgentID, kp.Fingerprint, res.PublicKeyVersion, destination(c.output))
	return 0
}

// RotateKey runs "secrets-bridge-agent rotate-key". It returns the exit
// code.
func RotateKey(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rotate-key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	c.register(fs)
	var credsDir, tokenFile string
	fs.StringVar(&credsDir, "credentials-dir", identity.DefaultCredentialsDir,
		"directory holding the current agent_id and agent_secret")
	fs.StringVar(&tokenFile, "rotation-token-file", "", `file holding the one-time rotation token, or "-" for stdin (required)`)
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, "Usage: secrets-bridge-agent rotate-key --cp-endpoint URL --credentials-dir DIR --rotation-token-file PATH|- --output PATH|- [flags]\n\n"+
			"Generates a new X25519 wire key locally and binds it to the agent with the one-time rotation\n"+
			"token an admin requested. The bundle keeps the same agent_id and agent_secret. Restart the\n"+
			"agent with the new bundle; until then it gets agent_key_mismatch and exits.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return usageExit(err)
	}
	if fs.NArg() != 0 {
		return fail(stderr, errors.New("unexpected positional argument, not echoed (the token is read from --rotation-token-file only)"))
	}
	if err := c.validate(); err != nil {
		return fail(stderr, err)
	}
	if tokenFile == "" {
		return fail(stderr, errors.New("--rotation-token-file is required (a file path, or - for stdin)"))
	}

	id, err := identity.LoadIdentity(credsDir)
	if err != nil {
		return fail(stderr, err)
	}
	cp, err := c.client()
	if err != nil {
		return fail(stderr, err)
	}
	// The rotation calls authenticate with X-Agent-Secret only: the old
	// private key may be the thing that was lost, so it is not read.
	token, err := readToken(tokenFile, stdin)
	if err != nil {
		return fail(stderr, err)
	}
	defer token.Zero()

	out, err := openOutput(c.output, stdout)
	if err != nil {
		return fail(stderr, err)
	}
	defer out.abort()

	kp, err := generateWireKey()
	if err != nil {
		return fail(stderr, err)
	}
	defer client.Zero(kp.Private)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch, err := cp.KeyRotationChallenge(ctx, id.AgentID, id.AgentSecret, token, kp.Public)
	if err != nil {
		return fail(stderr, fmt.Errorf("key rotation challenge: %w", err))
	}
	resp, err := openChallenge(ch, kp)
	if err != nil {
		return fail(stderr, err)
	}
	defer resp.Zero()

	res, err := cp.RotateKey(ctx, id.AgentID, id.AgentSecret, client.RotateKeyRequest{
		RotationToken:     token,
		ChallengeID:       ch.ChallengeID,
		ChallengeResponse: resp,
	})
	if err != nil {
		return fail(stderr, fmt.Errorf("key rotation: %w", err))
	}
	if res.PublicKeyFingerprint != kp.Fingerprint {
		return fail(stderr, fmt.Errorf("the control plane bound fingerprint %s, but the new local key is %s; no bundle was written",
			res.PublicKeyFingerprint, kp.Fingerprint))
	}

	secret := []byte(id.AgentSecret)
	defer client.Zero(secret)
	b := &bundle{AgentID: id.AgentID, AgentSecret: secret, PrivateKey: kp.Private, Fingerprint: kp.Fingerprint}
	if err := writeBundle(out, b, &c); err != nil {
		return fail(stderr, err)
	}
	_, _ = fmt.Fprintf(stderr, "rotated agent_id=%s public_key_fingerprint=%s public_key_version=%d; bundle written to %s\n",
		id.AgentID, kp.Fingerprint, res.PublicKeyVersion, destination(c.output))
	return 0
}

// openChallenge decrypts the sealed challenge with the new private key
// and returns the base64 challenge response.
func openChallenge(ch *client.Challenge, kp *identity.KeyPair) (client.Secret, error) {
	nonce, err := sealing.Open(ch.Sealed, kp.Private, kp.Public)
	if err != nil {
		return nil, fmt.Errorf("open the sealed challenge: %w", err)
	}
	defer client.Zero(nonce)
	if len(nonce) != 32 {
		return nil, fmt.Errorf("sealed challenge is %d bytes, want 32", len(nonce))
	}
	resp := make(client.Secret, base64.StdEncoding.EncodedLen(len(nonce)))
	base64.StdEncoding.Encode(resp, nonce)
	return resp, nil
}

func writeBundle(out *output, b *bundle, c *common) error {
	data, err := b.render(c.format, c.secretName, c.namespace)
	if err != nil {
		return err
	}
	defer client.Zero(data)
	return out.write(data)
}

// readToken reads a token from path, or from stdin when path is "-".
func readToken(path string, stdin io.Reader) (client.Secret, error) {
	var r io.Reader
	if path == "-" {
		if stdin == nil {
			return nil, errors.New("no stdin to read the token from")
		}
		r = stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("token file: %w", err)
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxTokenSize+1))
	if err != nil {
		client.Zero(raw)
		return nil, fmt.Errorf("read token: %w", err)
	}
	defer client.Zero(raw)
	if len(raw) > maxTokenSize {
		return nil, fmt.Errorf("token is larger than %d bytes", maxTokenSize)
	}
	tok := bytes.TrimSpace(raw)
	if len(tok) == 0 {
		return nil, errors.New("token is empty")
	}
	for _, b := range tok {
		if b < 0x21 || b >= 0x7f || b == '"' || b == '\\' {
			return nil, errors.New("token contains an unexpected character")
		}
	}
	return append(client.Secret(nil), tok...), nil
}

func envTrue(key string) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func destination(path string) string {
	if path == "-" {
		return "stdout"
	}
	return path
}

func fail(stderr io.Writer, err error) int {
	_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
	return 1
}

func usageExit(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return 2
}
