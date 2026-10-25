package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/agent/internal/identity"
	"github.com/secrets-bridge/agent/internal/sealing"
	"github.com/secrets-bridge/agent/internal/sealing/sealtest"
)

const (
	fakeToken       = "fake-enroll-token-5f2a"
	fakeRotateToken = "fake-rotate-token-9c1d"
	fakeAgentID     = "0f8b6c7e-2a51-4d3e-9b1f-6c2d4e8a9b10"
)

type challenge struct {
	nonce []byte
	pub   []byte
	token string
	used  bool
}

// fakeCP implements the schema_version 2 enrollment and rotation flow
// with real sealing, the way the contract describes the CP.
type fakeCP struct {
	t           *testing.T
	srv         *httptest.Server
	caFile      string
	secret      string
	calls       atomic.Int32
	sealToOther atomic.Bool // seal the challenge to a different key
	bindOther   atomic.Bool // report a different fingerprint at enroll
	rotateOther atomic.Bool // report a different fingerprint at rotation
	rejectToken atomic.Bool

	mu         sync.Mutex
	challenges map[string]*challenge
	boundPub   []byte
	consumed   map[string]bool
	rotFPs     []string
	headerDump []string
}

func newFakeCP(t *testing.T) *fakeCP {
	t.Helper()
	sb := make([]byte, 32)
	_, _ = rand.Read(sb)
	f := &fakeCP{t: t, secret: base64.RawURLEncoding.EncodeToString(sb), challenges: map[string]*challenge{}, consumed: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agents/enroll/challenge", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["schema_version"] != "2" {
			writeErr(w, http.StatusBadRequest, "unsupported_schema_version")
			return
		}
		if f.rejectToken.Load() || req["enrollment_token"] != fakeToken || f.isConsumed(fakeToken) {
			writeErr(w, http.StatusUnauthorized, "enrollment_rejected")
			return
		}
		f.issueChallenge(w, req, fakeToken)
	})
	mux.HandleFunc("POST /api/v1/agents/enroll", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["schema_version"] != "2" || req["name"] == "" {
			writeErr(w, http.StatusBadRequest, "unsupported_schema_version")
			return
		}
		ch := f.check(req, fakeToken)
		if ch == nil || req["enrollment_token"] != fakeToken {
			writeErr(w, http.StatusUnauthorized, "enrollment_rejected")
			return
		}
		f.mu.Lock()
		f.consumed[fakeToken] = true
		f.boundPub = ch.pub
		f.mu.Unlock()
		fp := sealing.Fingerprint(ch.pub)
		if f.bindOther.Load() {
			fp = sealing.Fingerprint(bytes.Repeat([]byte{9}, 32))
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agent_id": fakeAgentID, "agent_secret": f.secret, "public_key_fingerprint": fp,
			"public_key_version": 1, "heartbeat_interval_seconds": 30, "claim_interval_seconds": 5,
		})
	})
	mux.HandleFunc("POST /api/v1/agents/"+fakeAgentID+"/key-rotation/challenge", func(w http.ResponseWriter, r *http.Request) {
		if !f.agentAuth(w, r) {
			return
		}
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["schema_version"] != "2" || req["rotation_token"] != fakeRotateToken || f.isConsumed(fakeRotateToken) {
			writeErr(w, http.StatusUnauthorized, "enrollment_rejected")
			return
		}
		f.issueChallenge(w, req, fakeRotateToken)
	})
	mux.HandleFunc("POST /api/v1/agents/"+fakeAgentID+"/key-rotation", func(w http.ResponseWriter, r *http.Request) {
		if !f.agentAuth(w, r) {
			return
		}
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		ch := f.check(req, fakeRotateToken)
		if ch == nil || req["rotation_token"] != fakeRotateToken {
			writeErr(w, http.StatusUnauthorized, "enrollment_rejected")
			return
		}
		f.mu.Lock()
		f.consumed[fakeRotateToken] = true
		f.boundPub = ch.pub
		f.mu.Unlock()
		fp := sealing.Fingerprint(ch.pub)
		if f.rotateOther.Load() {
			fp = sealing.Fingerprint(bytes.Repeat([]byte{9}, 32))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agent_id": fakeAgentID, "public_key_fingerprint": fp, "public_key_version": 2,
		})
	})
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		f.mu.Lock()
		f.headerDump = append(f.headerDump, fmt.Sprint(r.Header), r.URL.String())
		f.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(f.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func writeErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q}`, code)
}

func (f *fakeCP) isConsumed(tok string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.consumed[tok]
}

func (f *fakeCP) agentAuth(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Agent-Secret") != f.secret {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	f.mu.Lock()
	f.rotFPs = append(f.rotFPs, r.Header.Get("X-Agent-Key-Fingerprint"))
	f.mu.Unlock()
	return true
}

func (f *fakeCP) issueChallenge(w http.ResponseWriter, req map[string]string, tok string) {
	pub, err := base64.StdEncoding.DecodeString(req["public_key"])
	if err != nil || req["public_key_algorithm"] != "x25519" || sealing.ValidatePublicKey(pub) != nil {
		writeErr(w, http.StatusBadRequest, "invalid_public_key")
		return
	}
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	sealTo := pub
	if f.sealToOther.Load() {
		other, _ := sealing.PublicFromPrivate(bytes.Repeat([]byte{5}, 32))
		sealTo = other
	}
	env, err := sealtest.Seal(nonce, sealTo)
	if err != nil {
		f.t.Error(err)
		return
	}
	id := fmt.Sprintf("c%d", len(f.challenges)+1)
	f.mu.Lock()
	f.challenges[id] = &challenge{nonce: nonce, pub: pub, token: tok}
	f.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{
		"challenge_id": id, "sealed_challenge": sealtest.Wire(env), "expires_at": "2026-10-25T12:02:00Z",
	})
}

// check validates and consumes a challenge response.
func (f *fakeCP) check(req map[string]string, tok string) *challenge {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := f.challenges[req["challenge_id"]]
	if ch == nil || ch.used || ch.token != tok {
		return nil
	}
	got, err := base64.StdEncoding.DecodeString(req["challenge_response"])
	if err != nil || subtle.ConstantTimeCompare(got, ch.nonce) != 1 {
		return nil
	}
	ch.used = true
	return ch
}

func (f *fakeCP) args(extra ...string) []string {
	return append([]string{"--cp-endpoint", f.srv.URL, "--cp-ca-file", f.caFile, "--cp-tls-server-name", "example.com"}, extra...)
}

type result struct {
	code   int
	stdout string
	stderr string
}

func runCmd(t *testing.T, cmd func(context.Context, []string, interface{ Read([]byte) (int, error) }, *bytes.Buffer, *bytes.Buffer) int, args []string, stdin string) result {
	t.Helper()
	var out, errb bytes.Buffer
	code := cmd(context.Background(), args, strings.NewReader(stdin), &out, &errb)
	return result{code, out.String(), errb.String()}
}

func enroll(ctx context.Context, args []string, in interface{ Read([]byte) (int, error) }, out, errb *bytes.Buffer) int {
	return Enroll(ctx, args, in, out, errb)
}

func rotate(ctx context.Context, args []string, in interface{ Read([]byte) (int, error) }, out, errb *bytes.Buffer) int {
	return RotateKey(ctx, args, in, out, errb)
}

func tokenFile(t *testing.T, tok string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func enrollArgs(f *fakeCP, extra ...string) []string {
	return f.args(append([]string{"--name", "agent-a", "--cluster-name", "tenant-a-uat", "--provider-type", "aws-sm", "--region", "eu-west-1"}, extra...)...)
}

// assertNoSecrets checks stderr never carries the token, the agent
// secret or a private key.
func assertNoSecrets(t *testing.T, f *fakeCP, stderr string, priv string) {
	t.Helper()
	for _, s := range []string{fakeToken, fakeRotateToken, f.secret} {
		if strings.Contains(stderr, s) {
			t.Fatalf("stderr carries a secret: %q", stderr)
		}
	}
	if priv != "" && strings.Contains(stderr, priv) {
		t.Fatalf("stderr carries the private key: %q", stderr)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, h := range f.headerDump {
		if strings.Contains(h, fakeToken) || strings.Contains(h, fakeRotateToken) {
			t.Fatalf("a token travelled in a header or URL: %s", h)
		}
	}
}

func parseJSONBundle(t *testing.T, data []byte) map[string]string {
	t.Helper()
	var b map[string]string
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("bundle is not JSON: %v", err)
	}
	if len(b) != 4 {
		t.Fatalf("bundle keys = %d want 4", len(b))
	}
	return b
}

// bundleDir writes the bundle fields as the credentials directory the
// runtime reads and loads it the same way.
func bundleDir(t *testing.T, b map[string]string) (identity.Identity, *identity.KeyPair, string) {
	t.Helper()
	dir := t.TempDir()
	for _, k := range []string{identity.FileAgentID, identity.FileAgentSecret, identity.FilePrivateKey} {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(b[k]), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	id, kp, err := identity.Load(dir)
	if err != nil {
		t.Fatalf("runtime refuses the bundle: %v", err)
	}
	return id, kp, dir
}

func TestEnroll_JSONFileBundle(t *testing.T) {
	f := newFakeCP(t)
	outPath := filepath.Join(t.TempDir(), "bundle.json")
	r := runCmd(t, enroll, enrollArgs(f, "--token-file", tokenFile(t, fakeToken), "--output", outPath), "")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("bundle mode = %#o want 0600", info.Mode().Perm())
	}
	data, _ := os.ReadFile(outPath)
	b := parseJSONBundle(t, data)
	id, kp, _ := bundleDir(t, b)
	if id.AgentID != fakeAgentID || id.AgentSecret != f.secret {
		t.Fatalf("bundle identity = %+v", id)
	}
	f.mu.Lock()
	bound := sealing.Fingerprint(f.boundPub)
	f.mu.Unlock()
	if kp.Fingerprint != bound || b["public_key_fingerprint"] != bound {
		t.Fatalf("bundle key %s / %s, CP bound %s", kp.Fingerprint, b["public_key_fingerprint"], bound)
	}
	if r.stdout != "" {
		t.Fatalf("stdout used while writing a file: %q", r.stdout)
	}
	if !strings.Contains(r.stderr, fakeAgentID) || !strings.Contains(r.stderr, bound) {
		t.Fatalf("stderr = %q want agent_id and fingerprint", r.stderr)
	}
	assertNoSecrets(t, f, r.stderr, b["private_key"])
}

func TestEnroll_StdinTokenStdoutFormats(t *testing.T) {
	for _, format := range []string{"json", "env", "k8s-secret"} {
		t.Run(format, func(t *testing.T) {
			f := newFakeCP(t)
			r := runCmd(t, enroll, enrollArgs(f, "--token-file", "-", "--output", "-", "--format", format, "--namespace", "secrets-bridge"), fakeToken+"\n")
			if r.code != 0 {
				t.Fatalf("exit %d: %s", r.code, r.stderr)
			}
			b := map[string]string{}
			switch format {
			case "json":
				b = parseJSONBundle(t, []byte(r.stdout))
			case "env":
				for _, line := range strings.Split(strings.TrimSpace(r.stdout), "\n") {
					k, v, ok := strings.Cut(line, "=")
					if !ok {
						t.Fatalf("env line %q", line)
					}
					b[k] = v
				}
			case "k8s-secret":
				for _, want := range []string{"apiVersion: v1\n", "kind: Secret\n", "  name: secrets-bridge-agent-identity\n", "  namespace: secrets-bridge\n", "type: Opaque\n", "stringData:\n", "never commit"} {
					if !strings.Contains(r.stdout, want) {
						t.Fatalf("manifest lacks %q:\n%s", want, r.stdout)
					}
				}
				for _, line := range strings.Split(r.stdout, "\n") {
					if k, v, ok := strings.Cut(strings.TrimSpace(line), `: "`); ok {
						b[k] = strings.TrimSuffix(v, `"`)
					}
				}
			}
			_, kp, _ := bundleDir(t, b)
			if b["public_key_fingerprint"] != kp.Fingerprint {
				t.Fatalf("fingerprint %q does not match private_key (%s)", b["public_key_fingerprint"], kp.Fingerprint)
			}
			assertNoSecrets(t, f, r.stderr, b["private_key"])
		})
	}
}

// An existing output file is never overwritten, and the token is not
// spent: the CP is never called.
func TestEnroll_ExistingOutputRefusedBeforeCPCall(t *testing.T) {
	f := newFakeCP(t)
	dir := t.TempDir()
	existing := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(existing, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(filepath.Join(dir, "target.json"), link); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{existing, link} {
		r := runCmd(t, enroll, enrollArgs(f, "--token-file", tokenFile(t, fakeToken), "--output", out), "")
		if r.code == 0 || !strings.Contains(r.stderr, "already exists") {
			t.Fatalf("%s: exit %d stderr %q want refusal", out, r.code, r.stderr)
		}
	}
	if got, _ := os.ReadFile(existing); string(got) != "keep me" {
		t.Fatal("existing file was modified")
	}
	if _, err := os.Lstat(filepath.Join(dir, "target.json")); err == nil {
		t.Fatal("bundle written through a symlink")
	}
	if f.calls.Load() != 0 {
		t.Fatalf("CP called %d times; the token would be spent for nothing", f.calls.Load())
	}
}

// Failures after the output file was created leave no file behind.
func TestEnroll_FailuresLeaveNoBundle(t *testing.T) {
	cases := map[string]func(f *fakeCP){
		"token rejected":         func(f *fakeCP) { f.rejectToken.Store(true) },
		"challenge to other key": func(f *fakeCP) { f.sealToOther.Store(true) },
		"cp binds other key":     func(f *fakeCP) { f.bindOther.Store(true) },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeCP(t)
			setup(f)
			out := filepath.Join(t.TempDir(), "bundle.json")
			r := runCmd(t, enroll, enrollArgs(f, "--token-file", tokenFile(t, fakeToken), "--output", out), "")
			if r.code == 0 {
				t.Fatal("enroll succeeded")
			}
			if _, err := os.Stat(out); err == nil {
				t.Fatal("a bundle file was left behind")
			}
			assertNoSecrets(t, f, r.stderr, "")
		})
	}
	f := newFakeCP(t)
	f.rejectToken.Store(true)
	r := runCmd(t, enroll, enrollArgs(f, "--token-file", tokenFile(t, fakeToken), "--output", "-"), "")
	if !strings.Contains(r.stderr, "enrollment_rejected") || r.stdout != "" {
		t.Fatalf("stderr %q stdout %q", r.stderr, r.stdout)
	}
}

func TestEnroll_FlagValidation(t *testing.T) {
	f := newFakeCP(t)
	tok := tokenFile(t, fakeToken)
	cases := map[string]struct {
		args []string
		code int
		want string
	}{
		"token flag does not exist": {enrollArgs(f, "--token", fakeToken, "--output", "-"), 2, "flag provided but not defined"},
		"token as argument":         {append(enrollArgs(f, "--token-file", tok, "--output", "-"), fakeToken), 1, "--token-file only"},
		"no token file":             {enrollArgs(f, "--output", "-"), 1, "--token-file is required"},
		"no output":                 {enrollArgs(f, "--token-file", tok), 1, "--output is required"},
		"bad format":                {enrollArgs(f, "--token-file", tok, "--output", "-", "--format", "yaml"), 1, "--format"},
		"no name": {[]string{"--cp-endpoint", f.srv.URL, "--provider-type", "aws-sm", "--token-file", tok, "--output", "-"},
			1, "--name is required"},
		"http refused": {[]string{"--cp-endpoint", "http://cp.example.com", "--name", "a", "--provider-type", "aws-sm", "--token-file", tok, "--output", "-"},
			1, "plain http://"},
		"bad secret name": {enrollArgs(f, "--token-file", tok, "--output", "-", "--format", "k8s-secret", "--secret-name", "Bad_Name"), 1, "--secret-name"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := runCmd(t, enroll, tc.args, "")
			if r.code != tc.code || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("exit %d stderr %q; want exit %d with %q", r.code, r.stderr, tc.code, tc.want)
			}
			if strings.Contains(r.stderr, fakeToken) {
				t.Fatalf("token echoed: %q", r.stderr)
			}
		})
	}
	if f.calls.Load() != 0 {
		t.Fatalf("CP called %d times by invalid invocations", f.calls.Load())
	}
	r := runCmd(t, enroll, enrollArgs(f, "--token-file", "-", "--output", "-"), "   \n")
	if r.code != 1 || !strings.Contains(r.stderr, "token is empty") {
		t.Fatalf("empty stdin token: exit %d %q", r.code, r.stderr)
	}
}

// rotate-key reads the current credentials, proves possession of a new
// key, and writes a bundle with the same agent credential and the new
// key. It authenticates with X-Agent-Secret and does not need the old key.
func TestRotateKey_NewBundle(t *testing.T) {
	f := newFakeCP(t)
	r := runCmd(t, enroll, enrollArgs(f, "--token-file", tokenFile(t, fakeToken), "--output", "-"), "")
	if r.code != 0 {
		t.Fatalf("enroll: %s", r.stderr)
	}
	old := parseJSONBundle(t, []byte(r.stdout))
	_, oldKP, dir := bundleDir(t, old)
	if err := os.Remove(filepath.Join(dir, identity.FilePrivateKey)); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "rotated.json")
	r = runCmd(t, rotate, f.args("--credentials-dir", dir, "--rotation-token-file", "-", "--output", out), fakeRotateToken)
	if r.code != 0 {
		t.Fatalf("rotate-key exit %d: %s", r.code, r.stderr)
	}
	data, _ := os.ReadFile(out)
	nb := parseJSONBundle(t, data)
	id, kp, _ := bundleDir(t, nb)
	if id.AgentID != old["agent_id"] || id.AgentSecret != old["agent_secret"] {
		t.Fatal("rotation changed the agent credential")
	}
	if kp.Fingerprint == oldKP.Fingerprint || nb["private_key"] == old["private_key"] {
		t.Fatal("rotation kept the old key")
	}
	f.mu.Lock()
	bound := sealing.Fingerprint(f.boundPub)
	rot := append([]string(nil), f.rotFPs...)
	f.mu.Unlock()
	if bound != kp.Fingerprint {
		t.Fatalf("CP bound %s, bundle has %s", bound, kp.Fingerprint)
	}
	if len(rot) != 2 {
		t.Fatalf("rotation made %d authenticated calls want 2", len(rot))
	}
	assertNoSecrets(t, f, r.stderr, nb["private_key"])

	// The rotation token is single use.
	r = runCmd(t, rotate, f.args("--credentials-dir", dir, "--rotation-token-file", "-", "--output", "-"), fakeRotateToken)
	if r.code == 0 || !strings.Contains(r.stderr, "enrollment_rejected") {
		t.Fatalf("reused rotation token: exit %d %q", r.code, r.stderr)
	}
}

func TestRotateKey_RefusesLooseCredentials(t *testing.T) {
	f := newFakeCP(t)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, identity.FileAgentID), []byte(fakeAgentID), 0o644)
	_ = os.WriteFile(filepath.Join(dir, identity.FileAgentSecret), []byte(f.secret), 0o644)
	r := runCmd(t, rotate, f.args("--credentials-dir", dir, "--rotation-token-file", "-", "--output", "-"), fakeRotateToken)
	if r.code != 1 || !strings.Contains(r.stderr, "mode") {
		t.Fatalf("exit %d %q want a mode refusal", r.code, r.stderr)
	}
	if f.calls.Load() != 0 {
		t.Fatal("CP called with loose credentials")
	}
}

// The transport flags default from the runtime's env vars, so the agent
// image can run enroll against a dev http control plane with
// SB_INSECURE_TRANSPORT=true.
func TestEnroll_TransportFromEnv(t *testing.T) {
	f := newFakeCP(t)
	plain := httptest.NewServer(f.srv.Config.Handler)
	t.Cleanup(plain.Close)
	t.Setenv("SB_CP_ENDPOINT", plain.URL)
	args := []string{"--name", "a", "--provider-type", "aws-sm", "--token-file", tokenFile(t, fakeToken), "--output", "-"}

	t.Setenv("SB_INSECURE_TRANSPORT", "")
	if r := runCmd(t, enroll, args, ""); r.code != 1 || !strings.Contains(r.stderr, "plain http://") {
		t.Fatalf("http without the dev switch: exit %d %q", r.code, r.stderr)
	}
	t.Setenv("SB_INSECURE_TRANSPORT", "true")
	r := runCmd(t, enroll, args, "")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	bundleDir(t, parseJSONBundle(t, []byte(r.stdout)))
}

// A terminal on stdout is refused before the control plane is called, so
// the one-time token is not spent and the bundle never reaches scrollback.
// --allow-tty writes it anyway.
func TestEnroll_StdoutTerminalRefused(t *testing.T) {
	orig := stdoutIsTerminal
	stdoutIsTerminal = func(io.Writer) bool { return true }
	t.Cleanup(func() { stdoutIsTerminal = orig })

	f := newFakeCP(t)
	for _, format := range []string{formatJSON, "env", "k8s-secret"} {
		r := runCmd(t, enroll, enrollArgs(f, "--token-file", "-", "--output", "-", "--format", format), fakeToken)
		if r.code == 0 || !strings.Contains(r.stderr, "--allow-tty") || r.stdout != "" {
			t.Fatalf("%s to a terminal: exit %d stdout %d bytes stderr %q", format, r.code, len(r.stdout), r.stderr)
		}
	}
	if n := f.calls.Load(); n != 0 || f.isConsumed(fakeToken) {
		t.Fatalf("refused output still called the CP %d times (token consumed: %v)", n, f.isConsumed(fakeToken))
	}
	r := runCmd(t, enroll, enrollArgs(f, "--token-file", "-", "--output", "-", "--allow-tty"), fakeToken)
	if r.code != 0 {
		t.Fatalf("--allow-tty: exit %d %q", r.code, r.stderr)
	}
	parseJSONBundle(t, []byte(r.stdout))
}

// rotate-key refuses a terminal the same way.
func TestRotateKey_StdoutTerminalRefused(t *testing.T) {
	f := newFakeCP(t)
	r := runCmd(t, enroll, enrollArgs(f, "--token-file", tokenFile(t, fakeToken), "--output", "-"), "")
	if r.code != 0 {
		t.Fatalf("enroll: %s", r.stderr)
	}
	_, _, dir := bundleDir(t, parseJSONBundle(t, []byte(r.stdout)))

	orig := stdoutIsTerminal
	stdoutIsTerminal = func(io.Writer) bool { return true }
	t.Cleanup(func() { stdoutIsTerminal = orig })
	before := f.calls.Load()
	r = runCmd(t, rotate, f.args("--credentials-dir", dir, "--rotation-token-file", "-", "--output", "-"), fakeRotateToken)
	if r.code == 0 || !strings.Contains(r.stderr, "--allow-tty") || r.stdout != "" || f.calls.Load() != before {
		t.Fatalf("rotate-key to a terminal: exit %d stdout %d bytes, %d CP calls, stderr %q", r.code, len(r.stdout), f.calls.Load()-before, r.stderr)
	}
}

// The real check: a character device (a terminal, and /dev/null) is a
// terminal, a pipe, a regular file or a buffer is not.
func TestStdoutIsTerminal(t *testing.T) {
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("no %s: %v", os.DevNull, err)
	}
	defer func() { _ = null.Close() }()
	if !stdoutIsTerminal(null) {
		t.Fatalf("%s is a character device, want terminal", os.DevNull)
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pr.Close(); _ = pw.Close() }()
	file, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	for name, w := range map[string]io.Writer{"pipe": pw, "file": file, "buffer": &bytes.Buffer{}} {
		if stdoutIsTerminal(w) {
			t.Fatalf("%s reported as a terminal", name)
		}
	}
}

// A control plane that binds another key at rotation gets no bundle.
func TestRotateKey_FingerprintMismatchWritesNothing(t *testing.T) {
	f := newFakeCP(t)
	r := runCmd(t, enroll, enrollArgs(f, "--token-file", tokenFile(t, fakeToken), "--output", "-"), "")
	if r.code != 0 {
		t.Fatalf("enroll: %s", r.stderr)
	}
	_, _, dir := bundleDir(t, parseJSONBundle(t, []byte(r.stdout)))
	f.rotateOther.Store(true)
	out := filepath.Join(t.TempDir(), "rotated.json")
	r = runCmd(t, rotate, f.args("--credentials-dir", dir, "--rotation-token-file", "-", "--output", out), fakeRotateToken)
	if r.code == 0 || !strings.Contains(r.stderr, "no bundle was written") {
		t.Fatalf("mismatched rotation: exit %d %q", r.code, r.stderr)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("a bundle file was left behind: %v", err)
	}
}

// A sealed challenge that does not open to exactly 32 bytes is refused.
func TestOpenChallenge_RefusesWrongLength(t *testing.T) {
	kp, err := generateWireKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 31, 33, 64} {
		env, err := sealtest.Seal(bytes.Repeat([]byte{7}, n), kp.Public)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := openChallenge(&client.Challenge{ChallengeID: "c1", Sealed: env}, kp); err == nil {
			t.Fatalf("a %d-byte challenge was accepted", n)
		}
	}
	env, err := sealtest.Seal(bytes.Repeat([]byte{7}, 32), kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openChallenge(&client.Challenge{ChallengeID: "c1", Sealed: env}, kp); err != nil {
		t.Fatalf("a 32-byte challenge was refused: %v", err)
	}
}
