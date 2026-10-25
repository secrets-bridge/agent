package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/agent/internal/identity"
	"github.com/secrets-bridge/agent/internal/local"
	"github.com/secrets-bridge/agent/internal/sealing"
	"github.com/secrets-bridge/agent/internal/sealing/sealtest"
	"github.com/secrets-bridge/core/providers"
)

const (
	testAgentID = "0f8b6c7e-2a51-4d3e-9b1f-6c2d4e8a9b10"
	// 32 bytes of 0x41 in unpadded base64url.
	testAgentSecret = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE"
)

// testKey returns a fresh X25519 private key.
func testKey(t *testing.T) []byte {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k.Bytes()
}

// writeCreds lays out a credentials directory the way the CLI bundle is
// stored: three files, mode 0400.
func writeCreds(t *testing.T, dir string, priv []byte) {
	t.Helper()
	files := map[string]string{
		identity.FileAgentID:     testAgentID,
		identity.FileAgentSecret: testAgentSecret,
		identity.FilePrivateKey:  base64.StdEncoding.EncodeToString(priv),
	}
	for name, v := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v), 0o400); err != nil {
			t.Fatal(err)
		}
	}
}

// fakeCP stands in for the control plane. Like AgentAuth it checks
// X-Agent-Secret and then X-Agent-Key-Fingerprint against the bound key on
// every /agents/:id/* request, answering 401 or 409 agent_key_mismatch.
// Wraps are sealed to the bound key at retrieval time, as on the CP.
type fakeCP struct {
	t   *testing.T
	srv *httptest.Server

	failHeartbeats atomic.Int32 // answer this many heartbeats with 503
	revoked        atomic.Bool  // answer every call with 401
	revokeOnly     atomic.Value // if set to a path suffix, only that call gets 401
	requests       atomic.Int32
	heartbeats     atomic.Int32
	claims         atomic.Int32
	mismatches     atomic.Int32
	firstBeatDone  atomic.Bool
	claimsEarly    atomic.Int32

	mu          sync.Mutex
	boundPub    []byte
	fingerprint []string // X-Agent-Key-Fingerprint of every request
	jobs        []map[string]any
	outcomes    map[string]client.JobOutcome
	wrapBodies  map[string]func(boundPub []byte) map[string]any
	posted      [][]byte
	dek         []byte
	heartbeatRq []client.HeartbeatReport
}

func newFakeCP(t *testing.T, boundPriv []byte) *fakeCP {
	t.Helper()
	pub, err := sealing.PublicFromPrivate(boundPriv)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCP{t: t, boundPub: pub, outcomes: map[string]client.JobOutcome{}, wrapBodies: map[string]func([]byte) map[string]any{}}
	f.dek = make([]byte, 32)
	_, _ = rand.Read(f.dek)
	base := "/api/v1/agents/" + testAgentID
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+base+"/heartbeat", f.auth(func(w http.ResponseWriter, r *http.Request) {
		if f.failHeartbeats.Load() > 0 {
			f.failHeartbeats.Add(-1)
			http.Error(w, `{"error":"unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		var rep client.HeartbeatReport
		_ = json.NewDecoder(r.Body).Decode(&rep)
		f.mu.Lock()
		f.heartbeatRq = append(f.heartbeatRq, rep)
		f.mu.Unlock()
		f.heartbeats.Add(1)
		f.firstBeatDone.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("POST "+base+"/jobs/claim", f.auth(f.claim))
	mux.HandleFunc("POST "+base+"/jobs/{job}/complete", f.auth(func(w http.ResponseWriter, r *http.Request) {
		var out client.JobOutcome
		_ = json.NewDecoder(r.Body).Decode(&out)
		f.mu.Lock()
		f.outcomes[r.PathValue("job")] = out
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("GET "+base+"/wraps/{wrap}", f.auth(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		build, pub := f.wrapBodies[r.PathValue("wrap")], f.boundPub
		f.mu.Unlock()
		if build == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(build(pub))
	}))
	mux.HandleFunc("POST "+base+"/dek", f.auth(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"algorithm":  "aes-256-gcm",
			"plaintext":  base64.StdEncoding.EncodeToString(f.dek),
			"ciphertext": base64.StdEncoding.EncodeToString([]byte("kms-wrapped-dek")),
			"kms_key_id": "local:test",
		})
	}))
	mux.HandleFunc("POST "+base+"/wraps", f.auth(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.posted = append(f.posted, b)
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"wrap_id":"w-new"}`))
	}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected CP call %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCP) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		fp := r.Header.Get("X-Agent-Key-Fingerprint")
		f.mu.Lock()
		f.fingerprint = append(f.fingerprint, fp)
		bound := sealing.Fingerprint(f.boundPub)
		f.mu.Unlock()
		only, _ := f.revokeOnly.Load().(string)
		if (f.revoked.Load() && (only == "" || strings.HasSuffix(r.URL.Path, only))) || r.Header.Get("X-Agent-Secret") != testAgentSecret {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if fp != bound {
			f.mismatches.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"agent_key_mismatch"}`))
			return
		}
		next(w, r)
	}
}

// rotate binds a new key, as POST /agents/:id/key-rotation does. Safe to
// call from any goroutine.
func (f *fakeCP) rotate(t *testing.T, newPriv []byte) {
	pub, err := sealing.PublicFromPrivate(newPriv)
	if err != nil {
		t.Error(err)
		return
	}
	f.mu.Lock()
	f.boundPub = pub
	f.mu.Unlock()
}

func (f *fakeCP) claim(w http.ResponseWriter, _ *http.Request) {
	f.claims.Add(1)
	if !f.firstBeatDone.Load() {
		f.claimsEarly.Add(1)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.jobs) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	job := f.jobs[0]
	f.jobs = f.jobs[1:]
	_ = json.NewEncoder(w).Encode(job)
}

func (f *fakeCP) queue(job map[string]any) {
	f.mu.Lock()
	f.jobs = append(f.jobs, job)
	f.mu.Unlock()
}

func (f *fakeCP) waitOutcome(t *testing.T, jobID string) client.JobOutcome {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		o, ok := f.outcomes[jobID]
		f.mu.Unlock()
		if ok {
			return o
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job %s never completed", jobID)
	return client.JobOutcome{}
}

// fakeProvider is an in-memory provider for the resolver run() is given.
type fakeProvider struct {
	mu    sync.Mutex
	value []byte
	puts  [][]byte
	panic bool
}

func (p *fakeProvider) GetMetadata(context.Context, providers.SecretRef) (providers.SecretMetadata, error) {
	return providers.SecretMetadata{}, errors.New("unused")
}
func (p *fakeProvider) ListMetadata(context.Context, providers.ProviderScope) ([]providers.SecretMetadata, error) {
	return nil, nil
}
func (p *fakeProvider) GetValue(context.Context, providers.SecretRef) (providers.SecretValue, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.panic {
		panic("fake-value in a provider panic")
	}
	if p.value == nil {
		return providers.SecretValue{}, providers.ErrNotFound
	}
	return providers.SecretValue{Bytes: append([]byte(nil), p.value...)}, nil
}
func (p *fakeProvider) PutValue(_ context.Context, _ providers.SecretRef, v providers.SecretValue, _ providers.PutOptions) (providers.SecretVersion, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.puts = append(p.puts, append([]byte(nil), v.Bytes...))
	return providers.SecretVersion{}, nil
}

func (p *fakeProvider) putCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.puts)
}

type runHarness struct {
	cp       *fakeCP
	probes   *local.Probes
	probeURL string
	logs     *lockedWriter
	done     chan error
	cancel   context.CancelFunc

	waitOnce sync.Once
	runErr   error
	finished bool
}

// wait returns run()'s result, waiting up to 5s for it.
func (h *runHarness) wait(t *testing.T) (bool, error) {
	t.Helper()
	h.waitOnce.Do(func() {
		select {
		case h.runErr = <-h.done:
			h.finished = true
		case <-time.After(5 * time.Second):
		}
	})
	return h.finished, h.runErr
}

// startRun loads the credentials from dir exactly as the binary does and
// boots run() against the fake CP with fast intervals.
func startRun(t *testing.T, cp *fakeCP, prov *fakeProvider, dir string) *runHarness {
	t.Helper()
	return startRunWith(t, cp, prov, dir, 10*time.Millisecond)
}

func startRunWith(t *testing.T, cp *fakeCP, prov *fakeProvider, dir string, heartbeat time.Duration) *runHarness {
	t.Helper()
	orig := startupRetry
	startupRetry = retryBackoff{initial: 5 * time.Millisecond, max: 20 * time.Millisecond}
	t.Cleanup(func() { startupRetry = orig })

	id, kp, err := identity.Load(dir)
	if err != nil {
		t.Fatalf("identity.Load: %v", err)
	}

	logs := &lockedWriter{w: &bytes.Buffer{}}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := Config{
		HeartbeatInterval: heartbeat,
		ClaimInterval:     5 * time.Millisecond,
		ClaimConcurrency:  2,
		ClusterName:       "tenant-a-uat",
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &runHarness{cp: cp, probes: local.NewProbes(), logs: logs, done: make(chan error, 1), cancel: cancel}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	probeSrv := local.NewServer("", h.probes, logger)
	go func() { _ = probeSrv.ServeOn(ln) }()
	t.Cleanup(func() { _ = probeSrv.Shutdown(context.Background()) })
	h.probeURL = "http://" + ln.Addr().String()
	resolve := func(string, map[string]any) (providers.Provider, error) { return prov, nil }
	c := client.New(cp.srv.URL).WithKeyFingerprint(kp.Fingerprint)
	go func() { h.done <- run(ctx, logger, cfg, c, id, kp, resolve, h.probes) }()
	t.Cleanup(func() {
		cancel()
		if ok, _ := h.wait(t); !ok {
			t.Error("run did not stop after cancel")
		}
	})
	return h
}

type lockedWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func (l *lockedWriter) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.String()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func credsDir(t *testing.T, priv []byte) string {
	t.Helper()
	dir := t.TempDir()
	writeCreds(t, dir, priv)
	return dir
}

func sealedWrap(t *testing.T, wrapID string, plaintext []byte, recipientFP func(boundPub []byte) string) func([]byte) map[string]any {
	t.Helper()
	sum := sha256.Sum256(plaintext)
	return func(boundPub []byte) map[string]any {
		env, err := sealtest.Seal(plaintext, boundPub)
		if err != nil {
			t.Error(err)
			return nil
		}
		return map[string]any{
			"wrap_id": wrapID, "key_name": "DB_PASSWORD", "byte_length": len(plaintext),
			"content_hash": hex.EncodeToString(sum[:]), "algorithm": "AES-256-GCM",
			"sealed":                    sealtest.Wire(env),
			"recipient_key_fingerprint": recipientFP(boundPub),
		}
	}
}

func patchJob(id, wrapID string) map[string]any {
	return map[string]any{"id": id, "job_type": "patch", "payload": map[string]any{
		"request_id":           "req-1",
		"target_provider_type": "aws-sm",
		"target_secret_ref":    "team-alpha/uat/db",
		"wraps":                []any{map[string]any{"wrap_id": wrapID, "key_name": "DB_PASSWORD"}},
	}}
}

func assertNoValueInLogs(t *testing.T, h *runHarness) {
	t.Helper()
	if strings.Contains(h.logs.String(), "fake-value") {
		t.Fatalf("a value reached the logs: %s", h.logs.String())
	}
}

// ready asks the harness's real loopback probe server for /readyz.
func (h *runHarness) ready() bool {
	resp, err := http.Get(h.probeURL + "/readyz")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A transient failure of the first heartbeat is retried; nothing is
// claimed and readiness stays false until the CP has accepted the
// credential and key.
func TestRun_FirstHeartbeatRetriedBeforeAnyClaim(t *testing.T) {
	priv := testKey(t)
	cp := newFakeCP(t, priv)
	cp.failHeartbeats.Store(3)
	h := startRun(t, cp, &fakeProvider{}, credsDir(t, priv))

	waitFor(t, "claims after the first heartbeat", func() bool { return cp.claims.Load() >= 3 })
	if cp.claimsEarly.Load() != 0 {
		t.Fatalf("agent claimed %d times before its first heartbeat succeeded", cp.claimsEarly.Load())
	}
	waitFor(t, "readiness", h.ready)
}

// Every CP request carries the fingerprint of the key in private_key, and
// the heartbeat reports the router's capabilities (agent#35).
func TestRun_FingerprintHeaderOnEveryRequest(t *testing.T) {
	priv := testKey(t)
	cp := newFakeCP(t, priv)
	prov := &fakeProvider{value: []byte(`{"DB_PASSWORD":"fake-value"}`)}
	cp.wrapBodies["wrap-1"] = sealedWrap(t, "wrap-1", []byte("fake-value"), sealing.Fingerprint)
	cp.queue(patchJob("job-1", "wrap-1"))
	cp.queue(map[string]any{"id": "job-2", "job_type": "read", "payload": map[string]any{
		"request_id": "req-1", "target_provider_type": "aws-sm", "target_secret_ref": "team-alpha/uat/db",
	}})
	startRun(t, cp, prov, credsDir(t, priv))
	if out := cp.waitOutcome(t, "job-1"); out.Status != client.StatusSucceeded {
		t.Fatalf("patch outcome = %+v", out)
	}
	if out := cp.waitOutcome(t, "job-2"); out.Status != client.StatusSucceeded {
		t.Fatalf("read outcome = %+v", out)
	}
	pub, _ := sealing.PublicFromPrivate(priv)
	want := sealing.Fingerprint(pub)
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if len(cp.fingerprint) < 6 {
		t.Fatalf("only %d CP requests seen", len(cp.fingerprint))
	}
	for i, fp := range cp.fingerprint {
		if fp != want {
			t.Fatalf("request %d sent X-Agent-Key-Fingerprint %q want %q", i, fp, want)
		}
	}
	if len(cp.heartbeatRq) == 0 || strings.Join(cp.heartbeatRq[0].Capabilities, ",") != "discover,patch,read" {
		t.Fatalf("heartbeat capabilities = %+v", cp.heartbeatRq)
	}
}

// A CP that has a different key bound answers 409 agent_key_mismatch. The
// agent stops with ErrKeyMismatch after one request: no retry, no claim.
func TestRun_KeyMismatchAtStartIsFatal(t *testing.T) {
	cp := newFakeCP(t, testKey(t))
	h := startRun(t, cp, &fakeProvider{}, credsDir(t, testKey(t)))
	ok, err := h.wait(t)
	if !ok || !errors.Is(err, client.ErrKeyMismatch) {
		t.Fatalf("run = (%v, %v) want ErrKeyMismatch", ok, err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := cp.requests.Load(); n != 1 || cp.claims.Load() != 0 {
		t.Fatalf("requests=%d claims=%d after a fatal mismatch; want 1 request and no claim", n, cp.claims.Load())
	}
	if !strings.Contains(fatalMessage(err), "agent_key_mismatch") {
		t.Fatalf("operator message %q does not name agent_key_mismatch", fatalMessage(err))
	}
}

// A rotation while the agent runs: the next call gets 409, the agent
// stops, and it makes no further requests (no hot loop). Restarted with
// the new bundle it opens wraps sealed to the new key.
func TestRun_RotationStopsOldKeyAndNewBundleWorks(t *testing.T) {
	oldPriv, newPriv := testKey(t), testKey(t)
	cp := newFakeCP(t, oldPriv)
	h := startRun(t, cp, &fakeProvider{}, credsDir(t, oldPriv))
	waitFor(t, "claims on the old key", func() bool { return cp.claims.Load() >= 2 })

	cp.rotate(t, newPriv)
	ok, err := h.wait(t)
	if !ok || !errors.Is(err, client.ErrKeyMismatch) {
		t.Fatalf("run = (%v, %v) want ErrKeyMismatch after rotation", ok, err)
	}
	after := cp.requests.Load()
	time.Sleep(50 * time.Millisecond)
	if cp.requests.Load() != after {
		t.Fatalf("agent kept calling the CP after a fatal mismatch (%d -> %d)", after, cp.requests.Load())
	}
	if h.ready() {
		t.Fatal("agent still ready after a fatal mismatch")
	}

	prov := &fakeProvider{}
	cp.wrapBodies["wrap-1"] = sealedWrap(t, "wrap-1", []byte("fake-value"), sealing.Fingerprint)
	cp.queue(patchJob("job-1", "wrap-1"))
	h2 := startRun(t, cp, prov, credsDir(t, newPriv))
	if out := cp.waitOutcome(t, "job-1"); out.Status != client.StatusSucceeded {
		t.Fatalf("outcome with the new bundle = %+v", out)
	}
	if prov.putCount() != 1 {
		t.Fatal("value sealed to the new key did not reach the provider")
	}
	assertNoValueInLogs(t, h2)
}

// Revocation: a 401 at start or mid-run stops the agent with
// ErrUnauthorized and no further requests.
func TestRun_RevocationIsFatal(t *testing.T) {
	t.Run("at start", func(t *testing.T) {
		priv := testKey(t)
		cp := newFakeCP(t, priv)
		cp.revoked.Store(true)
		h := startRun(t, cp, &fakeProvider{}, credsDir(t, priv))
		ok, err := h.wait(t)
		if !ok || !errors.Is(err, client.ErrUnauthorized) {
			t.Fatalf("run = (%v, %v) want ErrUnauthorized", ok, err)
		}
		if cp.requests.Load() != 1 {
			t.Fatalf("requests = %d want 1", cp.requests.Load())
		}
	})
	t.Run("mid-run", func(t *testing.T) {
		priv := testKey(t)
		cp := newFakeCP(t, priv)
		h := startRun(t, cp, &fakeProvider{}, credsDir(t, priv))
		waitFor(t, "readiness", h.ready)
		cp.revoked.Store(true)
		ok, err := h.wait(t)
		if !ok || !errors.Is(err, client.ErrUnauthorized) {
			t.Fatalf("run = (%v, %v) want ErrUnauthorized", ok, err)
		}
		after := cp.requests.Load()
		time.Sleep(50 * time.Millisecond)
		if cp.requests.Load() != after {
			t.Fatal("agent kept calling the CP after revocation")
		}
	})
}

// A wrap whose recipient_key_fingerprint is not this agent's key is not
// opened and the provider is not written.
func TestRun_WrapSealedToAnotherKeyRefused(t *testing.T) {
	priv := testKey(t)
	cp := newFakeCP(t, priv)
	other, _ := sealing.PublicFromPrivate(testKey(t))
	prov := &fakeProvider{}
	cp.wrapBodies["wrap-1"] = sealedWrap(t, "wrap-1", []byte("fake-value"), func([]byte) string { return sealing.Fingerprint(other) })
	cp.queue(patchJob("job-1", "wrap-1"))
	h := startRun(t, cp, prov, credsDir(t, priv))
	out := cp.waitOutcome(t, "job-1")
	if out.Status != client.StatusFailed || !strings.Contains(out.Error, "different public key") {
		t.Fatalf("outcome = %+v want failed wrong-key refusal", out)
	}
	if prov.putCount() != 0 {
		t.Fatal("provider written from a wrap sealed to another key")
	}
	assertNoValueInLogs(t, h)
}

// An unsealed wrap is refused (no fallback) and the provider is never
// written.
func TestRun_PatchJobRefusesUnsealedWrap(t *testing.T) {
	priv := testKey(t)
	cp := newFakeCP(t, priv)
	prov := &fakeProvider{}
	plaintext := []byte("fake-value")
	sum := sha256.Sum256(plaintext)
	cp.wrapBodies["wrap-1"] = func(pub []byte) map[string]any {
		return map[string]any{
			"wrap_id": "wrap-1", "key_name": "DB_PASSWORD", "byte_length": len(plaintext),
			"content_hash": hex.EncodeToString(sum[:]), "algorithm": "AES-256-GCM",
			"value":                     base64.StdEncoding.EncodeToString(plaintext),
			"recipient_key_fingerprint": sealing.Fingerprint(pub),
		}
	}
	cp.queue(patchJob("job-1", "wrap-1"))
	h := startRun(t, cp, prov, credsDir(t, priv))

	out := cp.waitOutcome(t, "job-1")
	if out.Status != client.StatusFailed || !strings.Contains(out.Error, "downgrade") {
		t.Fatalf("outcome = %+v want failed downgrade refusal", out)
	}
	if prov.putCount() != 0 {
		t.Fatal("provider written from an unsealed wrap")
	}
	assertNoValueInLogs(t, h)
}

// A malformed sealed nonce (the AGT-N-05 crash) fails that job; the agent
// keeps running and completes the next one.
func TestRun_MalformedSealedNonceFailsJobAgentSurvives(t *testing.T) {
	priv := testKey(t)
	cp := newFakeCP(t, priv)
	cp.wrapBodies["bad"] = func(pub []byte) map[string]any {
		env, _ := sealtest.Seal([]byte("fake-value"), pub)
		env.Nonce = []byte{1, 2, 3}
		return map[string]any{
			"wrap_id": "bad", "content_hash": "x", "algorithm": "AES-256-GCM",
			"sealed": sealtest.Wire(env), "recipient_key_fingerprint": sealing.Fingerprint(pub),
		}
	}
	cp.queue(patchJob("job-bad", "bad"))
	cp.queue(map[string]any{"id": "job-next", "job_type": "sync", "payload": map[string]any{}})
	startRun(t, cp, &fakeProvider{}, credsDir(t, priv))

	if out := cp.waitOutcome(t, "job-bad"); out.Status != client.StatusFailed {
		t.Fatalf("malformed nonce outcome = %+v", out)
	}
	cp.waitOutcome(t, "job-next")
}

// A provider that panics mid-job: the job is reported failed with no panic
// text, and the agent carries on.
func TestRun_ExecutorPanicReportedFailed(t *testing.T) {
	priv := testKey(t)
	cp := newFakeCP(t, priv)
	cp.queue(map[string]any{"id": "job-1", "job_type": "read", "payload": map[string]any{
		"request_id": "req-1", "target_provider_type": "aws-sm", "target_secret_ref": "team-alpha/uat/db",
	}})
	cp.queue(map[string]any{"id": "job-2", "job_type": "sync", "payload": map[string]any{}})
	h := startRun(t, cp, &fakeProvider{panic: true}, credsDir(t, priv))

	out := cp.waitOutcome(t, "job-1")
	if out.Status != client.StatusFailed || strings.Contains(out.Error, "fake-value") {
		t.Fatalf("outcome = %+v", out)
	}
	cp.waitOutcome(t, "job-2")
	assertNoValueInLogs(t, h)
}

// AGT-N-06: an unknown job type is completed as failed, never succeeded.
func TestRun_UnknownJobTypeReportedFailed(t *testing.T) {
	priv := testKey(t)
	cp := newFakeCP(t, priv)
	cp.queue(map[string]any{"id": "job-1", "job_type": "sync", "payload": map[string]any{}})
	startRun(t, cp, &fakeProvider{}, credsDir(t, priv))
	out := cp.waitOutcome(t, "job-1")
	if out.Status != client.StatusFailed || !strings.Contains(out.Error, "unsupported job type") {
		t.Fatalf("outcome = %+v want failed unsupported job type", out)
	}
}

// The read flow posts only the envelope; the plaintext never appears in
// the request body.
func TestRun_ReadJobPostsEnvelopeOnly(t *testing.T) {
	priv := testKey(t)
	cp := newFakeCP(t, priv)
	prov := &fakeProvider{value: []byte(`{"DB_PASSWORD":"fake-value"}`)}
	cp.queue(map[string]any{"id": "job-1", "job_type": "read", "payload": map[string]any{
		"request_id": "req-1", "target_provider_type": "aws-sm", "target_secret_ref": "team-alpha/uat/db",
	}})
	startRun(t, cp, prov, credsDir(t, priv))
	if out := cp.waitOutcome(t, "job-1"); out.Status != client.StatusSucceeded {
		t.Fatalf("outcome = %+v", out)
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if len(cp.posted) != 1 {
		t.Fatalf("posted %d wraps", len(cp.posted))
	}
	var raw map[string]any
	_ = json.Unmarshal(cp.posted[0], &raw)
	if _, ok := raw["value"]; ok || raw["envelope"] == nil {
		t.Fatalf("posted body is not envelope-only: keys %v", keysOf(raw))
	}
	if bytes.Contains(cp.posted[0], []byte("fake-value")) ||
		bytes.Contains(cp.posted[0], []byte(base64.StdEncoding.EncodeToString([]byte("fake-value")))) {
		t.Fatal("plaintext crossed the wire")
	}
}

// Each loop stops the agent on its own: a revocation seen only by the
// claim loop (heartbeats an hour apart), and one seen only by the
// heartbeat loop (claims keep succeeding).
func TestRun_EachLoopStopsOnFatal(t *testing.T) {
	t.Run("claim loop", func(t *testing.T) {
		priv := testKey(t)
		cp := newFakeCP(t, priv)
		h := startRunWith(t, cp, &fakeProvider{}, credsDir(t, priv), time.Hour)
		waitFor(t, "readiness", h.ready)
		cp.revoked.Store(true)
		if ok, err := h.wait(t); !ok || !errors.Is(err, client.ErrUnauthorized) {
			t.Fatalf("run = (%v, %v) want ErrUnauthorized from the claim loop", ok, err)
		}
	})
	t.Run("heartbeat loop", func(t *testing.T) {
		priv := testKey(t)
		cp := newFakeCP(t, priv)
		h := startRunWith(t, cp, &fakeProvider{}, credsDir(t, priv), 10*time.Millisecond)
		waitFor(t, "readiness", h.ready)
		cp.revokeOnly.Store("/heartbeat")
		cp.revoked.Store(true)
		if ok, err := h.wait(t); !ok || !errors.Is(err, client.ErrUnauthorized) {
			t.Fatalf("run = (%v, %v) want ErrUnauthorized from the heartbeat loop", ok, err)
		}
	})
}
