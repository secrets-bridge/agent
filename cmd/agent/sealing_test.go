package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/agent/internal/identity"
	"github.com/secrets-bridge/agent/internal/local"
	"github.com/secrets-bridge/agent/internal/sealing"
	"github.com/secrets-bridge/core/providers"
)

// fakeCP is a control plane good enough to drive run() end to end: public
// key registration, heartbeat, claim (from a queue), complete, wrap fetch
// and wrap post. It records what the agent did and in which order.
type fakeCP struct {
	t   *testing.T
	srv *httptest.Server

	failPubKey    atomic.Int32 // fail this many PUT /public-key calls with 503
	pubKeyStatus  atomic.Int32 // if non-zero, always answer PUT /public-key with this
	pubKeyCalls   atomic.Int32
	registered    atomic.Bool
	heartbeats    atomic.Int32
	claims        atomic.Int32
	claimsEarly   atomic.Int32 // claims seen before registration succeeded
	heartbeatEarl atomic.Int32 // heartbeats seen before registration succeeded

	mu         sync.Mutex
	agentPub   []byte
	jobs       []map[string]any
	outcomes   map[string]client.JobOutcome
	wrapBodies map[string]func(agentPub []byte) map[string]any
	posted     [][]byte
	dek        []byte
}

func newFakeCP(t *testing.T) *fakeCP {
	t.Helper()
	f := &fakeCP{t: t, outcomes: map[string]client.JobOutcome{}, wrapBodies: map[string]func([]byte) map[string]any{}}
	f.dek = make([]byte, 32)
	_, _ = rand.Read(f.dek)
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/v1/agents/agent-a/public-key", f.putPublicKey)
	mux.HandleFunc("POST /api/v1/agents/agent-a/heartbeat", func(w http.ResponseWriter, _ *http.Request) {
		f.heartbeats.Add(1)
		if !f.registered.Load() {
			f.heartbeatEarl.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/v1/agents/agent-a/jobs/claim", f.claim)
	mux.HandleFunc("POST /api/v1/agents/agent-a/jobs/{job}/complete", func(w http.ResponseWriter, r *http.Request) {
		var out client.JobOutcome
		_ = json.NewDecoder(r.Body).Decode(&out)
		f.mu.Lock()
		f.outcomes[r.PathValue("job")] = out
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/v1/agents/agent-a/wraps/{wrap}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		build, pub := f.wrapBodies[r.PathValue("wrap")], f.agentPub
		f.mu.Unlock()
		if build == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(build(pub))
	})
	mux.HandleFunc("POST /api/v1/agents/agent-a/dek", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"algorithm":  "aes-256-gcm",
			"plaintext":  base64.StdEncoding.EncodeToString(f.dek),
			"ciphertext": base64.StdEncoding.EncodeToString([]byte("kms-wrapped-dek")),
			"kms_key_id": "local:test",
		})
	})
	mux.HandleFunc("POST /api/v1/agents/agent-a/wraps", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.posted = append(f.posted, b)
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"wrap_id":"w-new"}`))
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCP) putPublicKey(w http.ResponseWriter, r *http.Request) {
	f.pubKeyCalls.Add(1)
	if s := f.pubKeyStatus.Load(); s != 0 {
		w.WriteHeader(int(s))
		return
	}
	if f.failPubKey.Load() > 0 {
		f.failPubKey.Add(-1)
		http.Error(w, `{"error":"unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	var body client.SetPublicKeyRequest
	_ = json.NewDecoder(r.Body).Decode(&body)
	pub, _ := base64.StdEncoding.DecodeString(body.PublicKey)
	f.mu.Lock()
	f.agentPub = pub
	f.mu.Unlock()
	f.registered.Store(true)
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeCP) claim(w http.ResponseWriter, _ *http.Request) {
	f.claims.Add(1)
	if !f.registered.Load() {
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

func (f *fakeCP) outcome(jobID string) (client.JobOutcome, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.outcomes[jobID]
	return o, ok
}

func (f *fakeCP) waitOutcome(t *testing.T, jobID string) client.JobOutcome {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if o, ok := f.outcome(jobID); ok {
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
	prov     *fakeProvider
	probes   *local.Probes
	probeURL string
	logs     *lockedWriter
	done     chan error
	cancel   context.CancelFunc

	waitOnce sync.Once
	runErr   error
	finished bool
}

// wait returns run()'s result, waiting up to 5s for it. Safe to call more
// than once.
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

// startRun boots run() against the fake CP with an ephemeral keypair (the
// mode that used to fall back to plaintext) and fast intervals.
func startRun(t *testing.T, cp *fakeCP, prov *fakeProvider) *runHarness {
	t.Helper()
	orig := pubKeyRetry
	pubKeyRetry = retryBackoff{initial: 5 * time.Millisecond, max: 20 * time.Millisecond}
	t.Cleanup(func() { pubKeyRetry = orig })

	t.Setenv(identity.EnvPrivateKey, "")
	t.Setenv(identity.EnvPrivateKeyFile, "")
	kp, err := identity.LoadOrGenerateKeyPair(identity.EnvPrivateKey, identity.EnvPrivateKeyFile)
	if err != nil || kp.Source != identity.KeyPairSourceEphemeral {
		t.Fatalf("ephemeral keypair: %v %v", kp, err)
	}

	logs := &lockedWriter{w: &bytes.Buffer{}}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := Config{
		HeartbeatInterval: time.Hour,
		ClaimInterval:     5 * time.Millisecond,
		ClaimConcurrency:  2,
		ClusterName:       "tenant-a-uat",
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &runHarness{cp: cp, prov: prov, probes: local.NewProbes(), logs: logs, done: make(chan error, 1), cancel: cancel}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	probeSrv := local.NewServer("", h.probes, logger)
	go func() { _ = probeSrv.ServeOn(ln) }()
	t.Cleanup(func() { _ = probeSrv.Shutdown(context.Background()) })
	h.probeURL = "http://" + ln.Addr().String()
	resolve := func(string, map[string]any) (providers.Provider, error) { return prov, nil }
	id := identity.Identity{AgentID: "agent-a", AgentSecret: "secret-a"}
	go func() { h.done <- run(ctx, logger, cfg, client.New(cp.srv.URL), id, kp, resolve, h.probes) }()
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

// AGT-02: a failed boot-time PUT /public-key no longer drops the agent into
// plaintext mode. It retries with backoff and claims nothing (and sends no
// heartbeat) until the CP has the key, even with an ephemeral keypair.
func TestRun_FailedRegistrationBlocksClaimingUntilItSucceeds(t *testing.T) {
	cp := newFakeCP(t)
	cp.failPubKey.Store(3)
	h := startRun(t, cp, &fakeProvider{})

	waitFor(t, "claims after registration", func() bool { return cp.claims.Load() >= 3 })
	if got := cp.pubKeyCalls.Load(); got != 4 {
		t.Fatalf("public-key calls = %d want 3 failures + 1 success", got)
	}
	if cp.claimsEarly.Load() != 0 || cp.heartbeatEarl.Load() != 0 {
		t.Fatalf("agent claimed %d jobs / sent %d heartbeats before its key was registered",
			cp.claimsEarly.Load(), cp.heartbeatEarl.Load())
	}
	waitFor(t, "readiness", h.ready)
}

func TestRun_RegistrationNeverSucceeds_NothingClaimed(t *testing.T) {
	cp := newFakeCP(t)
	cp.pubKeyStatus.Store(http.StatusServiceUnavailable)
	h := startRun(t, cp, &fakeProvider{})

	waitFor(t, "several registration attempts", func() bool { return cp.pubKeyCalls.Load() >= 5 })
	time.Sleep(50 * time.Millisecond) // ten claim intervals
	if cp.claims.Load() != 0 || cp.heartbeats.Load() != 0 {
		t.Fatalf("claims=%d heartbeats=%d while registration keeps failing", cp.claims.Load(), cp.heartbeats.Load())
	}
	if h.ready() {
		t.Fatal("agent reported ready without a registered key")
	}
	h.cancel()
	ok, err := h.wait(t)
	if !ok {
		t.Fatal("run did not return after cancel")
	}
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("run returned %v want a registration error wrapping context.Canceled", err)
	}
}

func TestRun_RegistrationUnauthorized_StopsWithoutRetry(t *testing.T) {
	cp := newFakeCP(t)
	cp.pubKeyStatus.Store(http.StatusUnauthorized)
	h := startRun(t, cp, &fakeProvider{})
	ok, err := h.wait(t)
	if !ok {
		t.Fatal("run kept retrying a 401")
	}
	if !errors.Is(err, client.ErrUnauthorized) {
		t.Fatalf("run returned %v want ErrUnauthorized", err)
	}
	if cp.pubKeyCalls.Load() != 1 || cp.claims.Load() != 0 {
		t.Fatalf("public-key calls=%d claims=%d", cp.pubKeyCalls.Load(), cp.claims.Load())
	}
}

// End to end: once registration succeeded the executors hold the keypair,
// so an unsealed wrap from the CP is refused (no fallback) and the
// provider is never written.
func TestRun_PatchJobRefusesUnsealedWrap(t *testing.T) {
	cp := newFakeCP(t)
	cp.failPubKey.Store(1)
	prov := &fakeProvider{}
	plaintext := []byte("fake-value")
	sum := sha256.Sum256(plaintext)
	cp.wrapBodies["wrap-1"] = func([]byte) map[string]any {
		return map[string]any{
			"wrap_id": "wrap-1", "key_name": "DB_PASSWORD", "byte_length": len(plaintext),
			"content_hash": hex.EncodeToString(sum[:]), "algorithm": "AES-256-GCM",
			"value": base64.StdEncoding.EncodeToString(plaintext),
		}
	}
	cp.queue(patchJob("job-1", "wrap-1"))
	h := startRun(t, cp, prov)

	out := cp.waitOutcome(t, "job-1")
	if out.Status != client.StatusFailed || !strings.Contains(out.Error, "downgrade") {
		t.Fatalf("outcome = %+v want failed downgrade refusal", out)
	}
	if prov.putCount() != 0 {
		t.Fatal("provider written from an unsealed wrap")
	}
	assertNoValueInLogs(t, h)
}

func TestRun_PatchJobOpensSealedWrap(t *testing.T) {
	cp := newFakeCP(t)
	prov := &fakeProvider{}
	plaintext := []byte("fake-value")
	sum := sha256.Sum256(plaintext)
	cp.wrapBodies["wrap-1"] = func(agentPub []byte) map[string]any {
		ct, nonce, eph := sealToAgent(t, plaintext, agentPub)
		return map[string]any{
			"wrap_id": "wrap-1", "key_name": "DB_PASSWORD", "byte_length": len(plaintext),
			"content_hash": hex.EncodeToString(sum[:]), "algorithm": "AES-256-GCM",
			"sealed": map[string]string{
				"algorithm":            sealing.Algorithm,
				"ciphertext":           base64.StdEncoding.EncodeToString(ct),
				"nonce":                base64.StdEncoding.EncodeToString(nonce),
				"ephemeral_public_key": base64.StdEncoding.EncodeToString(eph),
			},
		}
	}
	cp.queue(patchJob("job-1", "wrap-1"))
	h := startRun(t, cp, prov)

	out := cp.waitOutcome(t, "job-1")
	if out.Status != client.StatusSucceeded {
		t.Fatalf("outcome = %+v", out)
	}
	prov.mu.Lock()
	reached := len(prov.puts) == 1 && bytes.Contains(prov.puts[0], plaintext)
	prov.mu.Unlock()
	if !reached {
		t.Fatal("sealed value did not reach the provider")
	}
	assertNoValueInLogs(t, h)
}

// A malformed sealed nonce (the AGT-N-05 crash) fails that job; the agent
// keeps running and completes the next one.
func TestRun_MalformedSealedNonceFailsJobAgentSurvives(t *testing.T) {
	cp := newFakeCP(t)
	prov := &fakeProvider{}
	cp.wrapBodies["bad"] = func(agentPub []byte) map[string]any {
		ct, _, eph := sealToAgent(t, []byte("fake-value"), agentPub)
		return map[string]any{
			"wrap_id": "bad", "content_hash": "x", "algorithm": "AES-256-GCM",
			"sealed": map[string]string{
				"algorithm":            sealing.Algorithm,
				"ciphertext":           base64.StdEncoding.EncodeToString(ct),
				"nonce":                base64.StdEncoding.EncodeToString([]byte{1, 2, 3}),
				"ephemeral_public_key": base64.StdEncoding.EncodeToString(eph),
			},
		}
	}
	cp.queue(patchJob("job-bad", "bad"))
	cp.queue(map[string]any{"id": "job-next", "job_type": "sync", "payload": map[string]any{}})
	startRun(t, cp, prov)

	if out := cp.waitOutcome(t, "job-bad"); out.Status != client.StatusFailed {
		t.Fatalf("malformed nonce outcome = %+v", out)
	}
	cp.waitOutcome(t, "job-next") // the agent is still claiming
}

// A provider that panics mid-job: the job is reported failed with no panic
// text, and the agent carries on.
func TestRun_ExecutorPanicReportedFailed(t *testing.T) {
	cp := newFakeCP(t)
	prov := &fakeProvider{panic: true}
	cp.queue(map[string]any{"id": "job-1", "job_type": "read", "payload": map[string]any{
		"request_id": "req-1", "target_provider_type": "aws-sm", "target_secret_ref": "team-alpha/uat/db",
	}})
	cp.queue(map[string]any{"id": "job-2", "job_type": "sync", "payload": map[string]any{}})
	h := startRun(t, cp, prov)

	out := cp.waitOutcome(t, "job-1")
	if out.Status != client.StatusFailed || strings.Contains(out.Error, "fake-value") {
		t.Fatalf("outcome = %+v", out)
	}
	cp.waitOutcome(t, "job-2")
	assertNoValueInLogs(t, h)
}

// AGT-N-06: an unknown job type is completed as failed, never succeeded.
func TestRun_UnknownJobTypeReportedFailed(t *testing.T) {
	cp := newFakeCP(t)
	cp.queue(map[string]any{"id": "job-1", "job_type": "sync", "payload": map[string]any{}})
	startRun(t, cp, &fakeProvider{})
	out := cp.waitOutcome(t, "job-1")
	if out.Status != client.StatusFailed || !strings.Contains(out.Error, "unsupported job type") {
		t.Fatalf("outcome = %+v want failed unsupported job type", out)
	}
}

// The read flow posts only the envelope; the plaintext never appears in
// the request body.
func TestRun_ReadJobPostsEnvelopeOnly(t *testing.T) {
	cp := newFakeCP(t)
	prov := &fakeProvider{value: []byte(`{"DB_PASSWORD":"fake-value"}`)}
	cp.queue(map[string]any{"id": "job-1", "job_type": "read", "payload": map[string]any{
		"request_id": "req-1", "target_provider_type": "aws-sm", "target_secret_ref": "team-alpha/uat/db",
	}})
	startRun(t, cp, prov)
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

// sealToAgent mirrors api/pkg/sealing.Seal so the fake CP can seal to the
// public key the agent registered.
func sealToAgent(t *testing.T, plaintext, recipientPub []byte) (ct, nonce, ephPub []byte) {
	t.Helper()
	curve := ecdh.X25519()
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rcpt, err := curve.NewPublicKey(recipientPub)
	if err != nil {
		t.Fatalf("recipient key: %v", err)
	}
	shared, err := eph.ECDH(rcpt)
	if err != nil {
		t.Fatal(err)
	}
	ephPub = eph.PublicKey().Bytes()
	salt := append(append([]byte{}, ephPub...), recipientPub...)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(func() hash.Hash { return sha256.New() }, shared, salt, []byte("secrets-bridge.wrap.v1")), key); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce = make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	return gcm.Seal(nil, nonce, plaintext, nil), nonce, ephPub
}
