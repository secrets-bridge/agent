package transport

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/secrets-bridge/agent/internal/client"
)

// AGT-N-02 end to end with the transport the binary builds: an https CP
// that redirects to a plain-http host on another port must not get the
// agent to follow, and the redirect target must never see X-Agent-Secret.
func TestBuildHTTPClient_RefusesHTTPSToHTTPRedirect(t *testing.T) {
	var targetHits, targetSecrets atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		if r.Header.Get("X-Agent-Secret") != "" {
			targetSecrets.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)

	cp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(cp.Close)

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cp.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	hc, err := NewHTTPClient(Options{CPEndpoint: cp.URL, CAFile: caPath, TLSServerName: "example.com"})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	// Raw transport check: the client itself must not follow.
	req, _ := http.NewRequest(http.MethodPost, cp.URL+"/api/v1/agents/agent-a/heartbeat", http.NoBody)
	req.Header.Set("X-Agent-Secret", "secret-a")
	resp, err := hc.Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	// And through the CP client the agent actually uses.
	c := client.New(cp.URL).WithHTTPClient(hc)
	_, hbErr := c.Heartbeat(context.Background(), "agent-a", "secret-a", &client.HeartbeatReport{Status: "active"})

	if targetHits.Load() != 0 {
		t.Fatalf("redirect followed: target hit %d times, %d with X-Agent-Secret", targetHits.Load(), targetSecrets.Load())
	}
	if resp == nil || resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("raw transport did not return the 307 as-is: resp=%v err=%v", resp, err)
	}
	if hbErr == nil {
		t.Fatal("heartbeat treated a 307 as success")
	}
}

// AGT-N-08: credentials in SB_CP_ENDPOINT never reach the startup log.
func TestRedactEndpoint(t *testing.T) {
	cases := map[string]string{
		"https://cp.example.com":                            "https://cp.example.com",
		"https://cp.example.com:8443/base":                  "https://cp.example.com:8443/base",
		"https://user:fake-password@cp.example.com/":        "https://cp.example.com/",
		"https://fake-token@cp.example.com":                 "https://cp.example.com",
		"https://cp.example.com/?token=fake-token#frag":     "https://cp.example.com/",
		"http://user:fake-password@127.0.0.1:18080/api?x=y": "http://127.0.0.1:18080/api",
		"%%not a url fake-password":                         "<unparseable endpoint>",
	}
	for in, want := range cases {
		got := RedactEndpoint(in)
		if got != want {
			t.Errorf("RedactEndpoint(%q) = %q want %q", in, got, want)
		}
		if strings.Contains(got, "fake-") {
			t.Errorf("RedactEndpoint(%q) kept a credential: %q", in, got)
		}
	}
}

// The startup error for an unparseable SB_CP_ENDPOINT must not echo the
// URL, which can carry userinfo.
func TestValidateEndpoint_ParseErrorDoesNotEchoCredentials(t *testing.T) {
	_, err := ValidateEndpoint("https://agent:fake-password%zz@cp.example.com", false)
	if err == nil {
		t.Fatal("malformed endpoint accepted")
	}
	if strings.Contains(err.Error(), "fake-password") || strings.Contains(err.Error(), "agent:") {
		t.Fatalf("endpoint error carries the credential: %v", err)
	}
	if !strings.Contains(err.Error(), "valid URL") {
		t.Fatalf("error lost its hint: %v", err)
	}
}
