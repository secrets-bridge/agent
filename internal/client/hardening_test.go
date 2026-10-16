package client_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/secrets-bridge/agent/internal/client"
)

// redirectTarget counts requests and remembers any X-Agent-Secret it was
// sent. It stands in for an attacker-chosen host a CP (or a proxy in front
// of it) redirects the agent to.
type redirectTarget struct {
	hits    atomic.Int32
	secrets atomic.Int32
	srv     *httptest.Server
}

func newRedirectTarget(t *testing.T) *redirectTarget {
	t.Helper()
	rt := &redirectTarget{}
	rt.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt.hits.Add(1)
		if r.Header.Get("X-Agent-Secret") != "" {
			rt.secrets.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(rt.srv.Close)
	return rt
}

func redirectingCP(t *testing.T, status int, to string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, to+r.URL.Path, status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// AGT-N-02: the CP client must never follow a redirect. Following one
// re-sends X-Agent-Secret (and, for 307/308, the body) to whatever host
// the Location header names.
func TestClient_DoesNotFollowRedirects(t *testing.T) {
	statuses := []int{
		http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect,
	}
	calls := map[string]func(c *client.Client) error{
		"heartbeat": func(c *client.Client) error {
			_, err := c.Heartbeat(context.Background(), "agent-a", "secret-a", &client.HeartbeatReport{Status: "active"})
			return err
		},
		"claim": func(c *client.Client) error {
			_, err := c.ClaimJob(context.Background(), "agent-a", "secret-a")
			return err
		},
		"complete": func(c *client.Client) error {
			return c.CompleteJob(context.Background(), "agent-a", "secret-a", "job-1", client.JobOutcome{Status: client.StatusSucceeded})
		},
		"public-key": func(c *client.Client) error {
			return c.SetPublicKey(context.Background(), "agent-a", "secret-a", make([]byte, 32), "x25519")
		},
		"dek": func(c *client.Client) error {
			_, err := c.IssueDEK(context.Background(), "agent-a", "secret-a")
			return err
		},
		"enroll": func(c *client.Client) error {
			_, err := c.Enroll(context.Background(), client.EnrollRequest{EnrollmentToken: "fake-enroll-token", AgentName: "a"})
			return err
		},
	}
	builders := map[string]func(base string) *client.Client{
		"default http client": func(base string) *client.Client { return client.New(base) },
		"injected http client": func(base string) *client.Client {
			return client.New(base).WithHTTPClient(&http.Client{})
		},
	}
	for bname, build := range builders {
		for _, status := range statuses {
			for cname, call := range calls {
				t.Run(bname+"/"+http.StatusText(status)+"/"+cname, func(t *testing.T) {
					target := newRedirectTarget(t)
					cp := redirectingCP(t, status, target.srv.URL)
					err := call(build(cp.URL))
					if target.hits.Load() != 0 {
						t.Fatalf("client followed a %d redirect (%d hits, %d carried X-Agent-Secret)",
							status, target.hits.Load(), target.secrets.Load())
					}
					if err == nil {
						t.Fatalf("a %d response was treated as success", status)
					}
					if strings.Contains(err.Error(), "secret-a") || strings.Contains(err.Error(), "fake-enroll-token") {
						t.Fatalf("error carries a credential: %v", err)
					}
				})
			}
		}
	}
}

// AGT-N-08: response bodies are size-bounded. A CP (or anything that can
// answer for it) must not be able to make the agent buffer an unbounded
// body.
func TestClaimJob_OversizedResponseRejected(t *testing.T) {
	huge := `{"id":"job-1","job_type":"read","payload":{"pad":"` + strings.Repeat("A", 2<<20) + `"}}`
	c, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(huge))
	})
	job, err := c.ClaimJob(t.Context(), "agent-a", "secret-a")
	if err == nil {
		t.Fatalf("oversized claim response accepted (job %q)", job.ID)
	}
	if !errors.Is(err, client.ErrResponseTooLarge) {
		t.Fatalf("got %v want ErrResponseTooLarge", err)
	}
}

func TestGetWrap_OversizedResponseRejected(t *testing.T) {
	huge := `{"wrap_id":"w","sealed":{"algorithm":"x25519-hkdf-aes-gcm","ciphertext":"` +
		strings.Repeat("A", 9<<20) + `","nonce":"","ephemeral_public_key":""},"content_hash":"x"}`
	c, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(huge))
	})
	_, err := c.GetWrap(t.Context(), "agent-a", "secret-a", "w", make([]byte, 32), make([]byte, 32))
	if !errors.Is(err, client.ErrResponseTooLarge) {
		t.Fatalf("got %v want a size-limit error", err)
	}
}

func TestIssueDEK_OversizedResponseRejected(t *testing.T) {
	huge := `{"algorithm":"aes-256-gcm","plaintext":"","ciphertext":"","kms_key_id":"` + strings.Repeat("k", 1<<20) + `"}`
	c, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(huge))
	})
	if _, err := c.IssueDEK(t.Context(), "agent-a", "secret-a"); !errors.Is(err, client.ErrResponseTooLarge) {
		t.Fatalf("got %v want a size-limit error", err)
	}
}

func TestPostSecretsBulk_OversizedResponseRejected(t *testing.T) {
	huge := `{"count":1,"upserted_ids":["` + strings.Repeat("i", 9<<20) + `"]}`
	c, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(huge))
	})
	_, err := c.PostSecretsBulk(t.Context(), "agent-a", "secret-a", client.SecretBulkRequest{ClusterName: "tenant-a-uat"})
	if !errors.Is(err, client.ErrResponseTooLarge) {
		t.Fatalf("got %v want a size-limit error", err)
	}
}

func TestEnroll_OversizedResponseRejected(t *testing.T) {
	huge := `{"agent_id":"a","agent_token":"t","provider_connection_id":"` + strings.Repeat("p", 1<<20) + `"}`
	c, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(huge))
	})
	if _, err := c.Enroll(t.Context(), client.EnrollRequest{EnrollmentToken: "fake-enroll-token"}); !errors.Is(err, client.ErrResponseTooLarge) {
		t.Fatalf("got %v want a size-limit error", err)
	}
}

// AGT-02: without a keypair the client refuses to fetch a wrap at all;
// it never accepts a plaintext `value` off the wire.
func TestGetWrap_NoKeypair_RefusesUnsealedValue(t *testing.T) {
	plaintext := []byte("fake-value")
	sum := sha256.Sum256(plaintext)
	body := `{"wrap_id":"w","value":"` + base64.StdEncoding.EncodeToString(plaintext) +
		`","byte_length":10,"content_hash":"` + hex.EncodeToString(sum[:]) + `","algorithm":"AES-256-GCM"}`
	var hits atomic.Int32
	c, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(body))
	})
	got, err := c.GetWrap(t.Context(), "agent-a", "secret-a", "w", nil, nil)
	if err == nil {
		t.Fatalf("unsealed wrap accepted (%d bytes)", len(got.Plaintext))
	}
	if hits.Load() != 0 {
		t.Fatalf("wrap fetched (and consumed on the CP) with no keypair to open it: %d calls", hits.Load())
	}
}

// A response that is exactly at the limit still parses; the cap rejects
// only bodies that are larger.
func TestClaimJob_ResponseAtLimitAccepted(t *testing.T) {
	prefix := `{"id":"job-1","job_type":"read","payload":{"pad":"`
	suffix := `"}}`
	pad := strings.Repeat("A", (1<<20)-len(prefix)-len(suffix))
	c, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(prefix + pad + suffix))
	})
	job, err := c.ClaimJob(t.Context(), "agent-a", "secret-a")
	if err != nil {
		t.Fatalf("1 MiB claim response refused: %v", err)
	}
	if job.ID != "job-1" {
		t.Fatalf("job id = %q", job.ID)
	}
}
