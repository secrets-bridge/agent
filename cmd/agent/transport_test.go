package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		insecure bool
		wantErr  bool
		wantHint string
	}{
		{"https accepted", "https://cp.example.com", false, false, ""},
		{"http refused by default", "http://cp.example.com", false, true, "refuse to start"},
		{"http allowed with override", "http://cp.example.com", true, false, ""},
		{"empty refused", "", false, true, "is required"},
		{"weird scheme refused", "ftp://cp", false, true, "must be https://"},
		{"weird scheme refused even with override", "ftp://cp", true, true, "must be https://"},
		{"bad url refused", "%%not a url", false, true, "valid URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := validateEndpoint(tc.endpoint, tc.insecure)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("got %v want error", u)
				}
				if tc.wantHint != "" && !strings.Contains(err.Error(), tc.wantHint) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantHint)
				}
				return
			}
			if err != nil {
				t.Fatalf("got error %v", err)
			}
			if u == nil {
				t.Fatal("got nil url")
			}
		})
	}
}

func TestBuildTLSConfig_NoCAFile_UsesSystemRoots(t *testing.T) {
	cfg := Config{}
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if tlsCfg.RootCAs != nil {
		t.Fatal("RootCAs should be nil when CAFile is empty (= system roots)")
	}
	if tlsCfg.MinVersion < tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x want >= TLS 1.2", tlsCfg.MinVersion)
	}
}

func TestBuildTLSConfig_CustomCA_LoadsPool(t *testing.T) {
	pemBytes, _ := generateSelfSignedPEM(t, "test-ca")
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := Config{CAFile: caPath}
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if tlsCfg.RootCAs == nil {
		t.Fatal("RootCAs is nil despite CA file")
	}
	// system roots should NOT be mixed in — RootCAs is exclusive.
	// We can't easily count entries, but verify the pool contains
	// the cert subject we just loaded.
	subjects := tlsCfg.RootCAs.Subjects() //nolint:staticcheck // we don't have the cert to do CertPool.Equal
	if len(subjects) != 1 {
		t.Fatalf("RootCAs subjects = %d want 1 (CA file only)", len(subjects))
	}
}

func TestBuildTLSConfig_CAFileMissing_Errors(t *testing.T) {
	cfg := Config{CAFile: "/nonexistent/ca.pem"}
	_, err := buildTLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

func TestBuildTLSConfig_CAFileGarbage_Errors(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "garbage")
	_ = os.WriteFile(caPath, []byte("definitely not a PEM"), 0o600)
	cfg := Config{CAFile: caPath}
	_, err := buildTLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for non-PEM file")
	}
	if !strings.Contains(err.Error(), "no usable certificates") {
		t.Fatalf("error wording: %q", err.Error())
	}
}

func TestBuildTLSConfig_ServerNameOverride(t *testing.T) {
	cfg := Config{TLSServerName: "alt.example.com"}
	tlsCfg, _ := buildTLSConfig(cfg)
	if tlsCfg.ServerName != "alt.example.com" {
		t.Fatalf("ServerName = %q", tlsCfg.ServerName)
	}
}

// End-to-end: spin up an httptest TLS server with a self-signed cert,
// hand its CA to the agent's HTTP client, confirm the client can hit
// the server without InsecureSkipVerify (which we never enable).
func TestBuildHTTPClient_HitsTLSServerWithPinnedCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	// Drop the server's cert as a PEM file for buildTLSConfig to load.
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	_ = os.WriteFile(caPath, pemBytes, 0o600)

	cfg := Config{
		CPEndpoint: srv.URL,
		CAFile:     caPath,
		// httptest's cert is for "example.com" — we need to override
		// SNI / verification host.
		TLSServerName: "example.com",
	}
	hc, err := buildHTTPClient(cfg)
	if err != nil {
		t.Fatalf("buildHTTPClient: %v", err)
	}
	resp, err := hc.Get(srv.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestBuildHTTPClient_WrongCA_FailsHandshake(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	// Give the client a DIFFERENT CA than the server uses.
	otherPEM, _ := generateSelfSignedPEM(t, "unrelated")
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(caPath, otherPEM, 0o600)

	cfg := Config{
		CPEndpoint:    srv.URL,
		CAFile:        caPath,
		TLSServerName: "example.com",
	}
	hc, err := buildHTTPClient(cfg)
	if err != nil {
		t.Fatalf("buildHTTPClient: %v", err)
	}
	if _, err := hc.Get(srv.URL); err == nil {
		t.Fatal("expected TLS handshake failure against wrong CA")
	} else if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "tls") {
		t.Fatalf("unexpected error shape: %v", err)
	}
}

// --- helpers --------------------------------------------------------

// generateSelfSignedPEM builds a self-signed cert for testing.
// Returns the cert PEM and matching key PEM.
func generateSelfSignedPEM(t *testing.T, cn string) ([]byte, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{cn},
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// silence unused import warning if a test is skipped
var _ = errors.New
