package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// validateEndpoint enforces the transit-security posture:
//
//   - Default: SB_CP_ENDPOINT must use https://. Anything else is a
//     hard error at startup so a misconfigured deployment fails to
//     come up rather than silently leaking plaintext.
//   - Opt-in dev override: SB_INSECURE_TRANSPORT=true allows http://.
//     The caller is expected to log a loud warning when this is set.
//
// Returns the parsed URL on success.
func validateEndpoint(endpoint string, insecure bool) (*url.URL, error) {
	if endpoint == "" {
		return nil, errors.New("SB_CP_ENDPOINT is required")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		// url.Parse errors quote the whole raw URL, userinfo included;
		// keep only the reason so the startup error log can't carry a
		// credential embedded in SB_CP_ENDPOINT (AGT-N-08).
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return nil, fmt.Errorf("SB_CP_ENDPOINT is not a valid URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
		return u, nil
	case "http":
		if !insecure {
			return nil, errors.New(
				"SB_CP_ENDPOINT uses plain http:// — refuse to start; " +
					"use https:// in production, or set SB_INSECURE_TRANSPORT=true for dev only")
		}
		return u, nil
	default:
		return nil, fmt.Errorf("SB_CP_ENDPOINT scheme %q must be https:// (or http:// with SB_INSECURE_TRANSPORT=true)", u.Scheme)
	}
}

// buildHTTPClient constructs the HTTP client the agent uses for all
// CP traffic. When the endpoint is https:// the client gets a TLS
// config built from system roots + any operator-supplied CA file +
// optional SNI override. For http:// (dev mode) we still build the
// same client, just without TLS — the transport is plain. The client
// never follows redirects.
func buildHTTPClient(cfg Config) (*http.Client, error) {
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsCfg,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConns:          16,
	}
	return &http.Client{
		Timeout:       30 * time.Second,
		Transport:     transport,
		CheckRedirect: refuseRedirect,
	}, nil
}

// refuseRedirect stops the agent's HTTP client from following any
// redirect (AGT-N-02). Go re-sends custom headers such as X-Agent-Secret
// to the Location host, including an https -> http downgrade to another
// host, so a 3xx from the CP is returned to the caller as-is and treated
// as an error there.
func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// buildTLSConfig returns the *tls.Config to install on the HTTP
// client. Even when the endpoint is plain http:// we return a default
// TLS config so the same client can be reused if the operator
// switches to https:// at runtime.
//
// Behavior:
//   - CAFile is empty → trust system roots only (the default).
//   - CAFile is set → load that PEM bundle as the ONLY trust anchor.
//     System roots are intentionally NOT mixed in to keep the trust
//     boundary tight.
//   - TLSServerName is set → overrides SNI / cert-name verification.
func buildTLSConfig(cfg Config) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if cfg.TLSServerName != "" {
		tlsCfg.ServerName = cfg.TLSServerName
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file %q: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %q contained no usable certificates", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}
