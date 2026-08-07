package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newHTTPProbeTarget builds the target that probeHTTP takes for one host. The
// certificate of a test server names 127.0.0.1, not the host and port that the
// probe sends as the server name, so the checks stay off.
func newHTTPProbeTarget(t *testing.T, host string) httpTarget {
	t.Helper()

	client, err := newHTTPClient(HTTPDomain{Domain: host, InsecureSkipVerify: true}, 3*time.Second)
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}

	return httpTarget{domain: host, client: client}
}

// TestNewHTTPClientPerTarget shows that two targets get two clients, and that
// each client carries the TLS settings of its own target. One shared client
// cannot hold two different certificate authorities at the same time.
func TestNewHTTPClientPerTarget(t *testing.T) {
	strict := HTTPDomain{Domain: "strict.example.com"}
	relaxed := HTTPDomain{Domain: "relaxed.example.com", InsecureSkipVerify: true}

	strictClient, err := newHTTPClient(strict, time.Second)
	if err != nil {
		t.Fatalf("newHTTPClient for the strict target: %v", err)
	}

	relaxedClient, err := newHTTPClient(relaxed, time.Second)
	if err != nil {
		t.Fatalf("newHTTPClient for the relaxed target: %v", err)
	}

	if strictClient == relaxedClient {
		t.Fatal("both targets got the same client")
	}

	strictTransport, ok := strictClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("strict transport: got %T, want *http.Transport", strictClient.Transport)
	}
	relaxedTransport, ok := relaxedClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("relaxed transport: got %T, want *http.Transport", relaxedClient.Transport)
	}

	if strictTransport == relaxedTransport {
		t.Fatal("both targets got the same transport")
	}

	if got := strictTransport.TLSClientConfig.InsecureSkipVerify; got {
		t.Errorf("strict InsecureSkipVerify: got %v, want false", got)
	}
	if got := relaxedTransport.TLSClientConfig.InsecureSkipVerify; !got {
		t.Errorf("relaxed InsecureSkipVerify: got %v, want true", got)
	}

	if got := strictTransport.TLSClientConfig.ServerName; got != "strict.example.com" {
		t.Errorf("strict ServerName: got %q, want %q", got, "strict.example.com")
	}
	if got := relaxedTransport.TLSClientConfig.ServerName; got != "relaxed.example.com" {
		t.Errorf("relaxed ServerName: got %q, want %q", got, "relaxed.example.com")
	}

	if strictClient.Timeout != time.Second {
		t.Errorf("Timeout: got %v, want %v", strictClient.Timeout, time.Second)
	}
}

// TestProbeHTTPReadsTheCertificate makes sure that a good target gives the
// dates of the certificate that it presents.
func TestProbeHTTPReadsTheCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "https://")
	leaf := server.Certificate()

	res, err := probeHTTP(t.Context(), newHTTPProbeTarget(t, host))
	if err != nil {
		t.Fatalf("probeHTTP: %v", err)
	}

	if !res.up {
		t.Error("up: got false, want true")
	}
	if res.probeType != "http" {
		t.Errorf("probeType: got %q, want %q", res.probeType, "http")
	}
	if res.domain != host {
		t.Errorf("domain: got %q, want %q", res.domain, host)
	}
	if !res.notAfter.Equal(leaf.NotAfter) {
		t.Errorf("notAfter: got %v, want %v", res.notAfter, leaf.NotAfter)
	}
	if !res.notBefore.Equal(leaf.NotBefore) {
		t.Errorf("notBefore: got %v, want %v", res.notBefore, leaf.NotBefore)
	}
}

// TestProbeHTTPRedirectToPlainHTTP names the error for a target that answers
// on HTTPS and then redirects to plain HTTP. The response of such a target
// carries no TLS state.
func TestProbeHTTPRedirectToPlainHTTP(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	defer plain.Close()

	secure := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, plain.URL, http.StatusFound)
		}))
	defer secure.Close()

	host := strings.TrimPrefix(secure.URL, "https://")

	res, err := probeHTTP(t.Context(), newHTTPProbeTarget(t, host))
	if !errors.Is(err, errNoTLS) {
		t.Errorf("probeHTTP: got %v, want %v", err, errNoTLS)
	}
	if res.up {
		t.Error("up: got true, want false")
	}
}

// TestProbeHTTPKeepsTheLabelsWhenItFails makes sure that a failed probe still
// carries the labels of its target. Collect writes ssl_endpoint_up from them.
func TestProbeHTTPKeepsTheLabelsWhenItFails(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	host := strings.TrimPrefix(server.URL, "https://")
	target := newHTTPProbeTarget(t, host)

	// The target stops answering.
	server.Close()

	res, err := probeHTTP(t.Context(), target)
	if err == nil {
		t.Fatal("probeHTTP returned no error for a target that does not answer")
	}
	if res.up {
		t.Error("up: got true, want false")
	}
	if res.probeType != "http" {
		t.Errorf("probeType: got %q, want %q", res.probeType, "http")
	}
	if res.domain != host {
		t.Errorf("domain: got %q, want %q", res.domain, host)
	}
}

// TestProbeHTTPStopsOnACancelledContext cancels a probe that is waiting for a
// response. Without the context the probe runs to the timeout of its client,
// so a scrape that the Prometheus server dropped keeps working.
func TestProbeHTTPStopsOnACancelledContext(t *testing.T) {
	// The handler holds the response, so only the context ends the probe. It
	// watches the context of the request as well, so Close does not wait.
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))
	defer server.Close()
	defer close(release)

	target := newHTTPProbeTarget(t, strings.TrimPrefix(server.URL, "https://"))

	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() {
		_, err := probeHTTP(ctx, target)
		done <- err
	}()

	cancel()

	select {
	case err := <-done:
		// A client that ignores the context gives a timeout after 3 seconds
		// instead, which this check does not accept.
		if !errors.Is(err, context.Canceled) {
			t.Errorf("probeHTTP: got %v, want %v", err, context.Canceled)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("probeHTTP did not return after the context was cancelled")
	}
}

// TestProbeSMTPStopsOnACancelledContext makes sure that the context reaches
// the dial of an SMTP probe.
func TestProbeSMTPStopsOnACancelledContext(t *testing.T) {
	ca := newTestCA(t)
	port := startSMTPServer(t, ca.ServerCert)

	tlsConfig, err := TLSConfig("localhost", ca.CAFile, false)
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	res, err := probeSMTP(ctx, smtpTarget{domain: "localhost", port: port, tls: tlsConfig}, 5*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("probeSMTP: got %v, want %v", err, context.Canceled)
	}
	if res.up {
		t.Error("up: got true, want false")
	}
}

// TestProbeSMTPRejectsAnUntrustedCertificate names the STARTTLS failure for a
// server whose authority the probe does not hold.
func TestProbeSMTPRejectsAnUntrustedCertificate(t *testing.T) {
	ca := newTestCA(t)
	port := startSMTPServer(t, ca.ServerCert)

	tlsConfig, err := TLSConfig("localhost", "", false)
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}

	res, err := probeSMTP(t.Context(), smtpTarget{domain: "localhost", port: port, tls: tlsConfig}, 5*time.Second)
	if err == nil {
		t.Fatal("probeSMTP returned no error for an untrusted certificate")
	}
	if !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("error %q does not name the failed step", err)
	}
	if res.up {
		t.Error("up: got true, want false")
	}
	if res.probeType != "smtp" {
		t.Errorf("probeType: got %q, want %q", res.probeType, "smtp")
	}
}

// TestProbeSMTPReadsTheCertificate makes sure that a trusted target gives the
// dates of the certificate that it presents.
func TestProbeSMTPReadsTheCertificate(t *testing.T) {
	ca := newTestCA(t)
	port := startSMTPServer(t, ca.ServerCert)

	tlsConfig, err := TLSConfig("localhost", ca.CAFile, false)
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}

	res, err := probeSMTP(t.Context(), smtpTarget{domain: "localhost", port: port, tls: tlsConfig}, 5*time.Second)
	if err != nil {
		t.Fatalf("probeSMTP: %v", err)
	}

	if !res.up {
		t.Error("up: got false, want true")
	}
	if !res.notAfter.Equal(ca.ServerCert.Leaf.NotAfter) {
		t.Errorf("notAfter: got %v, want %v", res.notAfter, ca.ServerCert.Leaf.NotAfter)
	}
	if !res.notBefore.Equal(ca.ServerCert.Leaf.NotBefore) {
		t.Errorf("notBefore: got %v, want %v", res.notBefore, ca.ServerCert.Leaf.NotBefore)
	}
}
