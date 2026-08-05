package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

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

// TestCollectConcurrentTargets probes several targets in one scrape. The race
// detector reports the shared-client fault here, because every probe runs in
// its own goroutine.
func TestCollectConcurrentTargets(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "https://")

	config := &Config{}
	for i := 0; i < 8; i++ {
		config.HTTPDomains = append(config.HTTPDomains, HTTPDomain{
			Domain: host,
			// The certificate of the test server names 127.0.0.1, not the
			// host and port that the probe sends as the server name.
			InsecureSkipVerify: true,
		})
	}

	exporter, err := NewSSLExporter(config, 5*time.Second)
	if err != nil {
		t.Fatalf("NewSSLExporter: %v", err)
	}

	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(exporter); err != nil {
		t.Fatalf("register the exporter: %v", err)
	}

	// Two scrapes at the same time, as two Prometheus servers would do.
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			if _, err := registry.Gather(); err != nil {
				t.Errorf("Gather: %v", err)
			}
		}()
	}
	wg.Wait()

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	var up float64
	var found bool
	for _, family := range families {
		if family.GetName() != "ssl_endpoint_up" {
			continue
		}
		for _, metric := range family.GetMetric() {
			found = true
			up = metric.GetGauge().GetValue()
		}
	}

	if !found {
		t.Fatal("ssl_endpoint_up is not in the gathered metrics")
	}
	if up != 1 {
		t.Errorf("ssl_endpoint_up: got %v, want 1", up)
	}
}

// TestNewSSLExporterRejectsBadCA stops a target with a CA file that the
// exporter cannot read.
func TestNewSSLExporterRejectsBadCA(t *testing.T) {
	config := &Config{
		HTTPDomains: []HTTPDomain{{
			Domain: "internal.example.com",
			CAFile: "/does/not/exist.pem",
		}},
	}

	_, err := NewSSLExporter(config, time.Second)
	if err == nil {
		t.Fatal("NewSSLExporter returned no error for a CA file that does not exist")
	}
	if !strings.Contains(err.Error(), "internal.example.com") {
		t.Errorf("error %q does not name the target", err)
	}
}
