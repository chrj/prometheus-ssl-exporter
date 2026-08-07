package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// gatherMetric returns the value of one metric of one target, and reports
// whether the series is in the output at all.
func gatherMetric(t *testing.T, registry *prometheus.Registry, name string) (float64, bool) {
	t.Helper()

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		metrics := family.GetMetric()
		if len(metrics) == 0 {
			return 0, false
		}
		return metrics[0].GetGauge().GetValue(), true
	}

	return 0, false
}

// registerTarget builds an exporter for one HTTPS target and registers it.
func registerTarget(t *testing.T, host string) *prometheus.Registry {
	t.Helper()

	exporter, err := NewSSLExporter(&Config{
		HTTPDomains: []HTTPDomain{{Domain: host, InsecureSkipVerify: true}},
	}, 3*time.Second)
	if err != nil {
		t.Fatalf("NewSSLExporter: %v", err)
	}

	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(exporter.newScrape(t.Context())); err != nil {
		t.Fatalf("register the exporter: %v", err)
	}

	return registry
}

// TestExpiryLeavesTheOutputWhenTheProbeFails is the regression test for the
// stored gauges. The old collector kept the last good value, so a target that
// stopped answering still reported days left on its certificate.
func TestExpiryLeavesTheOutputWhenTheProbeFails(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	host := strings.TrimPrefix(server.URL, "https://")
	registry := registerTarget(t, host)

	up, ok := gatherMetric(t, registry, "ssl_endpoint_up")
	if !ok || up != 1 {
		t.Fatalf("first scrape ssl_endpoint_up: got %v (present %v), want 1", up, ok)
	}
	if _, ok := gatherMetric(t, registry, "ssl_certificate_days_left"); !ok {
		t.Fatal("first scrape: ssl_certificate_days_left is not in the output")
	}

	// The target stops answering.
	server.Close()

	up, ok = gatherMetric(t, registry, "ssl_endpoint_up")
	if !ok || up != 0 {
		t.Errorf("second scrape ssl_endpoint_up: got %v (present %v), want 0", up, ok)
	}
	if value, ok := gatherMetric(t, registry, "ssl_certificate_days_left"); ok {
		t.Errorf("second scrape ssl_certificate_days_left: got %v, want the series to leave the output", value)
	}
}

// TestRedirectToPlainHTTP covers a target that answers on HTTPS and then
// redirects to plain HTTP. The response of such a target carries no TLS
// state. The old collector read the certificate from it and stopped the
// exporter.
func TestRedirectToPlainHTTP(t *testing.T) {
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

	registry := registerTarget(t, strings.TrimPrefix(secure.URL, "https://"))

	up, ok := gatherMetric(t, registry, "ssl_endpoint_up")
	if !ok {
		t.Fatal("ssl_endpoint_up is not in the output")
	}
	if up != 0 {
		t.Errorf("ssl_endpoint_up: got %v, want 0", up)
	}
	if _, ok := gatherMetric(t, registry, "ssl_certificate_days_left"); ok {
		t.Error("ssl_certificate_days_left is in the output for a target with no TLS")
	}
}

// TestTargetLeavesTheOutput makes sure that a target reports nothing after it
// leaves the configuration. The stored gauges held such a series until a
// restart.
func TestTargetLeavesTheOutput(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "https://")

	withTarget := registerTarget(t, host)
	if _, ok := gatherMetric(t, withTarget, "ssl_endpoint_up"); !ok {
		t.Fatal("ssl_endpoint_up is not in the output of the first exporter")
	}

	// The same exporter with no target at all.
	empty, err := NewSSLExporter(&Config{}, 3*time.Second)
	if err != nil {
		t.Fatalf("NewSSLExporter: %v", err)
	}
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(empty.newScrape(t.Context())); err != nil {
		t.Fatalf("register the exporter: %v", err)
	}

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	if len(families) != 0 {
		var names []string
		for _, family := range families {
			names = append(names, family.GetName())
		}
		t.Errorf("families: got %v, want none", names)
	}
}
