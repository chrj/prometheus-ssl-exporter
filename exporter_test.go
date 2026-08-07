package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// TestHandlerServesBothRegistries makes sure that one scrape carries the
// metrics of the exporter and the metrics of the process. The exporter builds
// a registry for each request, and only the default one holds go_ and
// process_.
func TestHandlerServesBothRegistries(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	defer target.Close()

	exporter, err := NewSSLExporter(&Config{
		HTTPDomains: []HTTPDomain{{
			Domain:             strings.TrimPrefix(target.URL, "https://"),
			InsecureSkipVerify: true,
		}},
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("NewSSLExporter: %v", err)
	}

	metrics := httptest.NewServer(exporter.Handler())
	defer metrics.Close()

	// Two scrapes, because a registry that the handler keeps between requests
	// would fail the second one.
	for _, scrapeNumber := range []int{1, 2} {
		resp, err := metrics.Client().Get(metrics.URL)
		if err != nil {
			t.Fatalf("scrape %d: %v", scrapeNumber, err)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("scrape %d: read the body: %v", scrapeNumber, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("scrape %d: close the body: %v", scrapeNumber, err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("scrape %d status: got %d, want %d",
				scrapeNumber, resp.StatusCode, http.StatusOK)
		}

		for _, name := range []string{"ssl_endpoint_up", "ssl_cert_not_after", "go_goroutines"} {
			if !strings.Contains(string(body), name) {
				t.Errorf("scrape %d: %s is not in the output", scrapeNumber, name)
			}
		}
	}
}

// TestHandlerStopsTheProbesWhenTheClientGoesAway is the reason the handler
// builds a collector for each request. A scrape that the Prometheus server
// drops must not leave the probes running.
func TestHandlerStopsTheProbesWhenTheClientGoesAway(t *testing.T) {
	// The target holds the response, so only a cancelled probe ends it. It
	// reports that its own context ended, which happens when the probe stops.
	aborted := make(chan struct{}, 1)
	release := make(chan struct{})

	target := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
				select {
				case aborted <- struct{}{}:
				default:
				}
			case <-release:
			}
		}))
	defer target.Close()
	defer close(release)

	// A timeout long enough that only the client going away ends the probe.
	exporter, err := NewSSLExporter(&Config{
		HTTPDomains: []HTTPDomain{{
			Domain:             strings.TrimPrefix(target.URL, "https://"),
			InsecureSkipVerify: true,
		}},
	}, time.Minute)
	if err != nil {
		t.Fatalf("NewSSLExporter: %v", err)
	}

	metrics := httptest.NewServer(exporter.Handler())
	defer metrics.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metrics.URL, nil)
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	if _, err := metrics.Client().Do(req); err == nil {
		t.Fatal("the scrape finished, so the target did not hold the response")
	}

	select {
	case <-aborted:
	case <-time.After(10 * time.Second):
		t.Fatal("the probe kept running after the client went away")
	}
}

// TestCollectConcurrentTargets probes several targets in one scrape. The race
// detector reports the shared-client fault here, because every probe runs in
// its own goroutine.
func TestCollectConcurrentTargets(t *testing.T) {
	// One server for each target. Two targets cannot share a domain, because
	// the metrics of one scrape would then carry the same labels twice.
	config := &Config{}
	for i := 0; i < 8; i++ {
		server := httptest.NewTLSServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
		defer server.Close()

		config.HTTPDomains = append(config.HTTPDomains, HTTPDomain{
			Domain: strings.TrimPrefix(server.URL, "https://"),
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
	if err := registry.Register(exporter.newScrape(t.Context())); err != nil {
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

	var count int
	for _, family := range families {
		if family.GetName() != "ssl_endpoint_up" {
			continue
		}
		for _, metric := range family.GetMetric() {
			count++
			if up := metric.GetGauge().GetValue(); up != 1 {
				t.Errorf("ssl_endpoint_up for %v: got %v, want 1",
					metric.GetLabel(), up)
			}
		}
	}

	if count != 8 {
		t.Errorf("ssl_endpoint_up series: got %d, want 8", count)
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

func TestDaysLeft(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		notAfter time.Time
		want     float64
	}{
		{
			name:     "one day left",
			notAfter: now.Add(24 * time.Hour),
			want:     1,
		},
		{
			name:     "half a day left",
			notAfter: now.Add(12 * time.Hour),
			want:     0.5,
		},
		{
			name:     "the certificate ended a day ago",
			notAfter: now.Add(-24 * time.Hour),
			want:     -1,
		},
		{
			name:     "the certificate ends now",
			notAfter: now,
			want:     0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := daysLeft(test.notAfter, now); got != test.want {
				t.Errorf("daysLeft: got %v, want %v", got, test.want)
			}
		})
	}
}
