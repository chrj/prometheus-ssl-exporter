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
