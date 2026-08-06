package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// TestCertificateTimestamps makes sure that the timestamps match the
// certificate that the target presents, and that the old metric stays.
func TestCertificateTimestamps(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	defer server.Close()

	leaf := server.Certificate()
	registry := registerTarget(t, strings.TrimPrefix(server.URL, "https://"))

	tests := []struct {
		name   string
		metric string
		want   float64
	}{
		{
			name:   "the end of the validity",
			metric: "ssl_cert_not_after",
			want:   float64(leaf.NotAfter.Unix()),
		},
		{
			name:   "the start of the validity",
			metric: "ssl_cert_not_before",
			want:   float64(leaf.NotBefore.Unix()),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := gatherMetric(t, registry, test.metric)
			if !ok {
				t.Fatalf("%s is not in the output", test.metric)
			}
			if got != test.want {
				t.Errorf("%s: got %v, want %v", test.metric, got, test.want)
			}
		})
	}

	// The old metric keeps working for an installation that did not move.
	daysLeftValue, ok := gatherMetric(t, registry, "ssl_certificate_days_left")
	if !ok {
		t.Fatal("ssl_certificate_days_left is not in the output")
	}

	want := daysLeft(leaf.NotAfter, time.Now())
	if diff := daysLeftValue - want; diff > 0.01 || diff < -0.01 {
		t.Errorf("ssl_certificate_days_left: got %v, want about %v", daysLeftValue, want)
	}
}

// TestDaysLeftMatchesTheTimestamp shows that the two metrics agree, so a
// dashboard gives the same answer before and after the move.
func TestDaysLeftMatchesTheTimestamp(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	defer server.Close()

	registry := registerTarget(t, strings.TrimPrefix(server.URL, "https://"))

	notAfter, ok := gatherMetric(t, registry, "ssl_cert_not_after")
	if !ok {
		t.Fatal("ssl_cert_not_after is not in the output")
	}
	days, ok := gatherMetric(t, registry, "ssl_certificate_days_left")
	if !ok {
		t.Fatal("ssl_certificate_days_left is not in the output")
	}

	// This is the query that the README gives as the replacement.
	fromTimestamp := (notAfter - float64(time.Now().Unix())) / 86400

	if diff := fromTimestamp - days; diff > 0.01 || diff < -0.01 {
		t.Errorf("the two metrics disagree: %v days from the timestamp, %v from the old metric",
			fromTimestamp, days)
	}
}

// TestTimestampsLeaveTheOutputWhenTheProbeFails keeps the timestamps out of
// the output for a target that does not answer.
func TestTimestampsLeaveTheOutputWhenTheProbeFails(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	registry := registerTarget(t, strings.TrimPrefix(server.URL, "https://"))

	if _, ok := gatherMetric(t, registry, "ssl_cert_not_after"); !ok {
		t.Fatal("ssl_cert_not_after is not in the output of the first scrape")
	}

	server.Close()

	for _, name := range []string{"ssl_cert_not_after", "ssl_cert_not_before", "ssl_certificate_days_left"} {
		if value, ok := gatherMetric(t, registry, name); ok {
			t.Errorf("%s: got %v, want the series to leave the output", name, value)
		}
	}
}

// TestDeprecationIsInTheHelpText tells an operator that reads /metrics which
// metric to move to.
func TestDeprecationIsInTheHelpText(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	defer server.Close()

	registry := registerTarget(t, strings.TrimPrefix(server.URL, "https://"))

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	for _, family := range families {
		if family.GetName() != "ssl_certificate_days_left" {
			continue
		}
		help := family.GetHelp()
		if !strings.Contains(help, "DEPRECATED") {
			t.Errorf("help of ssl_certificate_days_left: got %q, want it to hold DEPRECATED", help)
		}
		if !strings.Contains(help, "ssl_cert_not_after") {
			t.Errorf("help of ssl_certificate_days_left: got %q, want it to name ssl_cert_not_after", help)
		}
		return
	}

	t.Fatal("ssl_certificate_days_left is not in the output")
}

// TestDescribeNamesEveryMetric keeps the registry able to find the metrics
// before the first scrape.
func TestDescribeNamesEveryMetric(t *testing.T) {
	exporter, err := NewSSLExporter(&Config{}, time.Second)
	if err != nil {
		t.Fatalf("NewSSLExporter: %v", err)
	}

	descs := make(chan *prometheus.Desc, 8)
	exporter.Describe(descs)
	close(descs)

	var joined string
	var count int
	for desc := range descs {
		joined += " " + desc.String()
		count++
	}

	if count != 4 {
		t.Fatalf("Describe sent %d descriptions, want 4", count)
	}

	for _, name := range []string{
		"ssl_endpoint_up",
		"ssl_cert_not_after",
		"ssl_cert_not_before",
		"ssl_certificate_days_left",
	} {
		if !strings.Contains(joined, name) {
			t.Errorf("Describe did not name %s", name)
		}
	}
}
