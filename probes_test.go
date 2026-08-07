package main

import (
	"net/http"
	"testing"
	"time"
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
