package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"time"
)

// errNoTLS reports a response that carries no TLS state. An HTTPS target
// that redirects to plain HTTP gives such a response.
var errNoTLS = errors.New("the connection did not use TLS")

// errNoPeerCertificate reports a TLS state with an empty certificate chain.
var errNoPeerCertificate = errors.New("the peer sent no certificate")

// httpTarget pairs a target with the client that probes it. Each target gets
// its own client, because each one can have a different certificate
// authority.
type httpTarget struct {
	domain string
	client *http.Client
}

// smtpTarget pairs a target with the TLS settings for its STARTTLS session.
type smtpTarget struct {
	domain string
	port   int
	tls    *tls.Config
}

// result is the outcome of one probe. Collect turns it into metrics.
type result struct {
	probeType string
	domain    string
	up        bool
	notBefore time.Time
	notAfter  time.Time
}

// newHTTPClient builds the client for one target. The TLS settings go in the
// transport of the client, so no probe writes to shared state.
func newHTTPClient(target HTTPDomain, timeout time.Duration) (*http.Client, error) {
	tlsConfig, err := TLSConfig(target.Domain, target.CAFile, target.InsecureSkipVerify)
	if err != nil {
		return nil, fmt.Errorf("TLS settings for %s: %w", target.Domain, err)
	}

	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("the default HTTP transport is %T, not *http.Transport",
			http.DefaultTransport)
	}

	transport := defaultTransport.Clone()
	transport.TLSClientConfig = tlsConfig

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}, nil
}

func probeHTTP(ctx context.Context, target httpTarget) (result, error) {

	res := result{probeType: "http", domain: target.domain}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("https://%s/", target.domain), nil)
	if err != nil {
		return res, fmt.Errorf("build the request: %w", err)
	}
	req.Header.Set("User-Agent", "prometheus-ssl-exporter/0.1 (SSL monitoring)")

	resp, err := target.client.Do(req)
	if err != nil {
		return res, fmt.Errorf("connect: %w", err)
	}

	// The body is read only, so a close error says nothing about the
	// certificate that the probe came for.
	defer func() { _ = resp.Body.Close() }()

	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return res, fmt.Errorf("read the response: %w", err)
	}

	// A target that redirects to plain HTTP gives a response with no TLS
	// state. Reading the certificate here would stop the exporter.
	if resp.TLS == nil {
		return res, errNoTLS
	}
	if len(resp.TLS.PeerCertificates) == 0 {
		return res, errNoPeerCertificate
	}

	leaf := resp.TLS.PeerCertificates[0]

	res.up = true
	res.notBefore = leaf.NotBefore
	res.notAfter = leaf.NotAfter

	return res, nil
}

// probeSMTP takes both a context and a timeout. The context cancels the dial
// and gives the deadline of the scrape. The timeout bounds this one session, so
// the probe still stops when the context carries no deadline.
func probeSMTP(ctx context.Context, target smtpTarget, timeout time.Duration) (result, error) {

	res := result{probeType: "smtp", domain: target.domain}

	address := net.JoinHostPort(target.domain, strconv.Itoa(target.port))

	start := time.Now()

	dialer := net.Dialer{Timeout: timeout}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return res, fmt.Errorf("connect to %s: %w", address, err)
	}

	// Close the connection on every path. smtp.NewClient takes it over only
	// when it succeeds, and Quit does not run when it fails. A close error
	// after a finished probe changes nothing, and Quit closes first on the
	// path where it runs.
	defer func() { _ = conn.Close() }()

	// smtp.Client watches no context, so the deadline of the connection is the
	// only thing that ends the session. Take whichever comes first, so the
	// deadline of the scrape holds the session as well.
	deadline := start.Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	if err := conn.SetDeadline(deadline); err != nil {
		return res, fmt.Errorf("set the deadline for %s: %w", address, err)
	}

	client, err := smtp.NewClient(conn, target.domain)
	if err != nil {
		return res, fmt.Errorf("start the session with %s: %w", address, err)
	}

	// QUIT is a courtesy to the mail server. The probe already has the
	// certificate by the time this runs, so a failure here is not a failure
	// of the probe.
	defer func() { _ = client.Quit() }()

	if err := client.StartTLS(target.tls); err != nil {
		return res, fmt.Errorf("STARTTLS with %s: %w", address, err)
	}

	state, ok := client.TLSConnectionState()
	if !ok {
		return res, fmt.Errorf("%s: %w", address, errNoTLS)
	}
	if len(state.PeerCertificates) == 0 {
		return res, fmt.Errorf("%s: %w", address, errNoPeerCertificate)
	}

	leaf := state.PeerCertificates[0]

	res.up = true
	res.notBefore = leaf.NotBefore
	res.notAfter = leaf.NotAfter

	return res, nil
}
