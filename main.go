package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	addr    = flag.String("listen-address", ":9203", "Prometheus metrics port")
	conf    = flag.String("config", "/etc/ssl/checks", "Configuration file")
	timeout = flag.Duration("timeout", 8*time.Second, "Timeout for network operations")
)

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

type Exporter struct {
	httpTargets []httpTarget
	smtpTargets []smtpTarget
	timeout     time.Duration
}

// result is the outcome of one probe. Collect turns it into metrics.
type result struct {
	probeType string
	domain    string
	up        bool
	notBefore time.Time
	notAfter  time.Time
}

// errNoTLS reports a response that carries no TLS state. An HTTPS target
// that redirects to plain HTTP gives such a response.
var errNoTLS = errors.New("the connection did not use TLS")

// errNoPeerCertificate reports a TLS state with an empty certificate chain.
var errNoPeerCertificate = errors.New("the peer sent no certificate")

var (
	certNotAfterDesc = prometheus.NewDesc(
		"ssl_cert_not_after",
		"End of the validity of the certificate, as seconds since the epoch",
		[]string{"type", "domain"}, nil)

	certNotBeforeDesc = prometheus.NewDesc(
		"ssl_cert_not_before",
		"Start of the validity of the certificate, as seconds since the epoch",
		[]string{"type", "domain"}, nil)

	certDaysLeftDesc = prometheus.NewDesc(
		"ssl_certificate_days_left",
		"DEPRECATED: use (ssl_cert_not_after - time()) / 86400. Number of days left on the certificate",
		[]string{"type", "domain"}, nil)

	endpointUpDesc = prometheus.NewDesc(
		"ssl_endpoint_up",
		"Was the last SSL poll successful",
		[]string{"type", "domain"}, nil)
)

// newHTTPClient builds the client for one target. The TLS settings go in the
// transport of the client, so no probe writes to shared state.
func newHTTPClient(target HTTPDomain, timeout time.Duration) (*http.Client, error) {
	tlsConfig, err := TLSConfig(target.Domain, target.CAFile, target.InsecureSkipVerify)
	if err != nil {
		return nil, fmt.Errorf("TLS settings for %s: %w", target.Domain, err)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}, nil
}

func NewSSLExporter(config *Config, timeout time.Duration) (*Exporter, error) {
	exporter := &Exporter{timeout: timeout}

	for _, target := range config.HTTPDomains {
		client, err := newHTTPClient(target, timeout)
		if err != nil {
			return nil, err
		}
		exporter.httpTargets = append(exporter.httpTargets, httpTarget{
			domain: target.Domain,
			client: client,
		})
	}

	for _, target := range config.SMTPDomains {
		tlsConfig, err := TLSConfig(target.Domain, target.CAFile, target.InsecureSkipVerify)
		if err != nil {
			return nil, fmt.Errorf("TLS settings for %s: %w", target.Domain, err)
		}
		exporter.smtpTargets = append(exporter.smtpTargets, smtpTarget{
			domain: target.Domain,
			port:   target.Port,
			tls:    tlsConfig,
		})
	}

	return exporter, nil
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- endpointUpDesc
	ch <- certNotAfterDesc
	ch <- certNotBeforeDesc
	ch <- certDaysLeftDesc
}

// Collect probes every target and writes the metrics of this scrape. It
// builds the metrics from the results of this scrape only, so a target that
// leaves the configuration leaves the output, and a probe that fails reports
// no expiry.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {

	results := make([]result, len(e.httpTargets)+len(e.smtpTargets))

	var wg sync.WaitGroup
	wg.Add(len(results))

	for i, target := range e.httpTargets {
		go func(slot int, target httpTarget) {
			defer wg.Done()
			results[slot] = e.probe(probeHTTP(target))
		}(i, target)
	}

	offset := len(e.httpTargets)

	for i, target := range e.smtpTargets {
		go func(slot int, target smtpTarget) {
			defer wg.Done()
			results[slot] = e.probe(probeSMTP(target, e.timeout))
		}(offset+i, target)
	}

	wg.Wait()

	now := time.Now()

	for _, res := range results {
		up := 0.0
		if res.up {
			up = 1
		}

		ch <- prometheus.MustNewConstMetric(endpointUpDesc,
			prometheus.GaugeValue, up, res.probeType, res.domain)

		if !res.up {
			continue
		}

		ch <- prometheus.MustNewConstMetric(certNotAfterDesc,
			prometheus.GaugeValue, float64(res.notAfter.Unix()),
			res.probeType, res.domain)

		ch <- prometheus.MustNewConstMetric(certNotBeforeDesc,
			prometheus.GaugeValue, float64(res.notBefore.Unix()),
			res.probeType, res.domain)

		ch <- prometheus.MustNewConstMetric(certDaysLeftDesc,
			prometheus.GaugeValue, daysLeft(res.notAfter, now),
			res.probeType, res.domain)
	}
}

// probe logs the error of a probe and returns its result.
func (e *Exporter) probe(res result, err error) result {
	if err != nil {
		log.Printf("probe %s target %s: %v", res.probeType, res.domain, err)
	}
	return res
}

// daysLeft gives the days between now and the end of the certificate. The
// value is negative for a certificate that ended.
func daysLeft(notAfter, now time.Time) float64 {
	return notAfter.Sub(now).Hours() / 24
}

func probeHTTP(target httpTarget) (result, error) {

	res := result{probeType: "http", domain: target.domain}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/", target.domain), nil)
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

func probeSMTP(target smtpTarget, timeout time.Duration) (result, error) {

	res := result{probeType: "smtp", domain: target.domain}

	address := net.JoinHostPort(target.domain, strconv.Itoa(target.port))

	start := time.Now()

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return res, fmt.Errorf("connect to %s: %w", address, err)
	}

	// Close the connection on every path. smtp.NewClient takes it over only
	// when it succeeds, and Quit does not run when it fails. A close error
	// after a finished probe changes nothing, and Quit closes first on the
	// path where it runs.
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(start.Add(timeout)); err != nil {
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

func main() {

	flag.Parse()

	config, err := LoadConfig(*conf)
	if err != nil {
		log.Fatalf("couldn't load the configuration: %v", err)
	}

	exporter, err := NewSSLExporter(config, *timeout)
	if err != nil {
		log.Fatalf("couldn't build the exporter: %v", err)
	}

	prometheus.MustRegister(exporter)

	http.Handle("/metrics", promhttp.Handler())

	if config.ServerTLS.Enabled() {
		log.Printf("starting exporter with TLS on %s", *addr)
		log.Fatal(http.ListenAndServeTLS(*addr,
			config.ServerTLS.CertFile, config.ServerTLS.KeyFile, nil))
	}

	log.Printf("starting exporter on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
