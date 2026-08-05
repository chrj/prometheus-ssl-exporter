package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
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

	certificates *prometheus.GaugeVec
	status       *prometheus.GaugeVec
}

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
	exporter := newExporter()

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

func newExporter() *Exporter {
	return &Exporter{
		certificates: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "ssl",
				Subsystem: "certificate",
				Name:      "days_left",
				Help:      "Number of days left on the certificate",
			},
			[]string{
				"type",
				"domain",
			},
		),
		status: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "ssl",
				Subsystem: "endpoint",
				Name:      "up",
				Help:      "Was the last SSL poll successful",
			},
			[]string{
				"type",
				"domain",
			},
		),
	}
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.certificates.Describe(ch)
	e.status.Describe(ch)
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {

	var top sync.WaitGroup

	top.Add(2)

	go func() {

		// Collect HTTP domains

		var wg sync.WaitGroup

		wg.Add(len(e.httpTargets))

		for _, target := range e.httpTargets {

			target := target

			go func() {
				e.collectHTTPDomain(target)
				wg.Done()
			}()

		}

		wg.Wait()

		top.Done()

	}()

	go func() {

		// Collect SMTP domains

		var wg sync.WaitGroup

		wg.Add(len(e.smtpTargets))

		for _, target := range e.smtpTargets {

			target := target

			go func() {
				e.collectSMTPDomain(target)
				wg.Done()
			}()

		}

		wg.Wait()

		top.Done()

	}()

	top.Wait()

	e.certificates.Collect(ch)
	e.status.Collect(ch)

}

func (e *Exporter) collectHTTPDomain(target httpTarget) {

	domain := target.domain

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/", domain), nil)
	if err != nil {
		log.Printf("error building the request for %v: %v", domain, err)
		e.status.WithLabelValues("http", domain).Set(0)
		return
	}
	req.Header.Set("User-Agent", "prometheus-ssl-exporter/0.1 (SSL monitoring)")

	resp, err := target.client.Do(req)
	if err != nil {
		log.Printf("error connecting to %v: %v", domain, err)
		e.status.WithLabelValues("http", domain).Set(0)
		return
	}

	defer resp.Body.Close()

	if _, err := io.Copy(ioutil.Discard, resp.Body); err != nil {
		log.Printf("error reading response from %v: %v", domain, err)
		e.status.WithLabelValues("http", domain).Set(0)
		return
	}

	cert := resp.TLS.PeerCertificates[0]

	e.certificates.WithLabelValues("http", domain).Set(
		float64(time.Until(cert.NotAfter)/time.Hour) / 24,
	)

	e.status.WithLabelValues("http", domain).Set(1)

}

func (e *Exporter) collectSMTPDomain(smtpTarget smtpTarget) {

	domain := smtpTarget.domain

	target := net.JoinHostPort(domain, strconv.Itoa(smtpTarget.port))

	start := time.Now()

	conn, err := net.DialTimeout("tcp", target, *timeout)
	if err != nil {
		log.Printf("error connecting to smtp server %v: %v", target, err)
		e.status.WithLabelValues("smtp", domain).Set(0)
		return
	}

	// Close the connection on every path. smtp.NewClient takes it over only
	// when it succeeds, and Quit does not run when it fails.
	defer conn.Close()

	conn.SetDeadline(start.Add(*timeout))

	c, err := smtp.NewClient(conn, domain)
	if err != nil {
		log.Printf("error collecting %v: %v", target, err)
		e.status.WithLabelValues("smtp", domain).Set(0)
		return
	}

	defer c.Quit()

	err = c.StartTLS(smtpTarget.tls)
	if err != nil {
		log.Printf("STARTTLS handshake failed for %v: %v", target, err)
		e.status.WithLabelValues("smtp", domain).Set(0)
		return
	}

	state, ok := c.TLSConnectionState()
	if !ok {
		log.Printf("couldn't get TLS state from %v", target)
		e.status.WithLabelValues("smtp", domain).Set(0)
		return
	}

	cert := state.PeerCertificates[0]

	e.certificates.WithLabelValues("smtp", domain).Set(
		float64(time.Until(cert.NotAfter)/time.Hour) / 24,
	)

	e.status.WithLabelValues("smtp", domain).Set(1)

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
