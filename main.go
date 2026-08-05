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

var httpClient *http.Client

type Exporter struct {
	config *Config

	certificates *prometheus.GaugeVec
	status       *prometheus.GaugeVec
}

func NewSSLExporter() *Exporter {
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

		wg.Add(len(e.config.HTTPDomains))

		for _, target := range e.config.HTTPDomains {

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

		wg.Add(len(e.config.SMTPDomains))

		for _, target := range e.config.SMTPDomains {

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

func (e *Exporter) collectHTTPDomain(target HTTPDomain) {

	domain := target.Domain

	req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s/", domain), nil)
	req.Header.Set("User-Agent", "prometheus-ssl-exporter/0.1 (SSL monitoring)")

	tlsConfig, err := TLSConfig(domain, target.CAFile, target.InsecureSkipVerify)
	if err != nil {
		log.Printf("error preparing TLS config for %v: %v", domain, err)
		e.status.WithLabelValues("http", domain).Set(0)
		return
	}

	// TODO: this writes to the shared client on every probe, which is a data
	// race between the goroutines of one scrape. A later commit gives each
	// target its own client.
	httpClient.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	resp, err := httpClient.Do(req)
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

func (e *Exporter) collectSMTPDomain(smtpTarget SMTPDomain) {

	domain := smtpTarget.Domain

	target := net.JoinHostPort(domain, strconv.Itoa(smtpTarget.Port))

	start := time.Now()

	conn, err := net.DialTimeout("tcp", target, *timeout)
	if err != nil {
		log.Printf("error connecting to smtp server %v: %v", target, err)
		e.status.WithLabelValues("smtp", domain).Set(0)
		return
	}

	conn.SetDeadline(start.Add(*timeout))

	c, err := smtp.NewClient(conn, domain)
	if err != nil {
		log.Printf("error collecting %v: %v", target, err)
		e.status.WithLabelValues("smtp", domain).Set(0)
		return
	}

	defer c.Quit()

	tlsconf := &tls.Config{ServerName: domain}

	err = c.StartTLS(tlsconf)
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

	httpClient = &http.Client{
		Timeout: *timeout,
	}

	config, err := LoadConfig(*conf)
	if err != nil {
		log.Fatalf("couldn't load the configuration: %v", err)
	}

	exporter := NewSSLExporter()
	exporter.config = config

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
