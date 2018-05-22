package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"sync"
	"time"

	"github.com/naoina/toml"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var addr = flag.String("listen-address", ":9203", "Prometheus metrics port")
var conf = flag.String("config", "/etc/ssl/checks", "Configuration file")

var httpClient = &http.Client{}

type HTTPDomain struct {
	Domain string
}

type SMTPDomain struct {
	Domain string
	Port   int
}

type Exporter struct {
	HTTPDomains []HTTPDomain
	SMTPDomains []SMTPDomain

	certificates *prometheus.GaugeVec
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
	}
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.certificates.Describe(ch)
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {

	var top sync.WaitGroup

	top.Add(2)

	go func() {

		// Collect HTTP domains

		var wg sync.WaitGroup

		wg.Add(len(e.HTTPDomains))

		for _, target := range e.HTTPDomains {

			target := target

			go func() {
				e.collectHTTPDomain(target.Domain)
				wg.Done()
			}()

		}

		wg.Wait()

		top.Done()

	}()

	go func() {

		// Collect SMTP domains

		var wg sync.WaitGroup

		wg.Add(len(e.SMTPDomains))

		for _, target := range e.SMTPDomains {

			target := target

			go func() {
				e.collectSMTPDomain(target.Domain, target.Port)
				wg.Done()
			}()

		}

		wg.Wait()

		top.Done()

	}()

	top.Wait()

	e.certificates.Collect(ch)

}

func (e *Exporter) collectHTTPDomain(domain string) {

	req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s/", domain), nil)
	req.Header.Set("User-Agent", "prometheus-ssl-exporter/0.1 (SSL monitoring)")

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("error collecting %v: %v", domain, err)
		return
	}

	resp.Body.Close()

	cert := resp.TLS.PeerCertificates[0]

	e.certificates.WithLabelValues("http", domain).Set(
		float64(time.Until(cert.NotAfter)/time.Hour) / 24,
	)

}

func (e *Exporter) collectSMTPDomain(domain string, port int) {

	target := fmt.Sprintf("%s:%d", domain, port)

	c, err := smtp.Dial(target)
	if err != nil {
		log.Printf("error collecting %v: %v", target, err)
		return
	}

	defer c.Quit()

	tlsconf := &tls.Config{ServerName: domain}

	err = c.StartTLS(tlsconf)
	if err != nil {
		log.Printf("STARTTLS handshake failed for %v: %v", target, err)
		return
	}

	state, ok := c.TLSConnectionState()
	if !ok {
		log.Printf("couldn't get TLS state from %v", target)
		return
	}

	cert := state.PeerCertificates[0]

	e.certificates.WithLabelValues("smtp", domain).Set(
		float64(time.Until(cert.NotAfter)/time.Hour) / 24,
	)

}

func main() {

	flag.Parse()

	f, err := os.Open(*conf)
	if err != nil {
		log.Fatalf("couldn't open configuration file: %v", err)
	}

	exporter := NewSSLExporter()

	if err := toml.NewDecoder(f).Decode(exporter); err != nil {
		log.Fatalf("couldn't parse configuration file: %v", err)
	}

	prometheus.MustRegister(exporter)

	http.Handle("/metrics", promhttp.Handler())

	log.Fatal(http.ListenAndServe(*addr, nil))

}
