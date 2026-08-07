package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

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

type Exporter struct {
	httpTargets []httpTarget
	smtpTargets []smtpTarget
	timeout     time.Duration
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
