package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

// scrape is the collector for one request. It holds a context, which a
// collector cannot take as an argument, so the probes of one scrape stop when
// the server that asked for them goes away.
type scrape struct {
	exporter *Exporter
	ctx      context.Context
}

// newScrape gives the collector for one scrape.
func (e *Exporter) newScrape(ctx context.Context) scrape {
	return scrape{exporter: e, ctx: ctx}
}

func (s scrape) Describe(ch chan<- *prometheus.Desc) {
	s.exporter.Describe(ch)
}

func (s scrape) Collect(ch chan<- prometheus.Metric) {
	s.exporter.collect(s.ctx, ch)
}

// Handler serves the metrics. It builds a registry for each request, because
// only a collector made for that request can carry its context.
func (e *Exporter) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), e.timeout)
		defer cancel()

		registry := prometheus.NewRegistry()
		if err := registry.Register(e.newScrape(ctx)); err != nil {
			log.Printf("register the collector for a scrape: %v", err)
			http.Error(w, "the exporter could not build the metrics for this scrape",
				http.StatusInternalServerError)
			return
		}

		// The default gatherer holds the go_ and process_ metrics, which the
		// registry of this request does not.
		gatherers := prometheus.Gatherers{prometheus.DefaultGatherer, registry}

		promhttp.HandlerFor(gatherers, promhttp.HandlerOpts{}).ServeHTTP(w, r)
	})
}

// collect probes every target and writes the metrics of this scrape. It
// builds the metrics from the results of this scrape only, so a target that
// leaves the configuration leaves the output, and a probe that fails reports
// no expiry.
func (e *Exporter) collect(ctx context.Context, ch chan<- prometheus.Metric) {

	results := make([]result, len(e.httpTargets)+len(e.smtpTargets))

	var wg sync.WaitGroup
	wg.Add(len(results))

	for i, target := range e.httpTargets {
		go func(slot int, target httpTarget) {
			defer wg.Done()
			results[slot] = e.probe(probeHTTP(ctx, target))
		}(i, target)
	}

	offset := len(e.httpTargets)

	for i, target := range e.smtpTargets {
		go func(slot int, target smtpTarget) {
			defer wg.Done()
			results[slot] = e.probe(probeSMTP(ctx, target, e.timeout))
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
