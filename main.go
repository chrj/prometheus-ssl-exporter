package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	addr    = flag.String("listen-address", ":9203", "Prometheus metrics port")
	conf    = flag.String("config", "/etc/ssl/checks", "Configuration file")
	timeout = flag.Duration("timeout", 8*time.Second, "Timeout for network operations")
)

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

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	// The timeouts stop a client that opens a connection and then stalls.
	// WriteTimeout covers the whole response, so it holds every probe of one
	// scrape and stays above the timeout for network operations.
	server := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      *timeout + 30*time.Second,
	}

	if config.ServerTLS.Enabled() {
		log.Printf("starting exporter with TLS on %s", *addr)
		log.Fatal(server.ListenAndServeTLS(
			config.ServerTLS.CertFile, config.ServerTLS.KeyFile))
	}

	log.Printf("starting exporter on %s", *addr)
	log.Fatal(server.ListenAndServe())
}
