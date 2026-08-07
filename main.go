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

	http.Handle("/metrics", promhttp.Handler())

	if config.ServerTLS.Enabled() {
		log.Printf("starting exporter with TLS on %s", *addr)
		log.Fatal(http.ListenAndServeTLS(*addr,
			config.ServerTLS.CertFile, config.ServerTLS.KeyFile, nil))
	}

	log.Printf("starting exporter on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
