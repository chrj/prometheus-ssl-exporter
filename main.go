package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"sync"
	"time"

	"github.com/naoina/toml"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

var (
	addr           = flag.String("listen-address", ":9203", "Prometheus metrics port")
	conf           = flag.String("config", "/etc/ssl/checks", "Configuration file")
	exporterConfig = flag.String("exporter-config", "exporter.yml", "Exporter configuration file")
	timeout        = flag.Duration("timeout", 8*time.Second, "Timeout for network operations")
)

var httpClient *http.Client

type HTTPDomain struct {
	Domain string
}

type SMTPDomain struct {
	Domain string
	Port   int
}

// custom TLS config for the exporter itself
type TLSConfigServer struct {
	Server struct {
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
	} `yaml:"tls_server_config"`
}

// config for the exporter itself
type Config struct {
	ListenAddr      string            `yaml:"port"`
	CAs             map[string]string `yaml:"cas"`
	SkipTLSVerify   bool              `yaml:"skip_tls_verify"`
	TlsConfigServer string            `yaml:"tls_config_server"`
}

func readConfig(path string) (*Config, error) {
	viper.SetConfigType("yaml")

	file, err := os.Open(path)
	defer file.Close()

	if err != nil {
		return nil, err
	}

	if err := viper.ReadConfig(file); err != nil {
		return nil, err
	}

	return &Config{
		ListenAddr:      viper.GetString("listen_addr"),
		CAs:             viper.GetStringMapString("cas"),
		SkipTLSVerify:   viper.GetBool("skip_tls_verify"),
		TlsConfigServer: viper.GetString("tls_config_server"),
	}, nil
}

type Exporter struct {
	HTTPDomains []HTTPDomain
	SMTPDomains []SMTPDomain

	certificates *prometheus.GaugeVec
	status       *prometheus.GaugeVec
	config       *Config
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
	e.status.Collect(ch)

}

func (e *Exporter) collectHTTPDomain(domain string) {

	req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s/", domain), nil)
	req.Header.Set("User-Agent", "prometheus-ssl-exporter/0.1 (SSL monitoring)")

	tlsConfig, err := prepareTlsConfig(e.config, domain)
	if err != nil {
		log.Printf("error preparing TLS config for %v: %v", domain, err)
	}
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

func (e *Exporter) collectSMTPDomain(domain string, port int) {

	target := fmt.Sprintf("%s:%d", domain, port)

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

func prepareTlsConfig(config *Config, domain string) (*tls.Config, error) {
	var (
		caCert     []byte
		caCertPool *x509.CertPool = nil
	)
	if !config.SkipTLSVerify {
		var err error
		caCert, err = os.ReadFile(config.CAs[domain])
		if err != nil {
			fmt.Printf("no valid custom CA certificate provided for domain %s will continue without custom CA\n", domain)
			goto ret
		}
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
	}
ret:
	return &tls.Config{
		InsecureSkipVerify: config.SkipTLSVerify,
		RootCAs:            caCertPool,
	}, nil
}

func main() {

	flag.Parse()

	httpClient = &http.Client{
		Timeout: *timeout,
	}
	config, err := readConfig(*exporterConfig)
	if err != nil {
		log.Fatalf("couldn't read configuration file: %v", err)
	}

	f, err := os.Open(*conf)
	if err != nil {
		log.Fatalf("couldn't open configuration file: %v", err)
	}

	exporter := NewSSLExporter()
	exporter.config = config
	if err := toml.NewDecoder(f).Decode(exporter); err != nil {
		log.Fatalf("couldn't parse configuration file: %v", err)
	}

	prometheus.MustRegister(exporter)

	http.Handle("/metrics", promhttp.Handler())

	if config.ListenAddr != "" {
		*addr = config.ListenAddr
	}

	if config.TlsConfigServer != "" {
		log.Printf("using TLS config %s", config.TlsConfigServer)
		file, err := os.ReadFile(config.TlsConfigServer)
		if err != nil {
			log.Fatalf("couldn't read TLS config file: %v", err)
		}
		var tlsConfig TLSConfigServer
		if err := yaml.Unmarshal(file, &tlsConfig); err != nil {
			log.Fatalf("couldn't parse TLS config file: %v", err)
		}
		log.Printf("starting exporter with TLS on %s", *addr)
		log.Fatal(http.ListenAndServeTLS(*addr, tlsConfig.Server.CertFile, tlsConfig.Server.KeyFile, nil))
	}
	log.Printf("starting exporter on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
