package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/naoina/toml"
)

// errNoCertificate reports a CA file that holds no PEM certificate.
var errNoCertificate = errors.New("no PEM certificate found")

// HTTPDomain is one HTTPS target.
type HTTPDomain struct {
	Domain string `toml:"domain"`

	// CAFile is a PEM file with the certificate authority that signed the
	// certificate of this target. An empty value selects the system pool.
	CAFile string `toml:"ca_file"`

	// InsecureSkipVerify stops the certificate checks for this target. The
	// probe then reports the expiry of a certificate that it cannot trust.
	InsecureSkipVerify bool `toml:"insecure_skip_verify"`
}

// SMTPDomain is one SMTP target that the exporter reaches with STARTTLS.
type SMTPDomain struct {
	Domain string `toml:"domain"`
	Port   int    `toml:"port"`

	// CAFile is a PEM file with the certificate authority that signed the
	// certificate of this target. An empty value selects the system pool.
	CAFile string `toml:"ca_file"`

	// InsecureSkipVerify stops the certificate checks for this target. The
	// probe then reports the expiry of a certificate that it cannot trust.
	InsecureSkipVerify bool `toml:"insecure_skip_verify"`
}

// ServerTLS turns on TLS for the metrics listener. Give both files or
// neither.
type ServerTLS struct {
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

// Enabled reports whether the listener must serve TLS.
func (s ServerTLS) Enabled() bool {
	return s.CertFile != "" && s.KeyFile != ""
}

// Config is the content of the configuration file.
type Config struct {
	HTTPDomains []HTTPDomain `toml:"http_domains"`
	SMTPDomains []SMTPDomain `toml:"smtp_domains"`
	ServerTLS   ServerTLS    `toml:"tls_server"`
}

// LoadConfig reads and checks the configuration file at path.
func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open the configuration file %s: %w", path, err)
	}
	// The file is open for reading only, so a close error says nothing that
	// the caller can act on.
	defer func() { _ = f.Close() }()

	var config Config
	if err := toml.NewDecoder(f).Decode(&config); err != nil {
		return nil, fmt.Errorf("parse the configuration file %s: %w", path, err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration file %s: %w", path, err)
	}

	return &config, nil
}

// Validate reports the first fault that it finds in the configuration.
func (c *Config) Validate() error {
	// The metrics carry the labels "type" and "domain" only. Two targets of
	// the same type and domain give two series with the same labels, which
	// makes the whole scrape fail.
	httpSeen := make(map[string]int, len(c.HTTPDomains))
	smtpSeen := make(map[string]int, len(c.SMTPDomains))

	for i, target := range c.HTTPDomains {
		if target.Domain == "" {
			return fmt.Errorf("http_domains[%d]: domain is required", i)
		}
		if first, ok := httpSeen[target.Domain]; ok {
			return fmt.Errorf("http_domains[%d] %q: domain is already at http_domains[%d]",
				i, target.Domain, first)
		}
		httpSeen[target.Domain] = i

		if _, err := TLSConfig(target.Domain, target.CAFile, target.InsecureSkipVerify); err != nil {
			return fmt.Errorf("http_domains[%d] %q: %w", i, target.Domain, err)
		}
	}

	for i, target := range c.SMTPDomains {
		if target.Domain == "" {
			return fmt.Errorf("smtp_domains[%d]: domain is required", i)
		}
		if first, ok := smtpSeen[target.Domain]; ok {
			return fmt.Errorf("smtp_domains[%d] %q: domain is already at smtp_domains[%d]",
				i, target.Domain, first)
		}
		smtpSeen[target.Domain] = i

		if target.Port < 1 || target.Port > 65535 {
			return fmt.Errorf("smtp_domains[%d] %q: port %d is outside the range 1-65535",
				i, target.Domain, target.Port)
		}
		if _, err := TLSConfig(target.Domain, target.CAFile, target.InsecureSkipVerify); err != nil {
			return fmt.Errorf("smtp_domains[%d] %q: %w", i, target.Domain, err)
		}
	}

	if c.ServerTLS.CertFile != "" && c.ServerTLS.KeyFile == "" {
		return errors.New("tls_server: key_file is required with cert_file")
	}
	if c.ServerTLS.KeyFile != "" && c.ServerTLS.CertFile == "" {
		return errors.New("tls_server: cert_file is required with key_file")
	}

	return nil
}

// TLSConfig builds the client configuration for one target. LoadConfig calls
// it for every target, so a CA file that it cannot read stops the exporter at
// startup instead of breaking each scrape.
func TLSConfig(serverName, caFile string, skipVerify bool) (*tls.Config, error) {
	config := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: skipVerify,
		MinVersion:         tls.VersionTLS12,
	}

	if caFile == "" {
		return config, nil
	}

	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read the CA file: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA file %s: %w", caFile, errNoCertificate)
	}
	config.RootCAs = pool

	return config, nil
}
