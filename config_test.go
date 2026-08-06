package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeFile puts content in a new file under the temporary directory of the
// test and returns the path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}

	return path
}

// writeCAFile makes a self-signed certificate and writes it as PEM.
func writeCAFile(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create a certificate: %v", err)
	}

	return writeFile(t, "ca.pem", string(pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: der})))
}

func TestLoadConfig(t *testing.T) {
	content := `
[[http_domains]]
  domain = "www.example.com"

[[http_domains]]
  domain = "internal.example.com"
  insecure_skip_verify = true

[[smtp_domains]]
  domain = "smtp.example.com"
  port = 587

[[smtp_domains]]
  domain = "mail.example.com"
  port = 25
  insecure_skip_verify = true

[tls_server]
  cert_file = "/etc/ssl/exporter.pem"
  key_file = "/etc/ssl/exporter.key"
`

	config, err := LoadConfig(writeFile(t, "checks.toml", content))
	if err != nil {
		t.Fatalf("LoadConfig returned an error: %v", err)
	}

	if len(config.HTTPDomains) != 2 {
		t.Fatalf("http_domains: got %d, want 2", len(config.HTTPDomains))
	}
	if got := config.HTTPDomains[0].Domain; got != "www.example.com" {
		t.Errorf("http_domains[0].domain: got %q, want %q", got, "www.example.com")
	}
	if got := config.HTTPDomains[0].InsecureSkipVerify; got {
		t.Errorf("http_domains[0].insecure_skip_verify: got %v, want false", got)
	}
	if got := config.HTTPDomains[1].InsecureSkipVerify; !got {
		t.Errorf("http_domains[1].insecure_skip_verify: got %v, want true", got)
	}

	if len(config.SMTPDomains) != 2 {
		t.Fatalf("smtp_domains: got %d, want 2", len(config.SMTPDomains))
	}
	if got := config.SMTPDomains[0].Domain; got != "smtp.example.com" {
		t.Errorf("smtp_domains[0].domain: got %q, want %q", got, "smtp.example.com")
	}
	if got := config.SMTPDomains[0].Port; got != 587 {
		t.Errorf("smtp_domains[0].port: got %d, want 587", got)
	}
	if got := config.SMTPDomains[0].InsecureSkipVerify; got {
		t.Errorf("smtp_domains[0].insecure_skip_verify: got %v, want false", got)
	}
	if got := config.SMTPDomains[1].InsecureSkipVerify; !got {
		t.Errorf("smtp_domains[1].insecure_skip_verify: got %v, want true", got)
	}

	if got := config.ServerTLS.CertFile; got != "/etc/ssl/exporter.pem" {
		t.Errorf("tls_server.cert_file: got %q, want %q", got, "/etc/ssl/exporter.pem")
	}
	if !config.ServerTLS.Enabled() {
		t.Error("ServerTLS.Enabled(): got false, want true")
	}
}

// TestLoadConfigOldFormat keeps the file of an existing deployment working.
func TestLoadConfigOldFormat(t *testing.T) {
	content := `
[[http_domains]]
  domain = "www.google.com"

[[smtp_domains]]
  domain = "smtp.gmail.com"
  port = 587
`

	config, err := LoadConfig(writeFile(t, "checks", content))
	if err != nil {
		t.Fatalf("LoadConfig returned an error: %v", err)
	}

	if len(config.HTTPDomains) != 1 || config.HTTPDomains[0].Domain != "www.google.com" {
		t.Errorf("http_domains: got %+v, want one entry for www.google.com", config.HTTPDomains)
	}
	if len(config.SMTPDomains) != 1 || config.SMTPDomains[0].Port != 587 {
		t.Errorf("smtp_domains: got %+v, want one entry on port 587", config.SMTPDomains)
	}
	if config.ServerTLS.Enabled() {
		t.Error("ServerTLS.Enabled(): got true, want false")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := LoadConfig(filepath.Join(t.TempDir(), "absent.toml"))
	if err == nil {
		t.Fatal("LoadConfig returned no error for a file that does not exist")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error: got %v, want it to wrap os.ErrNotExist", err)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name:   "empty configuration",
			config: Config{},
		},
		{
			name: "http domain with no name",
			config: Config{
				HTTPDomains: []HTTPDomain{{Domain: ""}},
			},
			wantErr: true,
		},
		{
			name: "smtp domain with no name",
			config: Config{
				SMTPDomains: []SMTPDomain{{Domain: "", Port: 587}},
			},
			wantErr: true,
		},
		{
			name: "smtp port of zero",
			config: Config{
				SMTPDomains: []SMTPDomain{{Domain: "smtp.example.com", Port: 0}},
			},
			wantErr: true,
		},
		{
			name: "smtp port above the range",
			config: Config{
				SMTPDomains: []SMTPDomain{{Domain: "smtp.example.com", Port: 70000}},
			},
			wantErr: true,
		},
		{
			name: "smtp port at the top of the range",
			config: Config{
				SMTPDomains: []SMTPDomain{{Domain: "smtp.example.com", Port: 65535}},
			},
		},
		{
			name: "certificate file with no key file",
			config: Config{
				ServerTLS: ServerTLS{CertFile: "/etc/ssl/exporter.pem"},
			},
			wantErr: true,
		},
		{
			name: "key file with no certificate file",
			config: Config{
				ServerTLS: ServerTLS{KeyFile: "/etc/ssl/exporter.key"},
			},
			wantErr: true,
		},
		{
			name: "CA file that does not exist",
			config: Config{
				HTTPDomains: []HTTPDomain{{
					Domain: "internal.example.com",
					CAFile: "/does/not/exist.pem",
				}},
			},
			wantErr: true,
		},
		{
			name: "SMTP CA file that does not exist",
			config: Config{
				SMTPDomains: []SMTPDomain{{
					Domain: "mail.example.com",
					Port:   587,
					CAFile: "/does/not/exist.pem",
				}},
			},
			wantErr: true,
		},
		{
			name: "the same HTTP domain twice",
			config: Config{
				HTTPDomains: []HTTPDomain{
					{Domain: "www.example.com"},
					{Domain: "www.example.com", InsecureSkipVerify: true},
				},
			},
			wantErr: true,
		},
		{
			name: "the same SMTP domain on two ports",
			config: Config{
				SMTPDomains: []SMTPDomain{
					{Domain: "mail.example.com", Port: 25},
					{Domain: "mail.example.com", Port: 587},
				},
			},
			wantErr: true,
		},
		{
			name: "the same domain for HTTP and SMTP",
			config: Config{
				HTTPDomains: []HTTPDomain{{Domain: "mail.example.com"}},
				SMTPDomains: []SMTPDomain{{Domain: "mail.example.com", Port: 587}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.config.Validate()
			if test.wantErr && err == nil {
				t.Error("Validate returned no error, want an error")
			}
			if !test.wantErr && err != nil {
				t.Errorf("Validate returned an error: %v", err)
			}
		})
	}
}

func TestTLSConfig(t *testing.T) {
	caFile := writeCAFile(t)

	t.Run("system pool", func(t *testing.T) {
		config, err := TLSConfig("www.example.com", "", false)
		if err != nil {
			t.Fatalf("TLSConfig returned an error: %v", err)
		}
		if config.ServerName != "www.example.com" {
			t.Errorf("ServerName: got %q, want %q", config.ServerName, "www.example.com")
		}
		if config.InsecureSkipVerify {
			t.Error("InsecureSkipVerify: got true, want false")
		}
		if config.RootCAs != nil {
			t.Error("RootCAs: got a pool, want nil for the system pool")
		}
	})

	t.Run("skip the check", func(t *testing.T) {
		config, err := TLSConfig("www.example.com", "", true)
		if err != nil {
			t.Fatalf("TLSConfig returned an error: %v", err)
		}
		if !config.InsecureSkipVerify {
			t.Error("InsecureSkipVerify: got false, want true")
		}
	})

	t.Run("custom authority", func(t *testing.T) {
		config, err := TLSConfig("internal.example.com", caFile, false)
		if err != nil {
			t.Fatalf("TLSConfig returned an error: %v", err)
		}
		if config.RootCAs == nil {
			t.Fatal("RootCAs: got nil, want the pool from the CA file")
		}
	})

	t.Run("CA file that does not exist", func(t *testing.T) {
		_, err := TLSConfig("internal.example.com", "/does/not/exist.pem", false)
		if err == nil {
			t.Fatal("TLSConfig returned no error for a file that does not exist")
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("error: got %v, want it to wrap os.ErrNotExist", err)
		}
	})

	t.Run("CA file with no certificate", func(t *testing.T) {
		empty := writeFile(t, "empty.pem", "this file holds no PEM block\n")

		_, err := TLSConfig("internal.example.com", empty, false)
		if err == nil {
			t.Fatal("TLSConfig returned no error for a file with no certificate")
		}
		if !errors.Is(err, errNoCertificate) {
			t.Errorf("error: got %v, want it to wrap errNoCertificate", err)
		}
	})
}
