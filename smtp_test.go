package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// testCA is a certificate authority and a server certificate that it signed.
type testCA struct {
	// CAFile is the path of the PEM file with the authority.
	CAFile string
	// ServerCert is the certificate for the host "localhost".
	ServerCert tls.Certificate
}

// newTestCA makes an authority, signs a certificate for "localhost", and
// writes the authority to a file.
func newTestCA(t *testing.T) testCA {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate the key of the authority: %v", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create the certificate of the authority: %v", err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse the certificate of the authority: %v", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate the key of the server: %v", err)
	}

	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	serverDER, err := x509.CreateCertificate(
		rand.Reader, &serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create the certificate of the server: %v", err)
	}

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write the file of the authority: %v", err)
	}

	return testCA{
		CAFile: caPath,
		ServerCert: tls.Certificate{
			Certificate: [][]byte{serverDER},
			PrivateKey:  serverKey,
			Leaf:        &serverTemplate,
		},
	}
}

// startSMTPServer runs an SMTP server that offers STARTTLS. It returns the
// port. The server stops when the test ends.
func startSMTPServer(t *testing.T, cert tls.Certificate) int {
	t.Helper()

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split the address of the listener: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse the port: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				serveSMTP(conn, tlsConfig)
			}()
		}
	}()

	t.Cleanup(func() {
		close(done)
		listener.Close()
		wg.Wait()
	})

	return port
}

// serveSMTP answers the commands that the probe sends. It offers STARTTLS
// and then continues the session inside TLS.
func serveSMTP(conn net.Conn, tlsConfig *tls.Config) {
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return
	}

	reader := bufio.NewReader(conn)

	write := func(line string) bool {
		_, err := conn.Write([]byte(line + "\r\n"))
		return err == nil
	}

	if !write("220 localhost ESMTP test") {
		return
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		command := strings.ToUpper(strings.TrimSpace(line))

		switch {
		case strings.HasPrefix(command, "EHLO"):
			if !write("250-localhost") || !write("250 STARTTLS") {
				return
			}

		case strings.HasPrefix(command, "HELO"):
			if !write("250 localhost") {
				return
			}

		case command == "STARTTLS":
			if !write("220 ready to start TLS") {
				return
			}

			tlsConn := tls.Server(conn, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				return
			}

			defer tlsConn.Close()
			conn = tlsConn
			reader = bufio.NewReader(tlsConn)

		case command == "QUIT":
			write("221 bye")
			return

		default:
			if !write("250 ok") {
				return
			}
		}
	}
}

// gatherSMTP runs one scrape over a single SMTP target and returns the value
// of ssl_endpoint_up.
func gatherSMTP(t *testing.T, target SMTPDomain) float64 {
	t.Helper()

	exporter, err := NewSSLExporter(&Config{SMTPDomains: []SMTPDomain{target}}, 5*time.Second)
	if err != nil {
		t.Fatalf("NewSSLExporter: %v", err)
	}

	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(exporter); err != nil {
		t.Fatalf("register the exporter: %v", err)
	}

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	for _, family := range families {
		if family.GetName() != "ssl_endpoint_up" {
			continue
		}
		for _, metric := range family.GetMetric() {
			return metric.GetGauge().GetValue()
		}
	}

	t.Fatal("ssl_endpoint_up is not in the gathered metrics")
	return 0
}

// TestSMTPCustomCA probes a server whose certificate a private authority
// signed. The probe reports the target as up only when it gets that
// authority, or when the check is off.
func TestSMTPCustomCA(t *testing.T) {
	ca := newTestCA(t)
	port := startSMTPServer(t, ca.ServerCert)

	tests := []struct {
		name   string
		target SMTPDomain
		want   float64
	}{
		{
			name:   "the system pool does not hold the authority",
			target: SMTPDomain{Domain: "localhost", Port: port},
			want:   0,
		},
		{
			name: "the custom authority is trusted",
			target: SMTPDomain{
				Domain: "localhost",
				Port:   port,
				CAFile: ca.CAFile,
			},
			want: 1,
		},
		{
			name: "the check is off",
			target: SMTPDomain{
				Domain:             "localhost",
				Port:               port,
				InsecureSkipVerify: true,
			},
			want: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := gatherSMTP(t, test.target); got != test.want {
				t.Errorf("ssl_endpoint_up: got %v, want %v", got, test.want)
			}
		})
	}
}

// TestSMTPCertificateExpiry makes sure that the probe reports the expiry of
// the certificate that the server presents.
func TestSMTPCertificateExpiry(t *testing.T) {
	ca := newTestCA(t)
	port := startSMTPServer(t, ca.ServerCert)

	exporter, err := NewSSLExporter(&Config{
		SMTPDomains: []SMTPDomain{{
			Domain: "localhost",
			Port:   port,
			CAFile: ca.CAFile,
		}},
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("NewSSLExporter: %v", err)
	}

	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(exporter); err != nil {
		t.Fatalf("register the exporter: %v", err)
	}

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	var daysLeft float64
	var found bool
	for _, family := range families {
		if family.GetName() != "ssl_certificate_days_left" {
			continue
		}
		for _, metric := range family.GetMetric() {
			found = true
			daysLeft = metric.GetGauge().GetValue()
		}
	}

	if !found {
		t.Fatal("ssl_certificate_days_left is not in the gathered metrics")
	}

	// The test certificate ends 24 hours from now.
	if daysLeft < 0 || daysLeft > 1 {
		t.Errorf("ssl_certificate_days_left: got %v, want a value between 0 and 1", daysLeft)
	}
}
