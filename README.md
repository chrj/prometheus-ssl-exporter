# SSL Exporter for Prometheus

[![CI](https://github.com/chrj/prometheus-ssl-exporter/actions/workflows/go.yml/badge.svg)](https://github.com/chrj/prometheus-ssl-exporter/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/chrj/prometheus-ssl-exporter)](https://goreportcard.com/report/github.com/chrj/prometheus-ssl-exporter)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Watch the certificates of your HTTPS and SMTP endpoints, and get an alert
before one of them expires.

The exporter holds a list of targets in one file. On each scrape it
connects to every target, reads the certificate that the server presents,
and reports the start and the end of its validity. An HTTPS target gets a
`GET` request. An SMTP target gets a STARTTLS session.

## Installation

Build from source with Go 1.26 or later:

```sh
go install github.com/chrj/prometheus-ssl-exporter@latest
```

There are no released binaries and no container image yet.

## Usage

```
Usage of prometheus-ssl-exporter:
  -config string
        Configuration file (default "/etc/ssl/checks")
  -listen-address string
        Prometheus metrics port (default ":9203")
  -timeout duration
        Timeout for network operations (default 8s)
```

## Configuration

The configuration file holds the targets. It uses
[TOML](https://toml.io/). Start from the [sample configuration
file](config.sample):

```toml
[[http_domains]]
  domain = "www.google.com"

[[smtp_domains]]
  domain = "smtp.gmail.com"
  port = 587
```

The exporter reads the file once, at startup. Send it a restart after you
change the file.

### Per-target options

These options apply to an `[[http_domains]]` entry and to an
`[[smtp_domains]]` entry. For an SMTP target they apply to the STARTTLS
session.

| Option | Meaning |
| --- | --- |
| `ca_file` | A PEM file with the certificate authority that signed the certificate of this target. An empty value selects the system pool. |
| `insecure_skip_verify` | Set it to `true` to stop the certificate checks for this target. The probe still reports the validity. |

The exporter reads every `ca_file` at startup. A file that it cannot read
stops the exporter, and the message names the target.

### Serve the metrics with TLS

```toml
[tls_server]
  cert_file = "/etc/ssl/exporter.pem"
  key_file = "/etc/ssl/exporter.key"
```

Give both files, or give neither.

## Metrics

Every metric carries the labels `domain` and `type`. The `type` label is
`http` or `smtp`.

| Metric | Meaning |
| --- | --- |
| `ssl_cert_not_after` | End of the validity of the certificate, as seconds since the epoch. |
| `ssl_cert_not_before` | Start of the validity of the certificate, as seconds since the epoch. |
| `ssl_endpoint_up` | 1 when the last probe read a certificate, 0 when it did not. |
| `ssl_certificate_days_left` | Days left on the certificate. Deprecated, see below. |

A probe that fails reports `ssl_endpoint_up 0` and no certificate
metrics. The certificate metrics of that target stay out of the output
until a probe succeeds again. A stored value from an older scrape never
reaches the output.

### Example

```
# HELP ssl_cert_not_after End of the validity of the certificate, as seconds since the epoch
# TYPE ssl_cert_not_after gauge
ssl_cert_not_after{domain="smtp.gmail.com",type="smtp"} 1.791828448e+09
ssl_cert_not_after{domain="www.google.com",type="http"} 1.789980012e+09
ssl_cert_not_after{domain="www.technobabble.dk",type="http"} 1.788093249e+09
# HELP ssl_cert_not_before Start of the validity of the certificate, as seconds since the epoch
# TYPE ssl_cert_not_before gauge
ssl_cert_not_before{domain="smtp.gmail.com",type="smtp"} 1.784570849e+09
ssl_cert_not_before{domain="www.google.com",type="http"} 1.782722413e+09
ssl_cert_not_before{domain="www.technobabble.dk",type="http"} 1.78031725e+09
# HELP ssl_endpoint_up Was the last SSL poll successful
# TYPE ssl_endpoint_up gauge
ssl_endpoint_up{domain="smtp.gmail.com",type="smtp"} 1
ssl_endpoint_up{domain="www.google.com",type="http"} 1
ssl_endpoint_up{domain="www.technobabble.dk",type="http"} 1
```

### `ssl_certificate_days_left` is deprecated

Use `ssl_cert_not_after` instead:

```promql
(ssl_cert_not_after - time()) / 86400
```

The two give the same number. `ssl_cert_not_after` is a fixed point in
time, so a graph of it holds a straight line while the certificate stays
the same. `ssl_certificate_days_left` falls on every scrape, which hides
the date and makes a recording rule only as correct as the last sample.

`ssl_certificate_days_left` stays for the installations that use it
today. It goes away in a later major version.

## Prometheus configuration

```yaml
- job_name: "ssl"
  scrape_interval: "1m"
  static_configs:
    - targets:
        - "server:9203"
```

Each scrape starts one probe for each target, so keep the interval longer
than the time that the slowest target needs.

## Alerting

The [sample alert definition](ssl.rules.yml) holds three alerts:

| Alert | Condition |
| --- | --- |
| `SSLCertificateNearExpiration` | The certificate is valid and ends in less than 21 days. |
| `SSLCertificateExpired` | The certificate ended. |
| `SSLEndpointDown` | The probes of the target failed for 15 minutes. |

Check the file after you change it:

```sh
promtool check rules ssl.rules.yml
```

## How this compares to ssl_exporter

[`ribbybibby/ssl_exporter`](https://github.com/ribbybibby/ssl_exporter)
covers more ground. It reads certificates from PEM files, Kubernetes
secrets, and kubeconfig files, it queries OCSP, and it speaks STARTTLS
for SMTP, FTP, IMAP, POP3, and PostgreSQL.

The two differ in the way they get their targets:

- `ssl_exporter` follows the model of the blackbox exporter. Prometheus
  holds the target list and passes each target as a query parameter to
  `/probe`. Service discovery therefore works.
- This exporter holds the target list in its own file and reports every
  target on `/metrics`.

Pick this one for a fixed list of endpoints that you want in one file.
Pick `ssl_exporter` for targets that come from service discovery, or for
certificates that do not sit behind a network endpoint.

## License

[MIT](LICENSE)
