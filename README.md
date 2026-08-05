# SSL Exporter for Prometheus

Run checks against HTTPS and SMTP (STARTTLS) endpoints and expose metrics about their SSL certificates

## Installation

    $ go get -u github.com/chrj/prometheus-ssl-exporter

## Usage

    Usage of prometheus-ssl-exporter:
      -config string
        	Configuration file (default "/etc/ssl/checks")
      -listen-address string
        	Prometheus metrics port (default ":9203")
      -timeout duration
        	Timeout for network operations (default 10s)

## Metrics

### Gauge: `ssl_certificate_days_left`

Number of days left on the certificate.

Labels:

* `domain`
* `type`

### Gauge: `ssl_endpoint_up`

Was the last SSL poll successful.

Labels:

* `domain`
* `type`

### Examples

    # HELP ssl_certificate_days_left Number of days left on the certificate
    # TYPE ssl_certificate_days_left gauge
    ssl_certificate_days_left{domain="smtp.gmail.com",type="smtp"} 48
    ssl_certificate_days_left{domain="www.google.com",type="http"} 48
    ssl_certificate_days_left{domain="www.technobabble.dk",type="http"} 36
    # HELP ssl_endpoint_up Was the last SSL poll successful
    # TYPE ssl_endpoint_up gauge
    ssl_endpoint_up{domain="smtp.gmail.com",type="smtp"} 1
    ssl_endpoint_up{domain="www.google.com",type="http"} 1
    ssl_endpoint_up{domain="www.technobabble.dk",type="http"} 1


## Configuration

Supply a configuration file path with `-config` (optionally, defaults to `/etc/ssl/checks`). Uses [TOML](https://github.com/toml-lang/toml).

[Sample configuration file](config.sample)

The file holds the targets and the options below. The exporter reads the CA
files at startup, so a file that it cannot read stops the exporter with a
message that names the target.

### Per-target options for `[[http_domains]]` and `[[smtp_domains]]`

* `ca_file`: a PEM file with the certificate authority that signed the
  certificate of this target. An empty value selects the system pool.
* `insecure_skip_verify`: set it to `true` to stop the certificate checks
  for this target. The probe still reports the expiry.

For an SMTP target, these options apply to the STARTTLS session.

### `[tls_server]`

Serve the metrics endpoint with TLS. Give `cert_file` and `key_file`
together, or give neither.

## Prometheus target

Supply a listen address with `-addr` (optionally, defaults to `:9203`), and configure a Prometheus job:

    - job_name: "ssl"
      scrape_interval: "1m"
      static_configs:
        - targets:
            - "server:9203"

## Prometheus alert

The real benefit is getting an alert triggered when an SSL certificate is nearing expiration or not responding. Check this [sample alert definition](ssl.rules).
