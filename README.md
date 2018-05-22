# SSL Exporter for Prometheus

Run checks against HTTPS and SMTP (STARTTLS) endpoints and expose metrics about their SSL certificates

## Installation

    $ go get -u github.com/chrj/prometheus-ssl-exporter

## Metrics

### Gauge: `ssl_certificate_days_left`

Labels:

* `domain`
* `type`

Examples:

    # HELP ssl_certificate_days_left Number of days left on the certificate
    # TYPE ssl_certificate_days_left gauge
    ssl_certificate_days_left{domain="smtp.gmail.com",type="smtp"} 48
    ssl_certificate_days_left{domain="www.google.com",type="http"} 48
    ssl_certificate_days_left{domain="www.technobabble.dk",type="http"} 36

## Configuration

Supply a configuration file path with `-config` (optionally, defaults to `/etc/ssl/checks`). Uses [TOML](https://github.com/toml-lang/toml).

[Sample configuration file](config.sample)

## Prometheus target

Supply a listen address with `-addr` (optionally, defaults to `:9203`), and configure a Prometheus job:

    - job_name: "ssl"
      scrape_interval: "1m"
      static_configs:
        - targets:
            - "server:9203"

## Prometheus alert

The real benefit is getting an alert triggered when an SSL certificate is nearing expiration. Check this [sample alert definition](ssl.rules).
