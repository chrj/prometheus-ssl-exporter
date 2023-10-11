BINARY_NAME=prometheus-ssl-exporter

build:
	@go build -o bin/$(BINARY_NAME) -v

run: build
	@./bin/$(BINARY_NAME)

# run-config: build
# 	@./bin/$(BINARY_NAME) --exporter-config /path/to/config/exporter.yml