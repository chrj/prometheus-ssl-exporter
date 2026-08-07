BINARY_NAME=prometheus-ssl-exporter

build:
	@go build -o bin/$(BINARY_NAME) -v

run: build
	@./bin/$(BINARY_NAME)

run-sample: build
	@./bin/$(BINARY_NAME) -config config.sample