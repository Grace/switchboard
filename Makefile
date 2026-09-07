.PHONY: test build
test:
	go test -race ./...
	python -m pytest controlplane/tests -v
build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -o bin/gateway ./cmd/gateway
