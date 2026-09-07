.PHONY: test build dev-up dev-smoke dev-down dev-logs
test:
	go test -race ./...
	python -m pytest controlplane/tests -v
build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -o bin/gateway ./cmd/gateway

# Local end-to-end stack. See docs/LOCAL.md.
dev-up:
	./scripts/dev-up.sh
dev-smoke:
	./scripts/dev-smoke.sh
dev-down:
	./scripts/dev-down.sh
dev-logs:
	docker compose -f docker-compose.dev.yml logs -f gateway controlplane
