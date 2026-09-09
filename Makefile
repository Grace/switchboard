.PHONY: fmt check test build dev-up dev-smoke dev-down dev-logs

# `make check` is the go job from .github/workflows/ci.yml, runnable before a
# push. It did not exist, which is how two gofmt nits sat on main for eight
# commits. Note the $$: a single $ is make's own expansion, so `$(gofmt -l ...)`
# would expand to nothing here and pass unconditionally.
fmt:
	gofmt -w cmd internal
check:
	test -z "$$(gofmt -l cmd internal)"
	go vet ./...
	go test -race ./...

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
