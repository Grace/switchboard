<p align="center">
  <img src="docs/img/switchboard.png" alt="Switchboard" width="420">
</p>

# Switchboard Sidecar

Switchboard is an AI infrastructure platform. The **Switchboard Sidecar** is its
deployable data-plane component: a Go inference sidecar with a Postgres-backed
Python/FastAPI control plane, targeting AWS ECS/Fargate.

It runs beside your application in the same task, exposes one OpenAI-compatible
endpoint on loopback, and routes to OpenAI, Anthropic or Gemini according to a
signed policy it cannot itself edit.

**Release status: production-oriented release candidate, not production-certified.** This is a fresh implementation of the Switchboard architecture and has not been verified for compatibility with any earlier version's implementation or persisted data. Read [validation](docs/VALIDATION.md) and [remaining gaps](docs/GAPS.md) before deployment.

## What is implemented

- Loopback-only, single-tenant Go data plane; text chat normalization for OpenAI, Anthropic, Gemini and Amazon Bedrock. Streaming for the first three; Bedrock is nonstreaming, and a streaming request skips a Bedrock route rather than failing.
- Postgres persistence, migrations, hashed bearer credentials, tenant-scoped RBAC, row-level security, revocation and audit records.
- Ed25519 policy signatures, restricted canonical JSON, pinned overlapping verification keys, expiry, version rollback/equivocation protection and atomic disk cache.
- Inference uses only local policy and direct provider connections. Control-plane polling and telemetry delivery are background work.
- Bounded concurrency, token-bucket rate limiting, retry budget, circuit breakers, body/event limits, total generation deadline, slow-client protection and graceful shutdown.
- Nonblocking telemetry admission, fsynced disk spool, acknowledgement-based deletion, replay after process restart and deduplicated ingestion.
- OTLP/HTTP JSON trace export on an independent bounded queue, Prometheus counters/gauges, generated request IDs, W3C trace context and structured logs.
- Hardened Dockerfiles, ECS task example, Terraform sidecar/control-plane/RDS modules, CI and unit/integration scenarios.

## Supported API

```http
POST /v1/chat/completions
Authorization: Bearer <local application token>
Content-Type: application/json

{"model":"preferred","stream":true,"max_tokens":1024,"messages":[{"role":"user","content":"Hello"}]}
```

Only `model`, `messages`, `stream`, `max_tokens`, and `temperature` are supported. Text-only `system` (first message only), `user`, and `assistant` roles; final message must be `user`. Temperature is limited to the portable 0–1 subset. There must be one to 128 messages. Models are selected by the signed routing policy, not user-supplied provider model names.

**Tools, tool results, structured output, multimodal content, Responses API and provider-specific options are rejected.** Unknown request fields fail validation instead of being silently dropped. Set SDK retries to zero; an ambiguous failure is not an invitation to replay a generation. See [API and failover](docs/API.md).

## Build and test

Go 1.26 (or newer supported Go release) and Python 3.14:

```sh
go test -race ./...
go build -o bin/gateway ./cmd/gateway
python -m venv .venv
.venv/bin/pip install -r controlplane/requirements-dev.txt
.venv/bin/python -m unittest controlplane.tests.test_policy
```

The Postgres tests need a **disposable dedicated cluster** and `TEST_DATABASE_URL`; they create schema and roles. CI supplies Postgres automatically and runs these tests. `SWITCHBOARD_IN_MEMORY_TESTS=1 go test -race ./...` uses an in-process HTTP transport when sockets are unavailable; this does not validate real network behavior.

## Deploy

Follow [deployment](docs/DEPLOYMENT.md), then [security and rotation](docs/SECURITY.md). No real credentials, private signing keys or Terraform state belong in this repository. The `.env.example` contains runtime references only.

Directories: `cmd/gateway`, `internal/gateway`, `controlplane`, `deploy`, `scripts`, `testdata`, and `docs`. The fixture public key in `testdata` is intentionally test-only and is not a deployment trust key.

## License

Source available under the [Elastic License 2.0](LICENSE). Not an OSI-approved
open source license, and the project should not be described as open source.

You may read, audit, modify, self-host and run Switchboard in production,
including commercially. You may not offer it to third parties as a hosted or
managed service, and you may not circumvent or remove the licensing
functionality — in this codebase, the AWS Marketplace entitlement check in
`internal/gateway/marketplace.go`.

The auditability argument is unaffected: every line is readable, and the
dependency graph is 4 direct and 12 indirect modules, all AWS-published.

Contributions are not currently accepted. A DCO will be added before any
external contribution is taken, so that the copyright position stays
unambiguous.
