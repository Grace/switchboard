# API and failure contract

## Gateway

| Endpoint | Authentication | Meaning |
|---|---|---|
| `POST /v1/chat/completions` | Local bearer token | Text generation using policy routes |
| `GET /healthz` | Loopback | Process responsive |
| `GET /readyz` | Loopback | Not draining; unexpired policy has a configured route |
| `GET /metrics` | Loopback | Prometheus exposition; no secrets or prompts |
| `GET /runtime` | Local bearer token | Readiness, policy version and expiry |

Readiness deliberately does not depend on the control plane, telemetry delivery or provider health checks. It cannot promise that an external provider is currently reachable. Liveness is distinct from readiness.

Streaming emits OpenAI-style `chat.completion.chunk` objects with stable generated ID, model, creation time, choice index, text delta and finish reason. Successful termination has exactly one `[DONE]`. Midstream failure emits an `error` object and closes without `[DONE]`; the already-sent HTTP status cannot change. Clients must regard EOF without `[DONE]` as failure and not automatically replay it.

OpenAI uses Chat Completions, Anthropic uses Messages, and Gemini uses `generateContent` / `streamGenerateContent?alt=sse`. Safety blocks normalize to `content_filter`; output limits to `length`; normal completion to `stop`. Unknown content/tool blocks and finish reasons fail closed. Hidden Gemini thought text is not exposed. Streaming usage chunks are not part of this initial portable subset. Nonstreaming usage contains normalized counts supplied by the provider, with missing counts zero.

## Failover matrix

| Result | Automatic next route? |
|---|---|
| Provider not configured or circuit open | Skip before sending |
| HTTP 429 or 503, before acceptance | Yes, if retry budget and attempt cap permit |
| HTTP 400, 401, 403, 404, 422, 500, 502, 504 or redirect | No |
| Transport error or timeout | No: server may already have accepted generation |
| HTTP 200 with malformed/unsupported body | No |
| Stream accepted then interrupted | No |
| Client cancellation | No |

429/503 failover still cannot establish provider-side exactly-once execution or equivalent model behavior. Select only routes approved for the workload, retention rules and regional requirements. `Retry-After` from a provider is not waited out: this release moves to a different approved provider with short jitter, bounded by the retry budget. No route is retried twice in one request.

`Idempotency-Key` is explicitly rejected. This gateway does not cache generated content or claim cross-provider idempotency. Disable automatic SDK retries (`max_retries=0` in the OpenAI Python client). Use application operation IDs and an application-owned transactional outbox for external side effects. Tools are entirely unsupported, including tool history, so no tool invocation can be silently translated or executed here.

## Control plane

Every protected call derives tenant and role from a hashed bearer credential. Tenant IDs supplied in policy bodies must match that identity.

| Role | Capabilities |
|---|---|
| `agent` | Read policy; ingest telemetry |
| `viewer` | Read policy, recent telemetry and audit |
| `publisher` | Read/publish policy and read telemetry |
| `admin` | Read/publish policy, read telemetry/audit, create and revoke principals |

- `GET/PUT /v1/policy`: returns or publishes the signed envelope; version must strictly increase.
- `POST /v1/telemetry`: bounded metadata-only event; returns `{ "id": "..." }` after transaction commit. Duplicate IDs do not insert twice.
- `GET /v1/telemetry`, `GET /v1/audit`: most recent 100 rows for this tenant.
- `POST /v1/principals`: SHA-256 digest of a caller-generated random credential, role and Unix expiry (at most 90 days); returns principal UUID. Raw credentials are never returned by this API.
- `DELETE /v1/principals/{uuid}`: revoke within current tenant.

Credential creation is caller-controlled: use at least 256 bits of random entropy, store it in a secrets system, and send only its SHA-256 digest to the principal endpoint. A digest is not a bearer credential. Authentication has no long-lived cache; revocation takes effect on subsequent calls. Already-admitted calls can finish.
