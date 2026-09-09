# API and failure contract

## Gateway

| Endpoint | Authentication | Meaning |
|---|---|---|
| `POST /v1/chat/completions` | Local bearer token | Text generation using policy routes |
| `GET /healthz` | Loopback | Process responsive |
| `GET /readyz` | Loopback | Not draining; unexpired policy has a configured route |
| `GET /metrics` | Loopback | Prometheus exposition; no secrets or prompts |
| `GET /runtime` | Local bearer token | Readiness, policy version and expiry |

### Unsupported request surface

The gateway models five request fields and rejects everything else. This is
deliberate -- unknown fields fail validation rather than being silently dropped,
so a caller never gets a response that quietly ignored what they asked for --
but it is a hard cap on what can run behind it, and it is easier to discover
here than from a 400.

| Not supported | Consequence |
|---|---|
| `tools`, `tool_choice`, `functions` | **No agentic workload can use this gateway.** No MCP host, no coding agent, no RAG-with-tools, no extraction pipeline. |
| Tool history: `role: "tool"`, assistant `tool_calls` | A tool loop cannot be carried even if the tools themselves were declared elsewhere. |
| `response_format`, structured output | JSON-mode and schema-constrained output are unavailable. |
| Multimodal content (`content` as an array of parts) | Text only. `content` must be a string. |
| `top_p`, `n`, `stop`, `seed`, `logprobs`, `stream_options`, provider-specific options | Rejected as unknown fields. |
| Responses API, embeddings, reranking, moderation, batch | Only `POST /v1/chat/completions` exists. |

Supported: `model` (which must be the literal `"preferred"`), `messages`,
`stream`, `max_tokens`, and `temperature` in the portable 0-1 subset. Roles are
`system` (first message only), `user`, and `assistant`, with 1-128 messages, and
the last message must be `user`. Plain multi-turn chat works; only the tool loop
does not.

Readiness deliberately does not depend on the control plane, telemetry delivery or provider health checks. It cannot promise that an external provider is currently reachable. Liveness is distinct from readiness.

Streaming emits OpenAI-style `chat.completion.chunk` objects with stable generated ID, model, creation time, choice index, text delta and finish reason. Successful termination has exactly one `[DONE]`. Midstream failure emits an `error` object and closes without `[DONE]`; the already-sent HTTP status cannot change. Clients must regard EOF without `[DONE]` as failure and not automatically replay it.

OpenAI uses Chat Completions, Anthropic uses Messages, and Gemini uses `generateContent` / `streamGenerateContent?alt=sse`. Safety blocks normalize to `content_filter`; output limits to `length`; normal completion to `stop`. Unknown content/tool blocks and finish reasons fail closed. Hidden Gemini thought text is not exposed. Streaming usage chunks are not part of this initial portable subset. Nonstreaming usage contains normalized counts supplied by the provider, with missing counts zero.

## Failover matrix

| Result | Automatic next route? |
|---|---|
| Provider not configured or circuit open | Skip before sending |
| HTTP 429 or 503, before acceptance | Yes, if retry budget and attempt cap permit |
| HTTP 401, 403 or 404, before acceptance | Yes. Refused before generation, so nothing was billed, and the refusal is specific to one provider: a key rotated at one says nothing about another, and a model one provider retired is not a model every provider retired. The refusing provider is then withheld for 60 seconds rather than retried on every request. |
| HTTP 400, 422 | No. The caller's request is malformed and would fail identically everywhere. The provider's own words are carried back. |
| HTTP 500, 502, 504 or redirect | No. The provider may have accepted the request and failed partway through generating it, so replaying it could be charged twice. It does count toward opening the circuit breaker. |
| Transport error or timeout | No: server may already have accepted generation |
| HTTP 200 with malformed/unsupported body | No |
| Stream accepted then interrupted | No |
| Client cancellation | No |

429/503 failover still cannot establish provider-side exactly-once execution or equivalent model behavior. Select only routes approved for the workload, retention rules and regional requirements. `Retry-After` from a provider is not waited out: this release moves to a different approved provider with short jitter, bounded by the retry budget. No route is retried twice in one request.

`Idempotency-Key` is rejected unless `idempotency_ttl_seconds` is set, and is off by default because entries hold request and response content. See [security](SECURITY.md).

With it enabled, a key gives you this and no more:

| Situation | Response |
|---|---|
| Same key, same body, original finished | The original response, with `X-Switchboard-Replayed: true`. No provider call. |
| Same key, still running | `409` |
| Same key, original outcome unknown | `409`, naming the ambiguity. Deliberately sticky: replaying could charge twice. |
| Same key, **different** body | `422` |
| Key expired or evicted | Treated as new |

**Exactly-once generation is still impossible** across provider APIs, and this does not claim it. Entries live in the gateway's data directory, so they survive a process restart but **not task replacement**, and they expire. A retry landing on a replacement task is a new request and can charge again.

A replayed stream carries the same answer, not the original frame timing: it arrives as one chunk followed by `[DONE]`.

Disable automatic SDK retries (`max_retries=0` in the OpenAI Python client) whether or not you use keys; the gateway never replays upstream on your behalf. Use application operation IDs and an application-owned transactional outbox for external side effects. Tools are entirely unsupported, including tool history, so no tool invocation can be silently translated or executed here; see [unsupported request surface](#unsupported-request-surface).

## Control plane

Every protected call derives tenant and role from a hashed bearer credential. Tenant IDs supplied in policy bodies must match that identity.

| Role | Capabilities |
|---|---|
| `agent` | Read policy; ingest telemetry. A control-plane principal -- unrelated to AI agents, which this gateway does not support; see above. |
| `viewer` | Read policy, recent telemetry and audit |
| `publisher` | Read/publish policy and read telemetry |
| `admin` | Read/publish policy, read telemetry/audit, create and revoke principals |

- `GET/PUT /v1/policy`: returns or publishes the signed envelope; version must strictly increase.
- `POST /v1/telemetry`: bounded metadata-only event; returns `{ "id": "..." }` after transaction commit. Duplicate IDs do not insert twice.
- `GET /v1/telemetry`, `GET /v1/audit`: most recent 100 rows for this tenant.
- `POST /v1/principals`: SHA-256 digest of a caller-generated random credential, role and Unix expiry (at most 90 days); returns principal UUID. Raw credentials are never returned by this API.
- `DELETE /v1/principals/{uuid}`: revoke within current tenant.

Credential creation is caller-controlled: use at least 256 bits of random entropy, store it in a secrets system, and send only its SHA-256 digest to the principal endpoint. A digest is not a bearer credential. Authentication has no long-lived cache; revocation takes effect on subsequent calls. Already-admitted calls can finish.
