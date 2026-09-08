# Running Switchboard locally

A local stack that serves a real request end to end, with no AWS account, no
provider credentials and no per-token cost.

```sh
make dev-up      # bring the stack up and provision it
make dev-smoke   # send a real completion through it
make dev-down    # tear down containers and volumes
```

`make dev-up` is idempotent. Rerunning it reuses the keys and tokens already in
`.dev/env`.

## What it starts

| Service | Role |
|---|---|
| `postgres` | Stands in for RDS. The only service outside the shared namespace. |
| `taskns` | Owns the shared network namespace. Stands in for the ECS task. |
| `controlplane` | FastAPI control plane, signs and serves routing policy. |
| `mockprovider` | Local stand-in for OpenAI, Anthropic and Gemini. |
| `gateway` | The sidecar under test, on `127.0.0.1:8080`. |

**Why a shared network namespace.** The gateway refuses any listen address that
is not loopback, and refuses plain `http` to anything but `localhost`, so the
containers cannot address each other by compose service name. They share one
namespace and talk over `127.0.0.1` — which is also how this runs on ECS, where
every container in a task shares the task's namespace. The compose file models
production rather than working around it.

Two consequences worth knowing:

- The gateway is deliberately **not reachable from your host**. Anything that
  talks to it must run inside the namespace. `scripts/dev-smoke.sh` does this
  with `docker run --network container:switchboard-taskns-1`.
- `docker compose run` cannot attach to a service that uses
  `network_mode: service:`, so the provisioning and smoke jobs use `docker run`
  directly. This is a compose limitation, not a configuration mistake.

The control plane is published on the host at `http://localhost:18000` for
poking at directly.

## What `dev-up` does

The manual first-run sequence is long, and most of it is not automated anywhere
else in the repo. `scripts/devstack.py` collapses it into three steps:

1. **`keys`** — generates the Ed25519 signing keypair and every bearer token,
   writing them to `.dev/env`. The control plane gets the 32-byte seed as
   `POLICY_SIGNING_SEED`; the gateway gets the matching public key in
   `trusted_keys`. Nothing distributes these for you in production.
2. **`dbinit`** — applies migrations via `controlplane.migrate`, then creates
   `switchboard_rt`, a login role granted the `switchboard_app` role. Migrations
   run as the database owner; the runtime login is deliberately weaker, so row
   level security is actually exercised rather than bypassed.
3. **`init`** — provisions the tenant through `scripts/bootstrap.py`, registers
   an `agent` principal (the API stores only a SHA-256 of the token), publishes
   and signs policy version 1, and writes the gateway's `config.json`.

The gateway then polls the control plane every 15 seconds. `/readyz` stays 503
until the first signed policy verifies, so `dev-smoke` waits rather than races.

## Driving failure

`scripts/mockprovider.py` reads these environment variables, which make retry,
circuit-breaker and failover paths reproducible without touching a real provider:

| Variable | Effect |
|---|---|
| `MOCK_STATUS` | Return this status instead of a completion, e.g. `429`, `503` |
| `MOCK_FAIL_FIRST` | Fail this many requests, then succeed |
| `MOCK_DELAY_MS` | Sleep before responding, to drive timeouts and deadlines |
| `MOCK_TEXT` | Completion text to return |

Forcing `MOCK_STATUS=503` makes the gateway exhaust its retry budget and return
a visible `503 routes unavailable or retry budget exhausted`, which is the
behavior `docs/ARCHITECTURE.md` describes.

## Using real providers instead

Point a provider at its real base URL in the generated `config.json`, supply the
matching key, and publish a policy naming a real model. Note that
`Config.Validate()` requires every configured provider's key environment
variable to be non-empty even when the policy never routes to it.

## Secrets

`.dev/env` holds a private signing seed and live bearer tokens in plaintext. It
is gitignored and must stay local. `devstack.py` prints tokens to stdout by
design, which is exactly what a deployment must never do — this tooling is for
local use only.

## Verifying against real providers

The local stack runs against a mock, which is what makes it free and
deterministic. A mock cannot tell you whether the adapters match reality: it
only returns the fields they were written to expect.

That is not hypothetical. The first real call to Bedrock immediately found a
defect that would have failed every genuine request — the response carried a
field the wire struct did not model, and decoding was strict. The mock returned
only modelled fields, so it passed.

`internal/gateway/live_test.go` calls the real APIs. It is skipped unless
enabled, because it costs money and needs credentials:

```sh
SWITCHBOARD_LIVE_OPENAI=1    OPENAI_API_KEY=...    go test -run Live ./internal/gateway/
SWITCHBOARD_LIVE_ANTHROPIC=1 ANTHROPIC_API_KEY=... go test -run Live ./internal/gateway/
SWITCHBOARD_LIVE_GEMINI=1    GEMINI_API_KEY=...    go test -run Live ./internal/gateway/
SWITCHBOARD_BEDROCK_LIVE=1                          go test -run Bedrock ./internal/gateway/
```

Bedrock needs no key — it authenticates with the ambient AWS credentials.

Each request goes through `upstream()` and each response through `normalize()`,
which is the path a production request takes, so request construction,
authentication, response parsing, finish-reason mapping and token accounting are
exercised together. Three cases are covered per provider: a complete response, a
streamed response, and a deliberately truncated one, since an unmapped finish
reason is a hard failure rather than a degraded result.

Four provider cases run, not three. OpenAI's legacy and reasoning models take
different request shapes — reasoning models reject `max_tokens` outright — and
signal truncation differently, so `gpt-4o-mini` and `gpt-5-nano` are exercised
separately through the same adapter.

**The model names in `liveProviders` are a live dependency, not a constant.**
Two of the three originally targeted models were retired out from under these
tests and began returning 404. When a case fails with "no longer available", list
what the key can actually reach and update the table:

```sh
curl -s https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY" | jq -r '.data[].id'
curl -s 'https://api.anthropic.com/v1/models?limit=100' -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H 'anthropic-version: 2023-06-01' | jq -r '.data[].id'
curl -s 'https://generativelanguage.googleapis.com/v1beta/models?pageSize=200' \
  -H "x-goog-api-key: $GEMINI_API_KEY" | jq -r '.models[].name'
```

A provider that answers 503 or 429 is retried three times with backoff and then
**skipped**, not failed: that records "not verified", which is honest, where a
failure would wrongly accuse the adapter. Gemini hits this most often.

Cost is a few cents. Keys can be revoked afterwards, and should be.

### The startup provider check

Once the first signed policy verifies, the gateway sends one 8-token completion to each provider the
policy routes to, using a model that policy names. A failure withholds that provider from routing for
60 seconds and logs at ERROR. Routing recovers on its own through the breaker's half-open probe once
the account is funded or the key replaced, and the first request that then succeeds through that
provider also clears it from the readiness check, so neither requires a restart.

Setting `"provider_check_strict": true` additionally holds `/readyz` at 503, so the platform's own
health check replaces the task rather than letting it serve requests that will all fail upstream.
Default is `false`, because a gateway whose purpose is to keep serving when one provider is
unavailable should not refuse to start over one.

It sends a real completion rather than hitting an auth-only endpoint deliberately. `GET /v1/models`
returned 200 on an OpenAI key whose account had no credits, minutes before a completion on the same
key returned 429. A check that passes while every real request fails is worse than no check, because
it turns an obvious failure into a confident one.

### When a model returns nothing

Reasoning models spend their token budget on hidden reasoning before writing any answer, and reserve
nothing for the answer itself. If the budget runs out first, the provider returns HTTP 200 with
`finish_reason: length` and empty content, and bills for every token. Measured on `gpt-5-nano`:

```
max_tokens 1024   0 characters      1024 reasoning tokens   billed 1024
max_tokens 2048   1469 characters    832 reasoning tokens   billed 1159
```

The gateway fails over to the next route rather than returning an empty answer, and counts
`switchboard_empty_completion_total`. If every route does the same, the caller gets a 503 saying so
rather than a generic routing failure, because the fix is theirs: raise `max_tokens`.

There is no budget that avoids this generally. The same model answered "reply with ok" using 64
reasoning tokens, so the requirement is prompt-dependent. Watch the ratio of reasoning tokens to the
caller's budget: it approaches 1.0 before the output goes empty.

### Which key is actually in use

The gateway reads each provider's key from the environment variable named by `key_env`, and
`Config.Validate()` only checks that the variable is **non-empty**. Nothing distinguishes a present
key from a correct one, so a stale export in `~/.zshrc` or `~/.zshenv` silently outranks whatever you
meant to use, and the failure arrives later as a provider `401`, or a `429` mentioning credits. Both
read as a provider fault when they are a configuration one.

This is not hypothetical: two different OpenAI keys for the same account were in play during the live
verification above, one of which reported having no credits.

Compare what the shell has against what you think you are using, without printing either:

```sh
printf %s "$OPENAI_API_KEY" | shasum -a 256 | cut -c1-12
printf %s "$(cat ~/.switchboard/openai)" | shasum -a 256 | cut -c1-12
```

Matching digests mean they agree. Note that a non-interactive shell does not source `~/.zshrc`, so an
automated run and your terminal can legitimately disagree about the same variable.

For OpenAI specifically, the response headers name the account the key belongs to, which settles
"is this the account holding the credits" without guessing:

```sh
curl -s -D - -o /dev/null https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY" | grep -i '^openai-organization'
```

A `user-` prefix is a personal account with no organization attached, so organization mismatch
errors do not apply to it. The gateway never sends an `OpenAI-Organization` header; `sk-proj-` keys
carry their own organization and project.
