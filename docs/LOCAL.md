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
