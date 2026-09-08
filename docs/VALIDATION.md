# Validation performed

What has actually been run, with the results. `docs/GAPS.md` records what has
not. Local builds are validation artifacts, not approved deployment binaries.

## 2026-09-07 — original build session

Host toolchain: Go 1.24.1 on macOS ARM64; bundled Python 3.12. This session had
no network, no Docker, no Terraform and no access to GitHub, so much of it could
only be compile-checked. Superseded in most respects by the runs below; retained
because it is the record of what was and was not established at the time.

- `go vet ./...` clean.
- `SWITCHBOARD_IN_MEMORY_TESTS=1 go test -race ./...`: 24 top-level Go tests plus
  subtests passed, 75.4% statement coverage in the gateway package, 0% in the
  command-line main package. The in-memory flag substitutes an in-process
  transport, so no real socket, TLS or timeout behavior was exercised.
- Cross-compilation to Linux AMD64 and ARM64 with CGO disabled.
- Three Python policy tests, including Ed25519 verification of the fixture shared
  with Go.
- Not run: real sockets, Postgres integration, container builds, dependency
  audit, Terraform validation, live providers, deployment, load, soak, or
  graceful shutdown. No remote repository or CI run existed.

## 2026-09-07 — local stack and CI

Python moved to 3.14; CI runs Go 1.26 and Python 3.14.

- All four CI jobs pass remotely: `go`, `control` (against a real `postgres:17`),
  `containers`, `terraform`.
- The local development stack (`make dev-up`) brings up Postgres, the control
  plane, a mock provider and the gateway, provisions keys, tenant, principals and
  a signed policy, and serves.
- `make dev-smoke`: `/readyz` 200; nonstreaming completion 200 with content;
  streaming completion 200 with 4 SSE frames.
- Telemetry: 2 events delivered through the disk spool to Postgres and
  acknowledged.
- Forcing the provider to 503 returns the documented
  `routes unavailable or retry budget exhausted` rather than hanging.
- Docker image builds on `python:3.14-slim-bookworm`; the built image reports
  Python 3.14.7 and imports the control plane.

## 2026-09-07 — AWS validation, images, load and soak

No billable AWS infrastructure was created. No stack was deployed.

### CloudFormation

- `cfn-lint` clean on `quickstart.yaml` and `controlplane.yaml`.
- `aws cloudformation validate-template` accepts both. Server-side validation
  reported one thing the linter did not: `quickstart.yaml` requires
  `CAPABILITY_IAM`, which a deploying buyer must acknowledge.
- `quickstart.yaml` has exactly two parameters without defaults:
  `CertificateArn` and `ControlPlaneImage`.

### Images

Built `linux/amd64` and pushed to a development ECR registry with immutable tags
and scan-on-push. Digests are recorded in `docs/DEPLOYMENT.md`.

- Gateway: **no scan findings**. It is distroless and carries almost no operating
  system.
- Control plane: **19 findings, 4 critical and 15 high**, all in Debian packages,
  none in the application or its Python dependencies, and all marked **no fix
  available**. Rebuilding on Debian trixie produced 17 findings including 6
  critical, also all unfixed, so the base was reverted. Subsequently resolved by
  rebasing onto distroless; see below.

`Dockerfile.gateway` was changed to cross-compile from `$BUILDPLATFORM`: running
the Go toolchain under QEMU emulation crashes it outright.

### Supply chain

- `govulncheck` under Go 1.26.8: **no vulnerabilities found**, including the AWS
  SDK dependencies added for Marketplace metering. Under the older Go 1.24.1
  still installed locally it reports 29 standard-library findings; that is a
  stale toolchain, not a property of the code, and neither CI nor the Dockerfile
  uses it.
- Python: the full dependency graph is pinned. A clean install in a fresh
  container resolves to exactly the 27 pinned versions, with nothing floating.
- `cfn-lint` runs as its own CI job, requiring no AWS credentials.

### Marketplace metering

`RegisterUsage` is implemented behind an interface and unit-tested across
entitled success, `CustomerNotEntitledException`, absent configuration, client
failure, per-call nonce uniqueness, and configuration validation. With no
marketplace block configured it makes no AWS call at all, which is what keeps the
development stack unaffected.

**The real call has never been made.** It requires a `ProductCode` that only
exists once a Marketplace listing does.

### Load and soak

Driven by `cmd/loadgen` against the local stack. It reads server-sent event
streams to completion, which general-purpose HTTP benchmarking tools do not, so
streaming latencies are measured over the whole generation rather than to the
first header.

| Scenario | Invocation | Result |
|---|---|---|
| Sustained | `-concurrency 8 -rps 40 -duration 60s -stream-pct 50` | 2,399 requests, 2,398 succeeded, 1 transport error. p50 1 ms, p95 43 ms, p99 45 ms. 4,796 SSE frames. |
| Backpressure | `-concurrency 64 -rps 0 -duration 30s -stream-pct 50` | 874,504 offered at 29,149/s against a 50/s limit. 1,555 admitted, 872,888 rejected 429. p99 held at 10 ms. |
| Failure injection | `-concurrency 16 -rps 40 -duration 60s -stream-pct 30`, provider failing its first 5 requests | 1,803 rejected 503 then 595 succeeded. Rejections took about 1 ms, without contacting the provider. Recovery was unaided. |
| Graceful shutdown | `-concurrency 12 -rps 4 -duration 45s -stream-pct 40`, provider delayed 3,000 ms, SIGTERM at 12s | Process exited after 4s with status 0. Every completed request shows a full ~3.01 s generation, so in-flight work finished. Subsequent transport errors are the generator continuing to fire at a stopped server. |

Two observations worth carrying forward:

- Backpressure is genuinely bounded. Offering load 580 times over the configured
  rate did not degrade latency; the gateway rejected immediately rather than
  queueing.
- Circuit-breaker recovery took roughly 45 seconds, where the architecture
  documented a 15-second open period. This was investigated rather than assumed
  and is fully explained below; the code was correct and the document was not.

An earlier attempt at the failure-injection scenario was invalid and is recorded
here rather than discarded: with the provider set to fail its first 300 requests,
the breaker opened and stopped contacting the provider, so its failure counter
never advanced and recovery was unreachable within the run. The test was
redesigned, not the system.

## 2026-09-07 — resolving the two open findings

### Control-plane image, rebased onto distroless

The 19 findings were all in Debian packages with no upstream fix, so they could
not be resolved by rebuilding or by changing Debian release. Three inspections
established that they could be removed instead: perl was installed and never
used by the application; the interpreter resolves only against glibc; and
`psycopg` and `cryptography` vendor their own OpenSSL and krb5 inside their
wheels rather than linking the operating system's.

The image now builds the environment on `python:3.14-slim` and copies the
interpreter, site-packages and the required architecture libraries into
`gcr.io/distroless/base-debian12`.

| | Findings | Size |
|---|---|---|
| `0.1.0`, python:3.14-slim-bookworm | 4 critical, 15 high, 6 medium | 62.9 MB |
| `0.2.0`, distroless | **none** | 55.7 MB |

The image has no shell, which required three changes: `scripts/devstack.py`
composes the database connection string in Python rather than relying on a `sh`
wrapper, the entry scripts carry an absolute-path shebang and the executable bit
so they work both as arguments to the interpreter and when exec'd directly, and
the CloudFormation bootstrap task passes `DBHOST` and `PGPASSWORD` instead of a
pre-composed URL. The full local stack was rebuilt and re-smoked afterwards and
passes unchanged.

Worth stating plainly: ECR scans operating-system packages. The vendored OpenSSL
inside the Python wheels is not covered by these findings either before or after.
Zero findings means a much smaller operating-system surface, not a guarantee.

### Circuit-breaker recovery, explained

The earlier 45-second recovery is the breaker behaving as written, not a defect.
It trips at three transient failures and closes to traffic for 15 seconds, then
admits exactly one half-open probe. A successful probe closes it immediately. A
**failed probe re-arms a fresh full 15 seconds**, with no backoff or decay.

The provider under test failed its first five requests: three to trip the
breaker, then two more consumed by failed probes, so three cycles elapsed —
3 x 15s = 45s.

Confirmed by prediction rather than by argument. Repeating the run with the
provider failing exactly three times, so no probe would fail:

| Injected failures | Predicted recovery | 503s observed | 200s observed |
|---|---|---|---|
| 5 | 3 cycles, ~45s | 1,803 | 595 |
| 3 | 1 cycle, ~15s | 603 | 1,795 |

At 40 requests/second those counts correspond to 45 and 15 seconds. The retry
budget played no part: it is consulted only on a second or later provider
attempt, and this route table has one provider. `docs/ARCHITECTURE.md` has been
corrected, since "opens for 15 seconds" described one cycle rather than a bound.

### Go toolchain

Upgraded locally from 1.24.1 to 1.27.1, and `go.mod`, CI and the gateway
Dockerfile aligned on 1.27. The `go` directive was raised deliberately: Go
switches toolchains automatically when a module requires a newer one, so this
makes it impossible to build the binary with a standard library carrying known
vulnerabilities. `govulncheck` under the local toolchain now reports no
vulnerabilities, where 1.24.1 reported 29.

## 2026-09-07 — first real deployment, and the routing change it preceded

### Deployment

The quickstart was deployed into a real account twice. The first attempt **failed**, at the resource
most likely to: `BootstrapRun`, the custom resource that applies migrations through a one-off ECS
task.

```
ResourceInitializationError: unable to pull secrets or registry auth:
failed to fetch secret arn:aws:secretsmanager:...:secret:rds!db-983da65c-...
```

The execution role enumerated the three secrets the template creates but not the master password
secret, which RDS creates and owns, and which the bootstrap task uses to connect as the migration
owner. Neither `cfn-lint` nor `validate-template` can catch this: the secret does not exist until
RDS makes it.

The second attempt reached `CREATE_COMPLETE` with every resource healthy. Verified:

- `dbinit: migrations applied; switchboard_rt granted switchboard_app` — migrations ran and the
  runtime login was created as a principal distinct from the migration owner, so row level security
  is exercised rather than bypassed
- ECS service `ACTIVE`, 2/2 running, rollout `COMPLETED`, both load balancer targets healthy
- `TLS_OK status=200 body={"ready":true}` from a task inside the VPC — real certificate, real
  internal load balancer. This is the one thing local testing structurally cannot prove.
- The signing seed is valid 32 bytes, proven by the control plane booting at all, since
  `controlplane/app.py` refuses to start otherwise. The secret was never read.

Three further defects came out of the same exercise. Postgres 17.4 did not exist in the region and
was caught by preflight before any spend. The KMS alias was deleted while its key was retained, so
the teardown script could not find the key it existed to remove. And teardown run against a
half-deleted stack did partial work and stopped on a raw AWS error, leaving the key unscheduled; it
now refuses to run until the stack is gone, and will not schedule the key while any snapshot
survives, since the key is what makes that snapshot readable.

Teardown was then verified end to end: snapshot deleted, secrets and log group removed, KMS key
scheduled, and no stacks, instances, snapshots, NAT gateways, load balancers, elastic IPs or secrets
left in the account.

### Rate limits are no longer treated as unhealthiness

A 429 and a 503 both fed the circuit breaker, so three rate limits opened the circuit for fifteen
seconds against a provider that was working. Measured with the same injection count and load,
before and after:

| Injected | Behaviour before | Behaviour after |
|---|---|---|
| 429 x5 then healthy | ~1,803 failures over ~45s, three breaker cycles | **5 failures**, 1,193/1,199 succeeded, 0.50% error rate |
| 503 x5 then healthy | 1,803 failures, 595 successes | **1,796 failures, 594 successes** — deliberately unchanged |

The 503 row is the control: the breaker still engages for genuine unhealthiness. Only the meaning of
a 429 changed.

`switchboard_rate_limited_total` recorded exactly 5. Note it is orthogonal to `errors_total` rather
than exclusive of it: with a single configured provider there was nowhere to fail over to, so those
requests counted as both a rate limit and a failed request.

## 2026-09-07 — Postgres 18.6 and the name-length defect

`deploy-test.sh` was written to make the deployment check repeatable. On its first real run it
found a defect no linter could:

```
The load balancer name 'switchboard-deploytest-164823-control'
cannot be longer than '32' characters
```

`LoadBalancer` and `TargetGroup` both set `Name` to the stack name plus `-control`, and ELBv2 caps
names at 32 characters. The first successful deployment only worked because `switchboard-eval` is
16 characters and fit with nothing to spare — **any stack name over 24 characters would have failed
a buyer**, after the VPC, NAT gateway and database had already been built. Both names are now
generated by CloudFormation.

The re-run used a deliberately long name, `switchboard-marketplace-verify` at 30 characters, which
is the case that previously failed:

| Check | Result |
|---|---|
| Preflight, all ten checks | pass |
| Deploy on Postgres 18.6 with a 30-character stack name | pass |
| Parameter group family derived as `postgres18` | pass |
| Migrations applied, `switchboard_rt` created as a separate login | pass |
| ECS service, 2 tasks running | pass |
| Load balancer targets healthy | pass |
| TLS probe | **failed — see below** |

The TLS failure was in the test script, not the product. The probe embedded double-quoted Python
inside a JSON `--overrides` argument, producing invalid JSON, so the task was never accepted. TLS
through the internal load balancer on the real certificate **was** verified by hand on the earlier
deployment (`TLS_OK status=200 body={"ready":true}`); it is the automated check that had not worked,
and it is now fixed but not yet re-exercised.

So Postgres 18.6, the derived parameter-group expression and the name-length fix are all proven. The
automated TLS check is not.

### Not run here

Full quickstart deployment, live provider requests, real Marketplace
registration, soak beyond 60 seconds, SBOM generation and image signing. See
`docs/GAPS.md` for the distinction between what remains open and what is blocked
on an external action.

## 2026-09-07 — live verification of the OpenAI, Anthropic and Gemini adapters

Until this run, these three adapters had never been called for real. Every response-shape assumption
in them had been checked only against mocks written from the same assumptions. That is the blind spot
that let a 100%-fatal Bedrock defect through earlier the same day, so it was worth closing.

Four provider cases were exercised, not three: OpenAI's legacy chat models and its reasoning models
take different request shapes and signal truncation differently, so `gpt-4o-mini` and `gpt-5-nano`
are tested separately through the same adapter.

### Results

| Case | Complete response | Streaming | Truncation |
|---|---|---|---|
| openai (`gpt-4o-mini`) | pass | pass, 8 frames | pass, `finish=length` |
| openai-reasoning (`gpt-5-nano`) | pass | pass, 2 frames | **HTTP 400, not a finish reason** |
| anthropic (`claude-haiku-4-5-20251001`) | pass | pass, 8 frames | pass, `finish=length` |
| gemini (`gemini-3.6-flash`) | pass (after retry) | pass, 2 frames | pass, `finish=length` |

All twelve cases pass. Measured usage: openai in 14 / out 1; openai-reasoning in 13 / out 74;
anthropic in 14 / out 4; **gemini in 8 / out 104**.

That last figure is the point of the exercise. Before the fix below, the identical call reported
`out=0`.

### Defect found and fixed: Gemini output tokens were metered as zero

`wire.UsageMetadata` read output tokens from `candidatesTokenCount` alone. Real Gemini responses bill
internal reasoning separately in `thoughtsTokenCount`, and **may omit `candidatesTokenCount`
entirely**. Two real responses:

```
{"promptTokenCount":8,                          "thoughtsTokenCount":103,"totalTokenCount":111}
{"promptTokenCount":6,"candidatesTokenCount":6, "thoughtsTokenCount":206,"totalTokenCount":218}
```

The first normalized to `out=0` against 103 tokens billed. The second normalized to `out=6` against
212 — a 97% under-report. This is an accuracy defect rather than a revenue one: `RegisterUsage`
meters per ECS task per hour and never sees a token count, and nothing bills off
`switchboard_usage_mismatch_total`. It would become a revenue defect under a usage-based metering
dimension, which the current startup-only registration cannot support.

Fixed by modelling `thoughtsTokenCount` and `totalTokenCount` and billing on
`candidatesTokenCount + thoughtsTokenCount`. Because a provider can change its accounting again, the
gateway now also cross-checks that sum against `totalTokenCount - promptTokenCount` and increments
`switchboard_usage_mismatch_total` when they disagree, rather than trusting the sum silently. A
mismatch does not fail the request. Both real bodies above are pinned as regression tests in
`adapter_test.go`.

### Defect found and fixed: OpenAI reasoning models were unusable

`upstream()` passed the whole `Chat` struct through as the OpenAI request body, which serialises the
token limit as `max_tokens`. Reasoning models reject that outright:

```
400 Unsupported parameter: 'max_tokens' is not supported with this model.
    Use 'max_completion_tokens' instead.
```

Verified against the live API that `gpt-4o-mini` accepts **either** name, so the fix is one
unconditional rename to `max_completion_tokens` with no per-model branching and no dialect
configuration. The OpenAI body is now built explicitly, like the other three adapters.

### Test-harness defects found and fixed

- `TestLiveTruncatedFinishReason` called `t.Skipf` on a non-200, so a run in which **every** request
  failed authentication reported the parent test as PASS. It now fails.
- Live model names had gone stale under the tests: `gemini-2.0-flash` and `claude-3-5-haiku-latest`
  both returned 404 "no longer available". Refreshed, and the table now carries a comment that model
  names are a live dependency rather than a constant.
- The tests requested 16 output tokens. A reasoning model spends its whole allowance thinking before
  emitting any visible text, so it returned `"content": {}` with no `parts` key and
  `finishReason: MAX_TOKENS`. The adapter handled that correctly; the assertion was wrong. Budgets
  raised to 512.

### Behaviour recorded, not changed

- **OpenAI reasoning models report truncation as HTTP 400**, where legacy models report it in band as
  `finish_reason: length`. The gateway maps 400 to "provider rejected request" and does not fail
  over, so a caller with too small a budget gets an opaque error. Recorded in `docs/GAPS.md`.
- **Anthropic signals billing exhaustion as HTTP 400** ("credit balance is too low"), not 402 or 429.
  Same path, same consequence: no failover to a funded provider.
- **A real OpenAI 429 carried no `Retry-After` and no `x-ratelimit-*` headers at all.** `retryAfter()`
  returns 0, so the breaker takes the `release()` branch and the gateway re-attempts an exhausted
  provider on every subsequent request. Correct for a transient limit, wasteful for one that will not
  clear on its own.
- **Anthropic returns `cache_creation_input_tokens` and `cache_read_input_tokens`**, neither modelled.
  Both were zero here, so input accounting is currently correct, but it would under-count if prompt
  caching were ever enabled.
- **Gemini streams have no `[DONE]` terminator** — the stream simply ends after the frame carrying
  `finishReason`. The adapter already treats a finish reason as completion, so this works.
- **Gemini throttles, and part of that was self-inflicted.** `gemini-3.6-flash` returned 503 "high
  demand" repeatedly, which is Google's own capacity signal. It also returned 429 "exceeded your
  current quota" — that one was a short per-minute limit tripped by running the suite repeatedly in
  quick succession, not an account problem, and it was initially and wrongly reported as needing
  billing enabled. The account had prepay credit throughout. A later run with no burst behind it
  passed all four Gemini cases with no retries at all, in 16 seconds against the 47 to 104 seconds
  the retrying runs took.

  The live tests retry 503 and 429 three times with backoff and skip rather than fail when all three
  are refused. A skip records "not verified", which is honest, where a failure would wrongly accuse
  the adapter. The corollary is worth stating: a green suite does not by itself prove Gemini was
  reached, so read the per-case output rather than the summary line.

### Confirmed sound

Decoding is lenient for all three adapters, with strictness correctly confined to client input via
`strictJSON`. The specific Bedrock defect — a provider adding an unmodelled response field — cannot
recur here. Anthropic's streaming path rejects unknown event types outright; all seven types a real
stream emitted (`message_start`, `content_block_start`, `content_block_delta`, `content_block_stop`,
`message_delta`, `message_stop`, `ping`) are in its allowed set, with `content_block.type: text` and
`delta.type: text_delta` as expected.

## 2026-09-07 — account-level failover, and empty completions

Live verification of the adapters left three provider refusals recorded but unhandled. Investigating
them found a fourth that was worse, because it looked like success.

### The measured refusals

| Provider | Condition | Response | Old behaviour |
|---|---|---|---|
| OpenAI | No credits | `429`, no `Retry-After`, no `x-ratelimit-*` | Circuit released, retried every request forever |
| Anthropic | Balance too low | **`400`**, not 402 or 429 | `fail(400)`, provider recorded healthy, no failover |
| Gemini | Quota exhausted | `429` "exceeded your current quota" | Same as OpenAI |
| OpenAI reasoning | Budget too small | `400` about `max_tokens` | `fail(400, "provider rejected request")` |

The Anthropic case is the one that mattered. A 400 was read as "this request is malformed", so a
caller got an opaque error while a funded provider sat unused in the same signed policy.

### Empty completions: measured, and worse

Investigating the fourth row showed the `400` only occurs at `max_tokens: 1`. From 4 upward the same
model returns **HTTP 200, `finish_reason: length`, and zero visible characters**, having spent the
whole budget on hidden reasoning. Measured on `gpt-5-nano`, prompt "Write a long paragraph about the
sea":

```
budget 1024   finish=length   0 chars      1024 reasoning   billed 1024
budget 2048   finish=stop     1469 chars    832 reasoning   billed 1159
budget 4096   finish=stop     2060 chars    640 reasoning   billed 1082
```

1024 is `ParseChat`'s own default. The gateway reported these as **200 successes** and metered the
full budget, so a caller could pay for 1024 tokens and receive nothing. It is prompt-dependent —
"reply with ok" needed 64 reasoning tokens against the same model — so no fixed budget avoids it.

### What changed

Refusals are now classified from the body, because the status code cannot separate an account that
cannot pay from a request that is malformed (`internal/gateway/fault.go`). An account fault withholds
that provider for 60 seconds and tries the next route; a terminal fault keeps the previous behaviour
and now carries the provider's own reason. **Classification fails safe**: an unrecognised 400 stays
terminal. A missed billing phrase costs a failover that could have happened; a wrongly matched one
would replay a bad request across every configured provider, which is worse.

Empty completions fail over and are counted. On the streaming path the frame carrying a truncation
finish reason is held back until text arrives, so a stream that produces nothing has sent no bytes
and can still fail over without breaking the no-replay-after-acceptance rule.

Providers are checked once at startup, after the first signed policy verifies, with a real 8-token
completion to each provider the policy routes to. An auth-only check was rejected on evidence:
`GET /v1/models` returned 200 on the no-credits OpenAI key minutes before a completion on that same
key returned 429. A check that passes while every real request fails is worse than no check.

New counters: `switchboard_account_failover_total`, `switchboard_empty_completion_total`,
`switchboard_provider_probe_failed_total`. Reasoning tokens are now carried through `normalize()`,
which is the leading indicator: reasoning approaching the caller's budget predicts the empty
completion before it happens.

### Tests

Classification is driven by verbatim captured bodies rather than invented ones, since the whole
mechanism is string matching against real wording. Coverage includes the direction that matters most:
an unrecognised 400 must **not** fail over, and an account fault must not increment the breaker's
failure count, because the provider is healthy and only the account is not.

Not changed: `ParseChat`'s 1024 default. Raising it would cost every caller money to protect against
one model family, and the operator can now see the problem instead. Recorded in `docs/GAPS.md`.

## 2026-09-07 — how often the default token budget produces nothing

The empty-completion handling was added on a single observation. This is the measurement that should
have preceded it, and it changed the conclusion.

Seven ordinary prompts against `gpt-5-nano` at `ParseChat`'s default of 1024:

| Prompt | @1024 | @2048 | @4096 | `gpt-4o-mini` @1024 |
|---|---|---|---|---|
| Reply with the single word: ok | 2 ch | | | |
| What is 2+2? | 22 ch | | | |
| Summarize the water cycle in two sentences | 277 ch | | | |
| List three uses for a paperclip | **empty** | 223 ch | 210 ch | 443 ch, 105 billed |
| Explain how TCP congestion control works | **empty** | **empty** | 4980 ch | |
| Write a long paragraph about the sea | **empty** | | | |
| Write a 500-word essay on urban planning | **empty** | **empty** | **empty** | 4158 ch, 666 billed |

**Four of seven fail at the default**, including a trivially simple prompt.

**Raising the default is ruled out.** 4096 still returned nothing for the essay prompt, so no static
number is sufficient. And 1024 is demonstrably correct for non-reasoning models: `gpt-4o-mini`
answered that same essay prompt in 666 billed tokens with a full 4158-character response, so raising
the default would charge those callers more for a problem they do not have.

Reasoning demand is not a stable property to size against either: the same prompt consumed 1920
reasoning tokens at a budget of 2048 and 1152 at 4096. It expands to fill what it is given.

The conclusion is that this is a routing problem, not a configuration one. Pending that, the 503 now
names each route that produced nothing and the reasoning tokens it consumed:

```
no provider produced output within max_tokens=1024:
openai/gpt-5-nano spent all 1024 tokens on internal reasoning and returned none;
retry with a higher max_tokens
```

It deliberately does **not** suggest a budget that would work. The table above shows that figure is
not knowable in advance, and a suggestion that then also fails is worse than none. Where a provider
reports no reasoning count, the message says only that output was absent rather than printing zero.

## 2026-09-08 — a clean live run, all four providers

Every earlier live run had at least one Gemini case skipped on 503 or 429, which was recorded as
provider capacity. Re-running with no preceding burst of requests passed all twelve cases with no
retries, in 16 seconds:

| Case | Complete | Streaming | Truncation |
|---|---|---|---|
| openai (`gpt-4o-mini`) | `in=14 out=1` | 8 frames | `finish=length` |
| openai-reasoning (`gpt-5-nano`) | `in=13 out=74` | 2 frames | HTTP 400 |
| anthropic (`claude-haiku-4-5`) | `in=14 out=4` | 8 frames | `finish=length` |
| gemini (`gemini-3.6-flash`) | `in=8 out=79` | 2 frames | `finish=length` |

The Gemini figure is the metering fix confirmed once more against the live API: 79 output tokens
where the pre-fix code would have reported 1, the difference being reasoning billed as output.

Two corrections to the earlier record. Gemini's 429 was a per-minute limit tripped by running the
suite repeatedly, not an account problem; it was wrongly reported as needing billing enabled when the
account had prepay credit throughout. Google's 503 "high demand" was real. The distinction matters
because "the provider is unreliable" and "the test harness is hammering it" call for different
responses, and only the second was true here.

## 2026-09-08 — Bedrock streaming against the real service

Bedrock was the one provider that could not stream, so a streaming request skipped the route
entirely. It now streams, and the translation was checked against the live service rather than only
against fixtures.

```
17 frames, finish=stop, in=5 out=47
text="It looks like you're counting up to three. Here's the continuation from where you left off: ..."
```

`out=47` is the figure that mattered. Bedrock ends a stream with `messageStop` carrying the stop
reason and then `metadata` carrying token usage, and the gateway terminates a stream on the first
frame reporting completion. Emitting `messageStop` as it arrived would have ended the stream before
usage was ever read and reported every streamed Bedrock request as costing nothing, which is the same
defect as the Gemini metering bug found the previous day. The translator holds the stop reason back
and emits it with usage as a single terminal frame.

The unit tests encode fixtures with the real `eventstream` encoder, which exercises the framing but
can only assert what was assumed about event type names and ordering. This live run is what
contradicts or confirms those assumptions, and it confirms them: `contentBlockDelta`, `messageStop`
and `metadata` all arrive as expected, with `metadata` after `messageStop`, and the response carries
`Content-Type` containing `eventstream`, which is what `stream()` keys on to select the translator.

Still unexercised: tool and reasoning blocks are refused rather than flattened on the streaming path,
tested only with synthetic frames, because Nova Micro does not emit them for these prompts.

## 2026-09-08 — 30 minute soak, and the memory growth it found

The longest previous run was 60 seconds. This is the first run long enough to say anything about
behaviour over time, and it found something.

Local stack, mock provider, 30 minutes at 20 requests per second, 8 workers, 40% streaming:

```
requests        35,988  (20.0/s)
succeeded       35,987
failed          1       (0.00%, a single transport error)
sse frames      57,596
latency         p50 2ms   p95 8ms   p99 43ms
```

Throughput, latency and backpressure are all clean. The disk spool stayed between 6 and 19 events for
the entire run and never grew, so telemetry delivery kept pace with production.

### Resident memory grows linearly and does not plateau

```
   2s   7.4 MiB
 326s  11.2 MiB
 649s  14.9 MiB
 972s  18.2 MiB
1294s  21.5 MiB
1617s  25.0 MiB
1779s  26.9 MiB
```

Roughly 0.65 MiB per minute, near perfectly linear, about 3.7 times the starting figure in half an
hour. The increments between samples are 3.84, 3.71, 3.27, 3.29 and 3.54 MiB, which is growth
proportional to requests served rather than a heap settling into a working set. A working set
plateaus; this does not.

Extrapolating is not evidence, but it frames the risk: at this rate a task passes 300 MiB inside
eight hours and approaches a gigabyte in a day. A sidecar with a modest ECS memory limit would be
replaced by the platform on a schedule set by its own leak.

**It is not released when load stops.** With the generator stopped, zero active requests, an empty
spool and idle CPU, resident memory held at 26.89 MiB across three samples a minute apart.

### Not diagnosed

No cause is claimed. The gateway exposes no pprof endpoint, so heap and goroutine profiles cannot be
taken from outside the process, and the only per-request goroutine in the code path is `bedrockSSE`,
which this run never exercised because the mock provider speaks the OpenAI shape. Guessing at a cause
from a memory curve would be the same mistake as diagnosing a provider from one error string.

The next step is a pprof endpoint on the existing loopback listener, which is where `/metrics`
already sits unauthenticated for the same reason, and a repeat of this run with heap profiles taken
at intervals. Until then this is a measured fact without an explanation, which is still worth more
than the 60 second runs that could not see it at all.

## 2026-09-08 — the memory growth, diagnosed and the earlier reading retracted

The previous entry recorded resident memory rising from 7.4 MiB to 26.9 MiB over a 30 minute soak,
called it the most important open item, and projected passing 300 MiB in eight hours. **That
conclusion was wrong.** It was drawn from `docker stats` alone, without decomposing what that number
contains, and the strength of the language was not supported by the evidence behind it.

pprof was added to measure it. What the instruments say:

| Measurement | Result |
|---|---|
| Go `Sys`, every byte the runtime holds from the OS | +0.25 MB over 3 minutes |
| `HeapAlloc`, live objects | flat, slightly declining |
| `Mallocs` minus `Frees` | 22,337, exactly equal to `HeapObjects` |
| Goroutines | 13 idle, 34 at one minute, 24 at six minutes |
| Heap profile diff, 1 min to 6 min | **negative**, minus 1,040 kB |

No object retention, no goroutine growth, and the Go process accounts for roughly 2.4 MB across 30
minutes rather than 19.5 MB. So the memory was never Go's.

The container's own cgroup accounting locates it:

```
             anon        slab_reclaimable   slab_unreclaimable   RSS
01:11:06    8.79 MB          4.60 MB               0           13.18 MiB
01:11:58    8.65 MB          5.13 MB               0           13.49 MiB
01:13:08    8.65 MB          5.79 MB               0           14.30 MiB
```

`anon`, the process itself, is flat. Resident growth tracks `slab_reclaimable`, and nothing is
unreclaimable. A page cache hypothesis was tested and rejected on the way: `file` was zero.

The complete profile set, taken across the whole load period rather than the two points above,
removes any remaining doubt:

```
cgroup delta over the run        Go heap in-use
  anon               +0.13 MB      before load   3391 kB
  slab_reclaimable   +2.01 MB      t = 1 min     2895 kB
  slab_unreclaimable +0.00 MB      t = 6 min     1855 kB
                                   t = 11 min    1855 kB
```

The Go heap fell and then plateaued exactly, identical at six and eleven minutes, while slab kept
climbing. 94% of the growth is reclaimable slab and 6% is the process. The heap diff from one minute
to eleven is minus 1,040 kB, all of it `net/http` initialisation buffers and the async log writer's
startup allocation being released rather than anything accumulating.

### Cause

The telemetry spool writes one file per event into `DataDir/spool` and unlinks it once the control
plane acknowledges the id. At 20 requests per second that is 40 dentry operations per second, and the
kernel caches the resulting dentries and inodes against this container's cgroup. Roughly 0.55 MB per
minute, which is about 16.5 MB across 30 minutes and matches the 19.5 MB originally reported.

### What it means, stated at the strength the evidence supports

Reclaimable slab counts toward a container memory limit, and the kernel frees it under pressure
instead of killing the process. There is no out-of-memory risk of the kind claimed. What is true is
that container memory graphs will show apparently unbounded growth, which will alarm an operator who
has not read this. Batching the spool into segment files rather than one file per event would remove
the churn if that becomes worth doing.

### The lesson, which is the same one as Gemini

`docker stats` was treated as if it measured the process. It measures a cgroup, which includes kernel
memory the process merely caused to be allocated. One number was read confidently without asking what
was inside it, exactly as a single provider error string was read confidently the day before. The
30 minute soak that produced the number was still worth running; the reading of it was not worth
publishing without decomposing it first.
