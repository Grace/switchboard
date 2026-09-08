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
212 — a 97% under-report. Marketplace metering depends on this figure, so this was a revenue defect,
not a cosmetic one.

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
- **Gemini capacity is unreliable.** `gemini-3.6-flash` returned 503 "high demand" repeatedly and
  429 on a short per-minute quota. The live tests now retry both, three attempts with backoff, and
  skip rather than fail when a provider is busy for all three — a skip records "not verified", which
  is honest, where a failure would wrongly accuse the adapter.

### Confirmed sound

Decoding is lenient for all three adapters, with strictness correctly confined to client input via
`strictJSON`. The specific Bedrock defect — a provider adding an unmodelled response field — cannot
recur here. Anthropic's streaming path rejects unknown event types outright; all seven types a real
stream emitted (`message_start`, `content_block_start`, `content_block_delta`, `content_block_stop`,
`message_delta`, `message_stop`, `ping`) are in its allowed set, with `content_block.type: text` and
`delta.type: text_delta` as expected.
