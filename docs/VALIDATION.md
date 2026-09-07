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
  critical, also all unfixed, so the base was reverted. Recorded as open in
  `docs/GAPS.md`.

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
  documents a 15-second open period with one half-open probe. The cause is not
  established. Recorded as open in `docs/GAPS.md` rather than reconciled by
  assumption.

An earlier attempt at the failure-injection scenario was invalid and is recorded
here rather than discarded: with the provider set to fail its first 300 requests,
the breaker opened and stopped contacting the provider, so its failure counter
never advanced and recovery was unreachable within the run. The test was
redesigned, not the system.

### Not run here

Full quickstart deployment, live provider requests, real Marketplace
registration, soak beyond 60 seconds, SBOM generation and image signing. See
`docs/GAPS.md` for the distinction between what remains open and what is blocked
on an external action.
