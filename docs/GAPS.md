# Status and remaining gaps

Last revised 2026-09-07, from evidence produced that day. Items move out of
"open" only when a run demonstrates them, never because the implementation looks
correct.

The Switchboard Sidecar is the deployable data-plane component of Switchboard.
This file covers the sidecar and the control plane it talks to.

## Verified

Each of these is backed by a run recorded in `docs/VALIDATION.md`.

1. **End-to-end request path.** A request traverses client, gateway, signed
   policy verification and provider, streaming and nonstreaming, over real
   sockets. Telemetry reaches Postgres through the disk spool and is
   acknowledged.
2. **Control-plane API, migrations, RLS, revocation and deduplication.** Run in
   CI against a real `postgres:17`, and again locally through the development
   stack, with migrations applied by the owner and the runtime connecting as a
   separate weaker login.
3. **Container builds.** Both images build and run; the control-plane image
   imports the application; the gateway serves.
4. **Terraform syntax and provider validation** across all three roots.
5. **CloudFormation templates** pass `cfn-lint` and server-side
   `aws cloudformation validate-template`.
6. **Sustained load.** 2,399 requests over 60s at 40/s, 8 workers, half
   streaming: 2,398 succeeded, p50 1 ms, p95 43 ms, p99 45 ms.
7. **Bounded backpressure.** 874,504 requests offered in 30s (29,149/s) against
   a configured limit of 50/s: 1,555 admitted, 872,888 rejected with 429, and
   p99 held at 10 ms. The gateway sheds load rather than queueing it.
8. **Circuit breaker and recovery.** With a provider failing, the breaker opens
   and rejects in about 1 ms without contacting the provider, then recovers
   unaided once the provider is healthy. Recovery timing is explained in item 13.
9. **Graceful shutdown under load.** SIGTERM during 3-second generations: the
   process exited after 4s with status 0, and every completed request shows a
   full generation latency, so in-flight work finished rather than being cut off.
10. **Python dependency reproducibility.** The full graph is pinned; a clean
    install resolves to exactly the 27 pinned versions.
11. **Go vulnerability scanning.** `govulncheck` reports no vulnerabilities. The
    toolchain is now aligned at Go 1.27 across `go.mod`, CI and the Dockerfile,
    and the `go` directive was raised so a stale toolchain cannot silently build
    the binary against a vulnerable standard library.
12. **Container image vulnerabilities — resolved.** The control-plane image
    previously reported 19 findings, 4 critical, all in Debian packages with no
    fix available upstream. Rebasing onto distroless removed the packages rather
    than waiting for fixes that do not exist: **the image now reports zero
    findings**, and is 7 MB smaller. perl and util-linux, which accounted for 13
    of the 19 and were never used by the application, are simply no longer
    present.
13. **Rate limits no longer trip the circuit breaker.** A 429 and a 503 both fed
    the breaker, so three rate limits withheld a healthy provider for fifteen
    seconds. A 429 is now a cooldown: it fails over, honours any `Retry-After`
    the provider sent, and records no failure. Measured with identical injection
    and load, five 429s cost five failed requests where they previously cost
    about 1,803 over 45 seconds; five 503s still cost 1,796, deliberately
    unchanged, which is the control showing the breaker was not weakened.
14. **Deployment, teardown and TLS.** The quickstart deploys, the bootstrap
    custom resource applies migrations and creates a runtime login distinct from
    the migration owner, and `/readyz` answers over TLS through the internal load
    balancer on a real certificate. Teardown removes everything billable and is
    guarded against running before a stack has finished deleting.
15. **Circuit-breaker recovery — explained, and it is not a defect.** The
    observed 45-second recovery is the breaker working as written: it trips at
    three failures, and each *failed* half-open probe re-arms a fresh full 15
    seconds. The provider under test failed five times, so three cycles elapsed
    before a probe succeeded. Confirmed by prediction: repeating the run with
    exactly three failures recovered in one cycle, 603 rejections against 1,795
    successes, where five failures gave 1,803 against 595. The code is
    self-consistent; `docs/ARCHITECTURE.md` was imprecise and has been corrected.

## Still open

1. **Deployment is proven for the quickstart only.** `quickstart.yaml` has been
   deployed, verified and torn down in one account, in us-east-1, with one
   certificate, on Postgres 17.11. **`controlplane.yaml` has never been
   deployed**, no other region has been tried, and the Postgres 18.6 default now
   in the template has never been deployed either — that default and the derived
   parameter-group expression remain unexercised.
2. **No live provider traffic.** All three adapters have only ever been exercised
   against the local mock and in-repo test handlers. Model equivalence, real
   streaming behavior, regional availability and data-retention suitability
   remain unverified.
3. **Soak duration.** The longest run is 60 seconds. Nothing addresses memory
   growth, file-descriptor leaks, spool behavior over hours, or policy rotation
   mid-flight.
4. **No idempotency.** There is no exactly-once guarantee, replay cache or
   ledger. A 429 or 503 retry cannot prove the absence of upstream billing.
   Clients must disable automatic retries.
5. **Security operations.** Bearer RBAC exists; SSO, MFA, human-user lifecycle,
   external authorization, hardware-backed signing and automated key renewal do
   not. Row level security defends against query mistakes, not against a
   compromised shared database session.
6. **Scale and operations.** Rate limits and circuit state are per process, not
   fleet-wide. There is no retention policy, partitioning, dashboard, SLO, audit
   export or restore drill. The spool caps at 100 events per tick.
7. **Supply chain, remaining.** No SBOM generation, no image signing, and GitHub
   Actions are pinned by tag rather than commit. Python and Go dependency
   graphs are pinned and scanned; container images and release artifacts are not
   yet signed.
8. **Infrastructure assumptions.** `controlplane.yaml` requires an existing VPC,
    subnets, IAM roles, KMS keys, ECS cluster and load balancer target group.
    `quickstart.yaml` removes all of those except the certificate.

## Blocked externally

These need an action from the owner or from AWS. **They are not implementation
defects, and nothing in the code is waiting on a fix.**

1. **AWS Marketplace seller registration**, including tax and banking details,
   and a defined customer support process — required for any listing, including
   a free one.
2. **A real `ProductCode`.** `RegisterUsage` is implemented and unit-tested
   across entitled, unentitled, unconfigured and client-failure paths, but it
   cannot be exercised against AWS until a listing exists. Registration against
   the live Marketplace metering service is therefore **untested**.
3. **A TLS certificate and DNS record.** The quickstart template cannot be
   deployed without an ACM certificate for a domain the deployer controls.
4. **Marketplace-managed ECR.** A listing requires every image a subscriber needs
   to be published there. The current images are in a development registry.
5. **A full deployment.** Standing up the quickstart stack costs roughly
   $180-200 per month while it runs, and is a spending decision rather than an
   engineering one.
