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
   unaided once the provider is healthy. See the caveat below on recovery time.
9. **Graceful shutdown under load.** SIGTERM during 3-second generations: the
   process exited after 4s with status 0, and every completed request shows a
   full generation latency, so in-flight work finished rather than being cut off.
10. **Python dependency reproducibility.** The full graph is pinned; a clean
    install resolves to exactly the 27 pinned versions.
11. **Go vulnerability scanning.** `govulncheck` reports no vulnerabilities under
    the Go 1.26 toolchain used by CI and the Dockerfile.

## Still open

1. **Container image vulnerabilities.** The control-plane image reports 19
   findings (4 critical, 15 high) in Debian packages — perl, util-linux,
   openssl, zlib, pcre2 — none in the application or its Python dependencies.
   **Every one is currently marked as having no fix available upstream**, so
   this is not resolved by rebuilding, and Debian trixie was worse (6 critical,
   11 high, also unfixed). Genuine remediation means reducing the operating
   system surface, which the gateway image already demonstrates: being
   distroless, it reports no findings at all. This is listing-relevant, because
   AWS Marketplace requires images free of known vulnerabilities.
2. **Circuit-breaker recovery time.** Documented as a 15-second open period with
   one half-open probe. Observed end-to-end recovery under 40 requests/second was
   approximately 45 seconds. The cause is not established — it may be several
   open-and-probe cycles — and the discrepancy should be understood before the
   documented figure is relied on.
3. **No real deployment.** Nothing has ever been provisioned. The templates are
   validated, not executed. The bootstrap custom resource, which runs migrations
   through a one-off ECS task, is the least proven part and the most likely to
   need iteration against a live account.
4. **No live provider traffic.** All three adapters have only ever been exercised
   against the local mock and in-repo test handlers. Model equivalence, real
   streaming behavior, regional availability and data-retention suitability
   remain unverified.
5. **Soak duration.** The longest run is 60 seconds. Nothing addresses memory
   growth, file-descriptor leaks, spool behavior over hours, or policy rotation
   mid-flight.
6. **No idempotency.** There is no exactly-once guarantee, replay cache or
   ledger. A 429 or 503 retry cannot prove the absence of upstream billing.
   Clients must disable automatic retries.
7. **Security operations.** Bearer RBAC exists; SSO, MFA, human-user lifecycle,
   external authorization, hardware-backed signing and automated key renewal do
   not. Row level security defends against query mistakes, not against a
   compromised shared database session.
8. **Scale and operations.** Rate limits and circuit state are per process, not
   fleet-wide. There is no retention policy, partitioning, dashboard, SLO, audit
   export or restore drill. The spool caps at 100 events per tick.
9. **Supply chain, remaining.** No SBOM generation, no image signing, and GitHub
   Actions are pinned by tag rather than commit. Python and Go dependency
   graphs are pinned and scanned; container images and release artifacts are not
   yet signed.
10. **Infrastructure assumptions.** `controlplane.yaml` requires an existing VPC,
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
