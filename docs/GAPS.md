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

16. **Account-level provider failures now fail over.** Three real refusals were
    measured and are now classified from the response body rather than the
    status code alone: OpenAI out of credits (429 with no `Retry-After` and no
    rate-limit headers), Anthropic balance too low (400, not 402 or 429), and
    Gemini quota exhausted (429). Each withholds that provider for 60 seconds
    and tries the next route, counted as `switchboard_account_failover_total`.
    Classification fails safe: an unrecognised 400 stays terminal, because a
    genuinely malformed request would be refused identically everywhere and
    replaying it would multiply the waste rather than avoid it. A terminal
    rejection now carries the provider's own reason instead of a bare
    "provider rejected request".
17. **Providers are checked at startup.** Once the first signed policy verifies,
    each provider it routes to receives one real 8-token completion using a model
    the policy names. A failure withholds that provider and logs at ERROR;
    `provider_check_strict` additionally holds `/readyz` at 503 so the platform
    replaces the task. `/readyz` and the serving path are deliberately separate:
    the gateway keeps serving through a failed check, because refusing every
    request would deadlock recovery, since a successful request is what clears
    the check. A completion is used rather than an auth-only endpoint
    because `GET /v1/models` returned 200 on a key whose account had no credits,
    minutes before a completion on the same key returned 429.

## Still open

1. **Deployment is proven for the quickstart only.** `quickstart.yaml` has been
   deployed, verified and torn down in one account, in us-east-1, with one
   certificate, on Postgres 17.11. **`controlplane.yaml` has never been
   deployed**, no other region has been tried, and the Postgres 18.6 default now
   in the template has never been deployed either — that default and the derived
   parameter-group expression remain unexercised.
2. **Live provider traffic, now verified; two behaviours recorded.** All four
   adapters have been exercised against the real services, complete and
   streaming, and two defects were found and fixed (Gemini metered output tokens
   as zero; OpenAI reasoning models were unusable because the request sent
   `max_tokens`). See `docs/VALIDATION.md`. What remains open is narrower:
   regional availability and data-retention suitability are still unassessed;
   `gemini-3.6-flash` returns 503 under load and 429 when the suite is run in
   quick succession, so a run can need retries and will skip rather than fail
   when all of them are refused, meaning a green suite does not by itself prove
   Gemini was reached; and model names
   proved to be a live dependency rather than a constant, with two of the three
   originally targeted models retired out from under the tests.
3. **A small `max_tokens` cannot reach a reasoning model that needs more.** The
   gateway fails over when a provider returns 200 with no text, counts
   `switchboard_empty_completion_total`, and now names the offending routes and
   the reasoning tokens they consumed so the caller can act. What it does not do
   is avoid the route in the first place, so a policy whose routes are all
   reasoning models still fails most default-budget requests.

   `ParseChat` still defaults `max_tokens` to 1024. Measured against
   `gpt-5-nano`, that default returned **zero characters for four of seven
   ordinary prompts**, including "list three uses for a paperclip". Raising the
   default is not the fix and has been ruled out on evidence: 4096 still returned
   nothing for a 500-word essay prompt, while `gpt-4o-mini` answered that same
   prompt inside 666 billed tokens. There is no static number that is both
   sufficient for reasoning models and not a tax on everything else. Reasoning
   demand is not even stable per prompt: the same request consumed 1920 reasoning
   tokens at a budget of 2048 and 1152 at 4096.

   Two decisions are deliberately open rather than forgotten:

   - **Budget-aware routing.** Track observed reasoning demand per provider and
     model, and skip a route whose demand exceeds the caller's budget in favour
     of one that can answer. This is the actual fix, it is what a router is for,
     and the reasoning-token signal it needs is already being collected. Deferred
     by choice, to be taken up next.
   - **Whether `max_tokens` may ever be exceeded** to obtain an answer. Today it
     never is: the caller's cap is treated as a hard spending limit, and the
     gateway routes around the problem rather than quietly spending more than was
     authorised. Left open.
4. **Metrics only leave the task if you configure it.** `/metrics` is loopback
   only, and the scraping collector is an opt-in container absent from both
   CloudFormation templates and the sample task definition, so a default
   deployment exposes no counters at all. Setting `otlp_metrics_url` pushes every
   counter, gauge and the request-duration histogram over OTLP with no extra
   container. The gateway now warns at startup when neither path is configured,
   so the default silence is at least visible in the log stream.
5. **No alerting is provisioned.** Neither template defines a CloudWatch alarm,
   SNS topic or metric filter. `docs/DEPLOYMENT.md` now gives per-metric
   thresholds, but the buyer applies them. This is harder than it sounds because
   **neither template deploys the gateway**: both deploy the control plane, and
   the sidecar is added to the customer's own task definition, so gateway alarms
   cannot simply be added to `quickstart.yaml`. They need a separate opt-in
   template or documented definitions applied against the buyer's own log group.
6. **Anthropic prompt-cache tokens are not counted.** Responses carry
   `cache_creation_input_tokens` and `cache_read_input_tokens`; neither is
   modelled. Both are zero today, so input accounting is currently correct, but
   enabling prompt caching would under-count input.
7. **Reasoning models constrain `temperature`.** They reject any value other
   than the default. `Chat.Temperature` is optional and was nil throughout
   testing, so this has not been hit, but a caller setting it against a
   reasoning model would get a 400. Not fixed blind.
8. **Bedrock does not stream.** Bedrock returns AWS event-stream framing rather
   than server-sent events, and that decode path is not built. A streaming
   request skips a bedrock route at selection time and tries the next provider,
   so a policy with another route still serves it; a policy whose only route is
   bedrock returns the ordinary 503. Nonstreaming Bedrock is complete.
9. **Soak duration.** The longest run is 60 seconds. Nothing addresses memory
   growth, file-descriptor leaks, spool behavior over hours, or policy rotation
   mid-flight.
10. **No idempotency.** There is no exactly-once guarantee, replay cache or
   ledger. A 429 or 503 retry cannot prove the absence of upstream billing.
   Clients must disable automatic retries.
11. **Security operations.** Bearer RBAC exists; SSO, MFA, human-user lifecycle,
   external authorization, hardware-backed signing and automated key renewal do
   not. Row level security defends against query mistakes, not against a
   compromised shared database session.
12. **Scale and operations.** Rate limits and circuit state are per process, not
   fleet-wide. There is no retention policy, partitioning, dashboard, SLO, audit
   export or restore drill. The spool caps at 100 events per tick.
13. **Supply chain, remaining.** No SBOM generation and no image signing, and
   there is no release workflow at all — images are built and pushed by hand.
   Python and Go dependency graphs are pinned and scanned, GitHub Actions are
   pinned by commit SHA, and both images report zero scan findings. Signing and
   SBOM are what a buyer's security review asks for rather than a listing
   requirement; the enforced requirement is freedom from known vulnerabilities,
   which is met.
14. **Infrastructure assumptions.** `controlplane.yaml` requires an existing VPC,
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
