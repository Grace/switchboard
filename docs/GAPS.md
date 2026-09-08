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
17. **Telemetry delivery is batched.** Delivery was one POST per event, issued
    sequentially, so its real ceiling was round-trip bound rather than the
    hundred per tick the cap suggested: comfortable against a control plane in
    the same task, roughly twenty per second across a network at 50 ms. A spool
    that cannot drain grows to its cap and then drops events, and those events
    are billing and audit records.

    Measured after the change, at 150 requests per second for 45 seconds: 6,746
    events delivered in **47 requests**, 143.5 events each, with the spool
    empty and zero drops and zero export errors afterwards.

    The control-plane route is additive and the gateway falls back to the
    per-event route on a 404, or on a 200 that does not carry the expected
    acknowledgement, so either component can be deployed first. That is what
    makes this safe to ship while the `Event` token fields are not: those would
    be rejected by an older control plane's `extra="forbid"`.

    An event the control plane refuses is dropped and counted rather than
    retried forever, because a deterministic rejection resent every tick would
    wedge every event queued behind it.

    **Write churn was deliberately not fixed.** `atomicFile` costs three dentry
    operations per event, which is most of the reclaimable slab growth measured
    on 2026-09-08. Fixing it means appending to rotating segment files, which
    widens the crash-loss window from the in-memory queue to the in-memory queue
    plus the unflushed tail of the open segment. Widening a data-loss window on
    billing records to make a container memory graph look tidier is the wrong
    trade, and the slab growth is reclaimable rather than a leak.

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
3. **Budget-aware routing, on measured behaviour.** A route is skipped when that
   model was already seen returning no text at the caller's `max_tokens`, and has
   never been seen succeeding at or below it. The gateway used to discover this
   per request, pay for it, and fail over; it now avoids the call.

   Verified live against real providers with a policy of `openai:gpt-5-nano` then
   `anthropic:claude-haiku-4-5`: the first 1024-token request reported
   `X-Switchboard-Attempts: 2` after the reasoning model returned nothing, and an
   identical second request reported `1`, having skipped it. Both callers got a
   real answer of over 1,500 characters.

   Two facts per model, not a statistic: the largest budget seen producing
   nothing, and the smallest seen producing text. Averaging would be confidently
   wrong, because the same prompt consumed 1920 reasoning tokens at a budget of
   2048 and 1152 at 4096. A single success overrides any number of failures, so
   the rule corrects itself rather than latching, which bounds its known
   imprecision: demand depends on the prompt, so a hard prompt failing can
   briefly shadow an easy one at the same budget.

   **If every eligible route would be skipped, none is.** Refusing to try is
   worse than trying and failing over, and a policy whose routes are all
   reasoning models is exactly the case this exists for. Observations are bounded
   and expire after six hours, because model behaviour moves: two of the three
   models named in the live tests were retired by their providers mid-project.

   `ParseChat` still defaults `max_tokens` to 1024, and that is still the budget
   measured returning nothing for four of seven ordinary prompts on `gpt-5-nano`.
   Raising it remains ruled out on evidence: 4096 also returned nothing for a
   500-word essay prompt, while `gpt-4o-mini` answered it inside 666 billed
   tokens. Routing around the problem is the fix; a bigger number is not.

4. **Metrics only leave the task if you configure it.** `/metrics` is loopback
   only, and the scraping collector is an opt-in container absent from both
   CloudFormation templates and the sample task definition, so a default
   deployment exposes no counters at all. Setting `otlp_metrics_url` pushes every
   counter, gauge and the request-duration histogram over OTLP with no extra
   container. The gateway now warns at startup when neither path is configured,
   so the default silence is at least visible in the log stream.
5. **Alerting goes through Honeycomb, and the path is built but unproven.**
   Gateway alarms hang off metrics in Honeycomb rather than CloudWatch, which is
   now a decision rather than an omission. CloudWatch remains reachable by the
   same mechanism whenever it is wanted.

   The blocker was that OTLP export could not authenticate to anything: both
   exporters set only `Content-Type`, so `otlp_metrics_url` worked against an
   unauthenticated collector on loopback and nothing else. `otlp_headers` now maps
   a header name to the **name of an environment variable**, matching how every
   other secret in this configuration is handled, and both exporters apply it.
   Header names are validated as HTTP tokens, so a hand-edited config cannot
   inject CR or LF, and the map cannot override `Content-Type` or `Authorization`.

   **Verified against Honeycomb on 2026-09-08.** Pointing the dev stack at
   `api.honeycomb.io` produced two datasets in the `gracefulcode` team's `test`
   environment within a minute: `metrics`, carrying all 30 `switchboard.*`
   counters and the latency histogram, and `switchboard-gateway`, carrying spans
   with `gen_ai.provider.name`, `duration_ms` and `trace.trace_id`. Both
   exporters authenticate through `otlp_headers`, so the path is no longer
   exercised only against an `httptest` server.

   Waiting for data was the right call, and it caught a real defect: **the two
   paths spell the counters differently.** `/metrics` emits
   `switchboard_empty_completion_failed_total`; OTLP emits
   `switchboard.empty_completion_failed_total`. Every trigger in
   `docs/DEPLOYMENT.md` had been written in the `/metrics` spelling, so all four
   would have referenced columns that do not exist. The table is corrected.

   **Two of the four triggers exist**, on
   `switchboard.empty_completion_failed_total` and
   `switchboard.account_failover_total`. The other two could not be created: the
   API returned "Failed to save trigger" for both, and for a minimal probe
   trigger on an unrelated column, which points at an account-level cap rather
   than anything wrong with the queries.

   **Neither existing trigger notifies anyone.** The team has no notification
   recipients configured, so both evaluate and neither pages. That is worse than
   having no trigger, because it reads as coverage on a dashboard. Adding a
   recipient is the remaining work.

6. **Anthropic prompt-cache tokens are not counted.** Responses carry
   `cache_creation_input_tokens` and `cache_read_input_tokens`; neither is
   modelled. Both are zero today, so input accounting is currently correct, but
   enabling prompt caching would under-count input.
7. **Reasoning models constrain `temperature`.** They reject any value other
   than the default. `Chat.Temperature` is optional and was nil throughout
   testing, so this has not been hit, but a caller setting it against a
   reasoning model would get a 400. Not fixed blind.
8. **Bedrock streaming, verified against the real service.** All four providers
   stream. Bedrock's AWS event-stream framing is translated into server-sent
   events at the provider boundary by `bedrockSSE`, so the generation deadline,
   finish tracking, empty-completion detection and the refusal to replay after
   acceptance apply to it identically rather than gaining an exception.

   The translator holds the stop reason back and emits it together with token
   usage, because Bedrock sends those as two separate events and the pipeline
   terminates on the first frame reporting completion. Without that, every
   streamed Bedrock request would have reported zero tokens. A live run confirms
   it: 17 frames, `finish=stop`, `in=5 out=47`, with usage intact.

   What remains unexercised on this path: tool and reasoning blocks are refused
   rather than flattened, and that refusal has only been tested with synthetic
   frames, because Nova Micro does not emit them for these prompts.
9. **Spool file churn grows reclaimable kernel slab. Not a leak, and the earlier
   claim that it was is retracted.** A 30 minute soak measured resident memory
   rising from 7.4 MiB to 26.9 MiB and this file previously called that the most
   important open item, projecting an out-of-memory kill within a day. That was
   wrong. It read `docker stats` without decomposing what the number contains.

   Measured with pprof and the container's own cgroup accounting:

   | | growing? |
   |---|---|
   | Go `Sys`, all memory the runtime holds | +0.25 MB in 3 minutes |
   | `HeapAlloc`, live objects | flat, slightly down |
   | `Mallocs` minus `Frees` | equals `HeapObjects` exactly |
   | goroutines | 34 then 24, down |
   | cgroup `anon`, the process | flat at 8.65 MB |
   | cgroup `slab_reclaimable` | **4.60 to 5.79 MB in 2 minutes** |
   | cgroup `slab_unreclaimable` | zero throughout |

   Resident growth tracks slab, and slab is entirely reclaimable. The telemetry
   spool writes one file per event and unlinks it after the control plane
   acknowledges, so 20 requests per second churns 40 dentry operations per
   second, and the kernel caches those dentries and inodes against this cgroup.
   At roughly 0.55 MB per minute that accounts for about 16.5 MB across 30
   minutes, which matches the 19.5 MB originally reported.

   The consequence is real but different: reclaimable slab counts toward a
   container memory limit, and the kernel frees it under pressure rather than
   killing the process. It will look like unbounded growth in any monitoring that
   watches container memory, which is worth documenting for operators. Batching
   the spool into segment files rather than one file per event would remove the
   churn, and is the fix if this ever needs one.
10. **Idempotency keys, bounded and off by default.** `Idempotency-Key` is
    honoured when `idempotency_ttl_seconds` is set. A duplicate key returns the
    original response without calling the provider; the same key with a different
    body is refused with 422; a key whose original outcome is genuinely unknown
    refuses the retry with 409 rather than risk charging twice.

    That last case is the point. Four paths in `chat()` end with generation
    ambiguous, and the entry is deliberately sticky there. An unambiguous failure
    such as a provider 400 releases the key instead, so a caller who can fix the
    request is not blocked by their own typo.

    **Exactly-once generation across provider APIs remains impossible**, and
    nothing here claims otherwise. What changed is the window in which the
    ambiguity costs money. Entries survive a process restart, because they are in
    `data_dir` under the existing exclusive lock, but **not task replacement**,
    since that directory is ephemeral unless mounted on EFS. A retry landing on a
    replacement task is a new request. Anything stronger needs durable shared
    storage, which is a different product decision.

    Off by default because entries hold request and response content, which is a
    new category of data at rest; `docs/SECURITY.md` says so plainly rather than
    leaving the earlier "not logged or in telemetry" statement to imply more than
    it covers.

11. **Security operations.** Bearer RBAC exists; SSO, MFA, human-user lifecycle,
   external authorization, hardware-backed signing and automated key renewal do
   not. Row level security defends against query mistakes, not against a
   compromised shared database session.
12. **Scale and operations.** Rate limits and circuit state are per process, not
   fleet-wide. There is no retention policy, partitioning, dashboard, SLO, audit
   export or restore drill.
13. **The release pipeline exists but has never run.**
    `.github/workflows/release.yml` builds both images on a `v*` tag, attaches
    SBOM and provenance attestations using buildx's own attestation support
    rather than a third-party action, signs each image by digest with keyless
    cosign, and verifies the signature it just made. Images are no longer
    specified as built by hand.

    **None of it has executed.** It needs the OIDC role from
    `deploy/cloudformation/github-oidc.yaml`, which is written but not deployed,
    and it could not be rehearsed locally: the attestation flags require buildx
    0.10 or later on the `docker-container` driver, and the machine it was
    written on has 0.8.2 on the `docker` driver. What is verified is that the
    workflow parses, that every action is pinned to a SHA confirmed to be a real
    commit, and that the trigger admits tags only.
14. **Infrastructure assumptions.** `controlplane.yaml` requires an existing VPC,
    subnets, IAM roles, KMS keys, ECS cluster and load balancer target group.
    `quickstart.yaml` removes all of those except the certificate.

15. **Onboarding, largely closed.** `docs/LOCAL.md` now documents a file-only
    path to a first real provider request that needs no Postgres, no migrations,
    no database roles, no tenant, no principals and no control plane. It was
    verified by following it from a clean directory, using nothing that is not on
    the page, and it produced a real completion from OpenAI with
    `X-Switchboard-Provider: openai`.

    Four defects behind it are fixed. `config.example.json` could not start,
    because its trust key was not valid base64 and it declared four providers of
    which three demand a key variable; it is now a working file-only example.
    Nothing derived a public key from a signing seed, while `quickstart.yaml` and
    `docs/SECURITY.md` both instructed the reader to obtain one, so
    `gateway -public-key` now does it and both documents are corrected. The
    single `invalid configuration limits` covering thirteen conditions now names
    the field and its range. `controlplane.policytool` signs a policy straight to
    `data_dir/policy.json` and computes the timestamps, reaching the same
    `policy.sign` the control plane uses; a fixture test holds the Python signer
    and the Go verifier to one canonical encoding.

    **A worse defect surfaced while testing that.** `slog.Error` followed by
    `os.Exit` raced the async log writer, and a misconfigured gateway exited 1
    printing nothing at all roughly a third of the time, measured at 6 and 8
    successes in 10 runs. Every fatal path now flushes first, verified at 20 out
    of 20. A configuration error that prints nothing is the worst possible
    failure for the exact person this work is for, and the hazard was already
    known: `main.go` carried a comment about it on one path and not the other
    thirteen.

    Still open, recorded so it is not rediscovered: four correlated secrets
    related only by `.dev/env`; the 15 second policy poll that makes a first
    control-plane attempt look like a hang; and `asm-exec`, referenced by
    `.env.example` and `docs/DEPLOYMENT.md`, which is not in this repository and
    is nowhere explained.

    Not a defect and deliberately unchanged: `adapter.go` rejects any model but
    `preferred`, so the first thing an OpenAI SDK user types fails. That is the
    signed policy doing its job, and `LOCAL.md` now says so at the point the
    reader meets it.

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
