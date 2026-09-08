# Contributing

**Contributions are not currently accepted.** This document exists so the
position is settled before that changes, not because there is a queue.

When it does change, the terms below apply.

## Sign-off

Every commit must carry a `Signed-off-by` trailer:

```sh
git commit -s
```

That appends `Signed-off-by: Your Name <you@example.com>` using your git
`user.name` and `user.email`. Use a real name and an address that reaches you.
CI rejects any commit in a pull request without the trailer.

Signing off certifies the [Developer Certificate of Origin 1.1](DCO), reproduced
verbatim in this repository.

**One wording note, because it would otherwise be confusing.** The DCO says
"the open source license indicated in the file." Switchboard is licensed under
the [Elastic License 2.0](LICENSE), which is source available and **not** an
OSI-approved open source license. For this project, signing off certifies the
same four things — (a) through (d) — with respect to the Elastic License 2.0.
Source-available projects use the DCO routinely; the text is left unmodified
because an edited DCO is worth less than the recognised one.

## Grant

You keep the copyright in your contribution.

By submitting a contribution, you grant the copyright holder identified in [LICENSE](LICENSE) a perpetual,
worldwide, non-exclusive, irrevocable, royalty-free, sublicensable and
transferable license to use, reproduce, modify, prepare derivative works of,
publicly display, distribute and relicense that contribution, in whole or in
part, **under any license terms and as part of any product**.

That last clause is doing real work and is stated plainly rather than buried:

- Switchboard Sidecar is source available under ELv2 today. This grant permits
  relicensing it later, including under different terms.
- **Switchboard Recordkeeper is proprietary and closed.** Your contribution may
  be used there, in a product whose source is not published.

If either is unacceptable to you, do not contribute. That is a reasonable
position and no argument will be made against it.

## Practical rules

- **No real credentials, private signing keys, or Terraform state** ever enter
  this repository. The `.env.example` holds runtime references only, and the
  fixture public key in `testdata` is test-only.
- `go test -race ./...` must pass. Postgres tests need a disposable dedicated
  cluster and `TEST_DATABASE_URL`; they create schema and roles.
- CI runs `govulncheck` and `pip-audit`, and pins every GitHub Action by full
  commit SHA. Keep it that way.
- **New dependencies are close to unwelcome.** The module graph is 4 direct and
  12 indirect, every one AWS-published, and the Python requirements are pinned
  direct and transitive. That is a load-bearing product claim, not an accident —
  a PR adding a convenience library will be declined on those grounds alone.
  Prometheus exposition, OTLP export, Ed25519 verification and SSE parsing are
  hand-written against the standard library for this reason.
- Unknown request fields are rejected on purpose. Widening the API surface is a
  design decision, not a patch.

## Not legal advice

This document was drafted without a lawyer. Before the first external
contribution is accepted, it — and the ELv2 relicense it sits on top of —
should be reviewed by one.
