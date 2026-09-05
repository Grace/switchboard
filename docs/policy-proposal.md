# Proposal: an expression layer for admission

**Status: proposed, not built.** Nothing described here exists. It is written
down so the design can be argued with before there is code to defend.

## The gap

Static configuration decides who may call, what they may spend, and what is
redacted. It cannot express a condition:

- this model only during business hours
- requests over 8k tokens must come from a named person, not a shared key
- this team may not reach a cloud provider at all, only on-device models
- a caller past 80% of budget may not start a streaming request

Every one of those is a real ask, and today the answer is "change the code."

## Why not a rules engine

The obvious move is to embed one. It is the wrong move here, and the reason is
the property the rest of this system rests on: **you can read the configuration
and know what the gateway will do.** Everything is validated before the listener
opens, unknown fields are rejected, and `docs/controls.md` leans on that in four
separate rows.

A general rules engine is late-bound. Its behaviour is not knowable from reading
its input, forward-chaining makes rule interaction hard to predict, and the
claim that this is a reference monitor small enough to read stops being true.
Trading that away for expressiveness would cost more than it buys.

## Do not embed a language. Ask something that already has one.

The obvious candidates are CEL and Rego, and the argument between them misses
what actually decides adoption: **any policy language is a learning cost for the
buyer**, and that cost is not evenly distributed.

Rego is what a great many platform teams already run — OPA is the de facto
standard for policy-as-code, and a shop with an OPA sidecar has the language,
the tooling, `opa test`, the CI integration and the reviewers already. For them
Rego is free and everything else is a new thing to learn.

For a shop *without* OPA, Rego is the most expensive of the options rather than
the least: it is datalog-derived, its partial-evaluation semantics are
famously unobvious, and it is the hardest of the three to pick up.

That cost is bimodal, which is the tell. **Any choice of embedded language is
wrong for half the market**, so this should not choose one.

```json
{
  "policy": {
    "enabled": true,
    "endpoint": "http://127.0.0.1:8181/v1/data/switchboard/admission",
    "timeout": "50ms",
    "fail": "closed"
  }
}
```

switchboard posts a metadata document and reads a decision back. The path shape
is OPA's data API, so a team with an OPA sidecar points at it and writes Rego
they already know. A team without one writes nothing and keeps static
configuration. A team that wants CEL puts a CEL service behind the same
interface. switchboard learns no language, gains no dependency — this is an HTTP
POST with `net/http` — and stays a thing you can read.

### The trade, stated plainly

This costs the property most of the rest of this design rests on: that you can
read the configuration and know what the gateway will do. Policy now lives
somewhere else, in something else's language.

That is a real regression and it should be the operator's decision rather than
one made for them. So:

- It is **off by default**. Static configuration remains the whole story unless
  someone turns this on.
- `fail: "closed"` is the default. An unreachable decision point refuses
  requests rather than admitting them, because a policy layer that fails open is
  worse than none — it is the appearance of enforcement.
- The **timeout is bounded and short**. A slow decision point becomes a refusal,
  not a slow gateway.
- The policy fingerprint records the endpoint and whatever version the decision
  point reports, so "which rules were in force" stays answerable.

### What it does not change

The decision point sees the same metadata document described below and **never
prompt content**. Moving policy out of the process does not move that line.

Its answer is still **deny-only**: it may refuse a request static configuration
would have allowed, and may not grant one static configuration refused. An
external system cannot widen access, which keeps the monotonic property and
means a compromised or misconfigured decision point can cause an outage but not
an authorisation bypass.

## Shape

```json
{
  "policy": {
    "enabled": true,
    "rules": [
      {
        "name": "opus-business-hours",
        "when": "request.model == 'claude-opus' && !(time.hour_utc >= 9 && time.hour_utc < 18)",
        "deny": "MODEL_UNAVAILABLE_NOW"
      },
      {
        "name": "large-requests-need-a-person",
        "when": "request.max_tokens > 8192 && !caller.authenticated_subject",
        "deny": "NAMED_CALLER_REQUIRED"
      },
      {
        "name": "research-stays-on-device",
        "when": "caller.team == 'research' && model.backend != 'local'",
        "deny": "PROVIDER_NOT_PERMITTED"
      }
    ]
  }
}
```

### Rules may only deny

A rule cannot grant access. It can refuse a request the static configuration
would otherwise have allowed, and nothing else.

This is the design decision to keep. It makes policy **monotonic**: adding a
rule can only ever restrict, never widen. "Did this new rule open a hole?" stops
being a question anyone has to answer, ordering between rules stops mattering,
and reviewing a policy change means reading one rule rather than simulating the
interaction of forty.

### What a rule can see

Metadata only:

```
request.model, request.max_tokens, request.message_count, request.stream
caller.team, caller.subject, caller.authenticated, caller.authenticated_subject
model.backend                       "local" or "bedrock"
usage.tokens_used, usage.tokens_allowed, usage.fraction_used
time.hour_utc, time.weekday
```

**Not prompt content.** That exclusion is deliberate and is the same position
[injection-study](https://github.com/Grace/injection-study) argues from: a
gateway is well placed to bound what a model may *do* and badly placed to guess
what an input *means*. A policy that reads prompts is a content filter wearing a
different hat, and it fails the same way.

### What a caller is told

`deny` is a **published code**, not a message and not the expression that
matched. The caller gets `PROVIDER_NOT_PERMITTED`; the audit entry records the
rule name that fired.

That split is the whole point, and it is the same problem
[warden](https://github.com/Grace/warden) exists to solve: a refusal reason is a
query, and telling a caller *which rule* refused them hands them a map of the
policy. Running warden's model inside this gateway is the intended composition.

## Consequences

**The audit record gains two fields** — the rule that denied, and the code the
caller received. Recording only the code would leave an investigation unable to
tell which rule fired; recording only the rule would leave it unable to tell
what was disclosed.

**The policy fingerprint must cover the rules.** Otherwise a policy change is
invisible in the log, which defeats the fingerprint's purpose.

**Deny happens before the backend call**, so a refused request costs nothing and
appears in the audit log with an outcome and no tokens.

## What still has to be built

An HTTP client with a bounded timeout, a documented input document, fail-closed
semantics, and the fingerprint carrying the endpoint. Small.

And the thing without which none of it should ship: a way to see what a policy
actually does before it is in the request path.

```
$ switchboard policy check -team research -model claude-opus
  endpoint  http://127.0.0.1:8181/v1/data/switchboard/admission
  decision  DENY → PROVIDER_NOT_PERMITTED   (14ms)
```

A policy that silently never denies looks exactly like a policy that is working.
That failure is the same shape as a redaction rule that never matches, and it
has the same answer: make it checkable in one command.

Nobody has asked for any of this yet. **It is written down rather than built for
that reason** — not because the design is unresolved.

## Alternatives considered

**OPA/Rego** — more powerful and more widely deployed for authorization, but
usually a separate process or a much larger embed, and Rego is a language a
platform team has to learn. CEL expressions read like the conditions they
replace.

**Embedding cel-go** — the first version of this proposal assumed it. It is the
right choice for something that needs CEL's semantics, and it costs both a
dependency and a language the buyer may not want. Half of them already have a
different one.

**Embedding a small hand-written expression language** — the second version of
this proposal argued for it: a fixed typed variable table, comparison and
boolean composition, roughly 450 lines, no dependency. It is a good design and
it is still the wrong one, because it asks every buyer to learn a language that
exists nowhere else, in exchange for saving the ones who already run OPA from
using what they have.

**Embedding OPA as a library** — possible, and a very large dependency: it
brings the Rego compiler and runtime into the process. Calling a sidecar gets
the same capability without it, and OPA is normally deployed that way anyway.

**Leaving it static** — what exists today. The honest default until someone
names a condition they cannot express.
