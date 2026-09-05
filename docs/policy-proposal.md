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

## Recommendation: evaluate in-process

Two rankings, and they point opposite ways.

**By adoption cost:** an external decision point wins. A shop already running
OPA writes Rego it knows, in tooling it has. A shop without one writes nothing.
Any embedded language is a new thing to learn, and for the OPA shops it is a new
thing to learn *instead of* the one they have.

**By auditability:** the order inverts, and an external decision point comes
last.

That inversion is the whole answer, because auditability is what this is for.

### Why an external decider is worst for audit

With an in-process evaluator, the rules live in the configuration — so the
policy fingerprint already covers them, the audit entry records which rule
denied, and **the decision is replayable from this system's own records**. The
expression is deterministic and the metadata it saw is in the entry. One
tamper-evident chain answers what happened, under what rules, and why.

With an external decider you can record the endpoint, the deny code, and
whatever version it reports. You cannot reconstruct *why*. That needs the policy
bundle at that version and the decider's own decision log — so the trail is now
split across two systems, with two retention policies, two chains of custody and
no shared integrity guarantee. "We have the gateway's chain and the OPA decision
log and they need correlating" is materially worse in an investigation than one
chain that answers everything, and correlation is exactly what fails when a
bundle from fourteen months ago is in nobody's artifact store.

**So the option that is best for adoption is worst for the thing this claims to
be.** The front page says *an LLM gateway that can prove what happened*. That
settles it.

### What to build: CEL, via cel-go

Evaluate in-process, using [cel-go](https://github.com/google/cel-go).

An earlier version of this proposal argued for a hand-written expression
language — a fixed typed variable table, comparison and boolean composition,
roughly 450 lines — on the grounds that it added no dependency. Two things
changed.

**The audit argument never distinguished the two.** It argued in-process against
external. A CEL expression in the configuration is covered by the fingerprint,
deterministic, and replayable from this system's own records exactly as a
bespoke grammar would be. That criterion is neutral here.

**And the learning-cost argument runs the other way.** A new language is a cost
to whoever adopts this — which is a heavier objection to a grammar *nobody*
knows than to CEL, which people meet in Kubernetes admission policy, Envoy and
gRPC authorization. A bespoke expression language is the worst case of that
objection rather than an escape from it.

The remaining argument was the dependency, and the OpenTelemetry SDK has since
brought protobuf into the tree, so cel-go is no longer a new dependency family.
Writing a parser, a type checker and an evaluator to avoid something already
present is not a trade worth making — particularly when the failure mode of
getting it wrong is a rule that silently never fires.

What cel-go gives that is worth having: compilation and type-checking at load,
so a malformed or ill-typed expression is a startup error under the same
contract as the rest of the configuration; guaranteed termination, since CEL is
not Turing-complete; and a cost model, so an expensive expression is refused
rather than discovered under load.

### Boundaries still apply

CEL is larger than these conditions need, and an environment can be narrower
than the language. Declare only the variables below, and no extension
functions — no regex, since that is a content filter arriving through a side
door, and nothing that reaches outside the request.

**A rule that silently never fires looks exactly like a rule that is working**,
which is the same failure as a redaction rule that never matches. So this ships
with the command or it does not ship:

```
$ switchboard policy check -team research -model claude-opus
  research-stays-on-device      FIRES   → PROVIDER_NOT_PERMITTED
  opus-business-hours           no      (time.hour_utc is 14)
  large-requests-need-a-person  no      (max_tokens unset)
```

## OPA, as a documented integration

Some deployments have already standardised on OPA, and telling them to express
policy twice is not a serious answer. So the same admission point can call out
instead:

```json
{
  "policy": {
    "endpoint": "http://127.0.0.1:8181/v1/data/switchboard/admission",
    "timeout": "50ms",
    "fail": "closed"
  }
}
```

The path shape is OPA's data API, so an existing sidecar works unchanged.

**This is an integration, not the recommended path**, and the reason is the one
above: it splits the audit trail. The documentation should say so rather than
presenting the two as equivalent.

One mitigation recovers most of what is lost: **record the full decision input
and output in this system's own chain**, not merely the verdict. You still
cannot reconstruct *why* the decider answered as it did — that reasoning lives
in a bundle you may no longer have — but you can prove, tamper-evidently and
without them, exactly what was asked and what came back. For most investigations
that is the question.

Fail-closed remains the default. A policy layer that fails open is the
appearance of enforcement, which is worse than no policy layer at all.

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

**A hand-written expression language** — argued for in an earlier version, on
the grounds that it added no dependency. It loses now that protobuf is already
in the tree, and it always lost on learning cost: a grammar nobody knows is a
worse answer to "customers must learn a new language" than one they have met in
Kubernetes.

**An external decision point as the primary mechanism** — argued for in another
version, on adoption grounds that are correct as far as they go. It loses on the
criterion that decides this: policy living elsewhere means a decision cannot be
reconstructed from this system's records. It survives as an integration, above.

**Embedding OPA as a library** — possible, and a very large dependency: it
brings the Rego compiler and runtime into the process. Calling a sidecar gets
the same capability without it, and OPA is normally deployed that way anyway.

**Leaving it static** — what exists today. The honest default until someone
names a condition they cannot express.
