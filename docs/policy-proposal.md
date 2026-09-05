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

## Why CEL specifically

[CEL](https://cel.dev) is the narrow version of the same idea, and the
differences are exactly the ones that matter:

- **It compiles and type-checks at load.** A malformed or ill-typed expression
  is a startup error in front of whoever wrote it — the same contract as the
  rest of the configuration.
- **It is not Turing-complete.** Evaluation provably terminates. No policy can
  hang the gateway, which is not a promise a rules engine can make.
- **It has a cost model**, so an expensive expression is refused rather than
  discovered under load.
- **Kubernetes admission control uses it**, so the security reviewer this is
  written for has already accepted it somewhere else.

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

## The cost, stated plainly

`cel-go` is a real dependency, and `docs/controls.md` currently says under
ISO 27001 A.8.30: *standard library plus the AWS SDK; go.mod is the whole list.*
That sentence would change, and it is a sentence that has done real work in this
project's favour.

Whether expressiveness is worth it depends on whether anyone actually asks for
these conditions. Nobody has yet. **This is written down rather than built for
exactly that reason** — the feature is speculative until a deployment needs it,
and speculative dependencies are how a small tool stops being one.

## Alternatives considered

**OPA/Rego** — more powerful and more widely deployed for authorization, but
usually a separate process or a much larger embed, and Rego is a language a
platform team has to learn. CEL expressions read like the conditions they
replace.

**A hand-written expression evaluator** — the JWT verifier in switchboard is
in-tree for reasons that do not apply here. There the surface was small,
verification-only, and every attack was testable. An expression language is
neither small nor bounded, and getting it wrong means a policy that silently
does not mean what it says.

**Leaving it static** — what exists today. The honest default until someone
names a condition they cannot express.
