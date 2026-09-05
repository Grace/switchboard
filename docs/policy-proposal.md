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

## Why an expression language, and why a small one

[CEL](https://cel.dev) is the well-known answer: compiled and type-checked
ahead of evaluation, not Turing-complete, cost-modelled, and already accepted by
security reviewers because Kubernetes admission control uses it.

But look at what the conditions above actually need. Identifiers drawn from a
**fixed, typed table**. String, integer, float and boolean literals. Comparison.
Boolean composition. Parentheses. That is a recursive-descent parser and a
lookup table — on the order of 450 lines with a type checker, against cel-go's
fifty thousand, because CEL carries protobuf types, macros, comprehensions and a
general type system that none of this uses.

Termination is not a promise here, it is a property of the grammar: no loops, no
function calls, no recursion, nothing to bound. Type checking is a table lookup
rather than inference, because the variables are known in advance.

So the same argument that put JWT verification in-tree applies, with one
difference worth being precise about.

**The failure mode is not the same.** A wrong JWT verifier accepts forged
tokens: loud, and testable by constructing each attack. A wrong expression
evaluator produces **a rule that silently never fires** — nothing errors, the
policy looks enforced, and it is not. That is the redaction-rule failure again,
and it has the same answer:

```
$ switchboard policy test -team research -model claude-opus
  research-stays-on-device      FIRES   → PROVIDER_NOT_PERMITTED
  opus-business-hours           no      (time.hour_utc is 14)
  large-requests-need-a-person  no      (max_tokens unset)
```

**Without that command, this should not be built.** With it, a rule that never
fires is visible in one command rather than never.

### Boundaries, written down before starting

This is the kind of thing that grows into a language one reasonable request at a
time, so:

- **No function calls.** Not even `startsWith`.
- **No arithmetic.** Compare values, do not compute them.
- **No regex.** That is a content filter arriving through a side door.
- **No collection operations** beyond membership in a literal list.

Anything past that boundary is a signal the condition belongs in code, not in
configuration.

**And it is not CEL.** A subset wearing that name promises semantics it does not
have, which is the same species of overclaim as "tamper-proof". It is a
condition expression, and the documentation should say exactly what it accepts.

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

Roughly 450 lines of parser, type checker and evaluator that have to be right,
plus the test command without which a silent non-firing rule is undetectable.
That is real work, and it is code this project would own forever.

What it does not cost is a dependency. `docs/controls.md` says under ISO 27001
A.8.30 that go.mod is the standard library plus the AWS SDK, and that sentence
has done real work here.

Whether the expressiveness is worth it depends on whether anyone actually asks
for these conditions. Nobody has yet. **This is written down rather than built
for that reason** — not because the design is unresolved.

## Alternatives considered

**OPA/Rego** — more powerful and more widely deployed for authorization, but
usually a separate process or a much larger embed, and Rego is a language a
platform team has to learn. CEL expressions read like the conditions they
replace.

**cel-go** — the obvious dependency, and the one this proposal originally
assumed. It is the right choice for anything needing CEL's semantics. Nothing
here does, and it would cost the sentence under ISO 27001 A.8.30 that currently
reads *standard library plus the AWS SDK* — a sentence that has done real work.

**Leaving it static** — what exists today. The honest default until someone
names a condition they cannot express.
