# Honeycomb, and the two tiers

*Wide events for debugging. A chain for evidence. One instrumentation point.*

```json
{
  "telemetry": {
    "endpoint": "api.honeycomb.io:443",
    "headers": {
      "x-honeycomb-team": "env:HONEYCOMB_API_KEY",
      "x-honeycomb-dataset": "switchboard"
    },
    "include_subject": false
  }
}
```

`env:NAME` is read from the environment at startup. Put the key there rather
than in this file: it is a credential for somebody else's system, this file gets
committed, and somebody approving a configuration change should not have to read
secrets to do it. A missing or empty variable stops startup, because an
unauthenticated export fails in a log nobody reads and the first sign of trouble
is a dashboard that was quietly empty for a week.

## What this is actually for

The obvious framing is "your observability tool cannot hold evidence, so add a
second thing." That is true and it is the wrong way round, because it reads as
extra work.

Here is the useful way round. **In a regulated environment, the unresolved
compliance question is what stops the observability tool being adopted at all.**
The conversation goes the same way every time: a team wants to run agents in
production, they want real observability for it, and someone in risk or audit
asks whether that platform is the system of record for what the models did.
The honest answer is no — it samples, and it keeps sixty days. At which point
the project either stalls, or the team is told to build a bespoke archive
first, or somebody buys a heavyweight "AI governance" suite that does mediocre
observability as a side effect.

None of those outcomes is good for anybody, and all three are caused by asking
one system to answer two questions it was never designed to answer together.

Separate the tiers and the objection goes away. The observability platform gets
to be excellent at observability without pretending to be a system of record,
and the compliance question is answered by something built for it. **This does
not compete with your observability vendor. It removes the reason you could not
buy one.**

## Why the split is structural

Honeycomb has written the clearest statement of this that exists, and it is
theirs rather than mine —
[Mike Terhar, September 2023](https://www.honeycomb.io/blog/infinite-retention-opentelemetry-honeycomb):

> The needs of observability workloads can sometimes be orthogonal to the needs
> of compliance workloads… Honeycomb is designed for software developers to
> quickly fix problems in production, where reducing 100% data completeness to
> 99.99% is acceptable to receive immediate answers.

That is exactly right, and it is a statement about design rather than about
roadmap. Sampling is the product — [Refinery](https://github.com/honeycombio/refinery)
exists to drop the traces you do not need. Retention is 60 days. Both are
correct choices for debugging and both are disqualifying for evidence, where
completeness is the whole claim and the obligations run from six months
(EU AI Act Art. 19) to six years (HIPAA, FINRA).

Nobody should want those choices reversed. A platform that kept everything for
seven years to satisfy an auditor would be slower and more expensive at the job
it is actually for.

| | Honeycomb | The audit log |
|---|---|---|
| Question | what is happening | what happened, and can you prove it |
| Completeness | sampled | every request, or the request is refused |
| Retention | 60 days | your obligation |
| Integrity | a vendor record | hash-chained, verifiable without the vendor |
| Content | never | redacted, behind a retention policy |

**One instrumentation point.** The gateway is already in the request path, so
neither tier needs an SDK, a wrapper, or a change to any application. The cost
of adding the evidence tier is a config block, which is the other half of why
this is not extra work.

## What is on the event

Honeycomb's model is a wide event: one rich row per unit of work, sliced
afterwards on whichever field turns out to matter. That is the shape the audit
record already had, so the span is the record minus content:

```
gen_ai.request.model            claude-sonnet
gen_ai.response.model           anthropic.claude-sonnet-4-6-20260501-v1:0
switchboard.model_id            anthropic.claude-sonnet-4-6-20260501-v1:0
switchboard.backend             bedrock
switchboard.team                search
gen_ai.usage.input_tokens       1204
gen_ai.usage.output_tokens      388
gen_ai.usage.cache_read_tokens  11402
gen_ai.usage.cache_write_tokens 0
gen_ai.tool.call_count          2
switchboard.tools.offered       [search_tickets, wire_transfer]
switchboard.tools.refused       1
gen_ai.response.finish_reason   tool_use
switchboard.policy              4f4c581392f8
switchboard.audit.id            01JB2K…
switchboard.audit.recorded      true
```

Four of those are worth their own paragraph.

**Cached tokens are separate fields.** They bill at a fraction of the input rate
— a tenth, on the Anthropic API — so a cost chart that folds them into input is
wrong by close to an order of magnitude for exactly the deployments with a large
stable system prompt. See [reconciliation.md](reconciliation.md), where the same
mistake makes a bill fail to balance.

**`switchboard.tools.refused` is its own attribute**, not something to derive by
unpacking the per-call events. This is the field somebody builds an alert on,
and a count that has to be computed from a nested list will not be. A refusal is
either an attack that was stopped or a permission somebody needs and lacks, and
a trace showing only the calls that succeeded is silent about both.

**`switchboard.audit.recorded` is false when the completion did not reach the
log.** A request that happened and was not written down is precisely the gap the
evidence tier exists to close, so it belongs in the tool people actually watch
rather than only in the tool they consult during an audit. Alert on it.

**`switchboard.policy` is the join to the rules.** An event here lives in a
backend that samples and expires; the fingerprint resolves against the
[archived configuration](change-control.md) long after the event is gone. Given
a Honeycomb event from four months ago, `switchboard audit policy -id 4f4c581392f8`
prints the exact rules it was served under, verified against its own digest.

`switchboard.audit.id` is the other join — the entry itself, in the chain, with
its content and its MAC.

## What never leaves

Prompts, completions, and tool call arguments. Not by configuration — there is
no field on the exported shapes able to carry them, and a test asserts that no
future edit adds one.

The reason is the chokepoint. Content is redacted on its way into the audit log,
and telemetry goes to a collector switchboard does not control and which has no
redaction step of its own. A span carrying an argument to `transfer_funds` would
route around the one control the whole design depends on. Tool *names* export,
because a name is metadata and is the finding; arguments are content and there
is nowhere to put them.

`include_subject` is the one identity that can be exported, and it is off by
default. On, per-person investigation happens in the tool your team already uses;
off, the export identifies nobody. It goes on spans and never on metrics, where
a label per person is unbounded and breaks the backend.

## Seeing the gap

Send both tiers for a week and compare counts. Honeycomb will be short, by
whatever Refinery dropped, and the chain will be contiguous — `switchboard audit
verify` proves nothing was removed from the middle.

That difference is not a bug in either system. It is the reason there are two,
and it is worth measuring once so that nobody later mistakes the sampled copy
for the record.
