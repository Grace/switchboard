# Tool enforcement

Everything else in switchboard records what happened. This is one of the few
places that stops something — and it stops the thing a completion log is worst
at showing. Not a bad answer, but an action. A model talked into calling a tool
it was never meant to reach is the failure that leaves money moved rather than a
sentence written.

```json
{
  "tools": {
    "enabled": true,
    "declare": {
      "lookup_account":  { "bundle": "billing", "scopes": ["customer_pii"] },
      "post_adjustment": { "bundle": "billing", "scopes": ["ledger"] },
      "email_customer":  { "bundle": "support", "scopes": ["customer_pii"], "egress": true }
    },
    "grants": {
      "billing": { "tools": ["lookup_account", "post_adjustment"],
                   "scopes": ["customer_pii", "ledger"] },
      "support": { "tools": ["lookup_account", "email_customer"],
                   "scopes": ["customer_pii"], "egress": true }
    },
    "default": {}
  }
}
```

A call outside a caller's envelope is **refused and recorded**. The request
fails with `403 tool_not_permitted`.

## Nothing is open by default

An undeclared tool is refused, and a team with no grant gets `default`, whose
zero value authorises nothing. A deployment that has said nothing about a tool
has not authorised it, and a default-open list would make every declaration
optional.

`tools.enabled` is off by default, which is a different thing: with it off,
calls are recorded and not judged. That is the honest state of a deployment
that has not declared anything yet, and a better default than refusing
everything on first start.

A grant naming a tool nobody declared is a load error. It reads as an
authorisation, grants nothing, and would silently start granting the day
somebody declared that name.

## What this borrows, and what it does not

The idea is from Shen et al., [*Sealing the Audit-Runtime Gap for LLM
Skills*](https://arxiv.org/abs/2605.05274), which computes a permission
envelope over everything loaded into an agent's context so that a permission
held by one loaded source cannot silently become available to the whole context.

Their construction anchors manifests on an on-chain registry vetted by a staked
DAO audit committee. None of that is here, and none of it is what makes the idea
work — the paper itself notes the registry is "conceptually a tamper-evident
storage abstraction" instantiable over "blockchains and append-only databases",
and switchboard already has the second. What is taken is the permission algebra.
What is left is the token economics.

**Their intersection is deliberately not implemented**, and the reason matters
more than the feature. `T∩ = ⋂Tᵢ` intersects over *skills*, each declaring its
own tool set, and it works because their loader can stop and ask a person to
authorise everything in the difference. A gateway has nobody to ask, and a
completion request carries a flat list of tool names rather than skills — so a
name belongs to one declared source, the intersection across two sources is
empty, and a faithful port would refuse every call the moment a second bundle
appeared. That is not a strict control. It is a broken one, and it would be
switched off within a day.

What survives is their single-source check (Eq. 2, `declared ⊆ authorised`),
which is most of the value, plus one rule below that reaches for the same
property without the degenerate behaviour.

## The cross-bundle egress rule

Bundles group tools that ship together. When a request loads tools from **more
than one** bundle, a tool that can send data outside is refused unless the
caller holds `cross_bundle_egress`.

That is the shape of the attack the intersection was aimed at: read customer
data with one source, send it with another, each call individually permitted and
the composition the harm. Refusing that combination stops it without refusing
the ordinary calls that are fine.

`cross_bundle_egress` requires `egress` — it widens egress rather than replacing
it, and setting it alone is a load error rather than a silent no-op.

## Streaming is weaker, and says so

Enforcement is on the response, not the request: offering a tool is not using
one, and refusing a request because it made something available would break
applications that offer a broad toolset and use a narrow part of it. What is
refused is the action. The cost is that tokens are already spent when a call is
refused, which is the right trade — the thing being prevented is the action, not
the expense.

On a **streaming** request that trade gets worse. Tool-call deltas are forwarded
as the backend produces them, so by the time a call is complete enough to check,
a client assembling deltas has already seen it. switchboard refuses to send the
frame that completes the call, emits `tool_not_permitted`, and writes the
refusal down — which stops a client that waits for the finish reason and does
not stop one that acts on deltas.

**A deployment that needs this to be a control rather than a signal should not
offer tools on streaming requests.**

## Refusals are the entries worth having

A refused call is recorded with `refused: true` and the reason. It is the most
valuable thing this log can hold: the moment a model asked for something it was
not permitted is either an attack that was stopped or a permission somebody
needs and does not have, and both are findings. A log recording only successful
calls would be silent about exactly the events it exists for.

## In the control report

Enforcement that no reviewer can point at is not evidence yet, so `switchboard
controls` grows a **Model agency** section with two rows:

    Model agency
      OK  Tool calls are authorised before they take effect   NIST 800-53 AC-6 · SOC 2 CC6.3 · ISO 27001 A.8.2
      OK  Tool calls and refusals are recorded                NIST 800-53 AU-3 · SOC 2 CC7.2 · EU AI Act Art. 12

The evidence line is generated from the configuration in force — how many tools
are declared, across how many bundles, how many of them can send data outside,
how many teams hold grants, and what a caller with no grant may do. It cannot
flatter the deployment, because it is a rendering of it.

The met row states the streaming limit in the row itself rather than in a
footnote. A reviewer reads the row and stops, and this is the one row in the
report that claims an action was *prevented*; overstating it is worse than not
having it.

Three states, deliberately:

- `tools.enabled` on → **met**, with the counts above.
- `tools.enabled` off → **unmet**. switchboard forwards tools whether or not it
  bounds them, so "we have not configured this" is a gap, not a silence.
- A foreign deployment → **unknown**, with a caveat naming what to go and ask
  for. An endpoint export describes a route to a model, not the agent behind it;
  answering `no` there would invent a finding.

## What this does not do

It checks calls one at a time against a declared envelope. It does not reason
about **sequences** — two calls, both permitted, whose order and composition
constitute the harm. The paper is explicit about the same limit: its evaluation
"supports only a permission-level mitigation claim; it does not establish
defense against semantic collusion through shared context, outputs, naming
conventions, or data formats."

Closing that needs information-flow tracking across a conversation rather than a
permission check per call. The record now carries what such a thing would read —
every call, in order, grouped by conversation — which is the prerequisite, not
the feature.
