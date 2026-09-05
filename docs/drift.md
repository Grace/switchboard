# Drift

```sh
switchboard drift
switchboard drift -period 2026-Q3
switchboard drift -strict          # for CI
```

Compares what the log shows against what the configuration approves. Today that
is the model roster: every distinct model that answered a request, set beside
the models this deployment lists.

```
MODEL        BACKEND  REQUESTS  SEEN                     STATUS
claude       bedrock  96        2026-09-01 → 2026-09-20  approved
gpt-4o-mini  bedrock  12        2026-09-18 → 2026-09-20  NOT ON ROSTER

  !  1 model answered requests and is not listed in this configuration:
     gpt-4o-mini.
  -  Approved and never called: haiku. An unused route to a provider is still
     a route; removing it is free.
```

The test is trivial to describe and almost nobody runs it, which is exactly why
it finds things. A model that answered production traffic and was never on
anyone's approved list is a finding no amount of policy documentation would have
surfaced, and the data was already recorded — this costs one command.

The window on the finding is the part that makes it actionable. An auditor's
next question after "what is that" is always "since when", and the row answers
it without anyone going back through the log.

## One name, more than one thing behind it

A comparison of *names* is blind to the change that matters most: a provider
repointing an alias, or updating a pinned name server-side. The name is
unchanged, your roster is unchanged, and something different answered.

So the record carries three model fields, and keeping them apart is the point:

| field | question it answers | who chose it |
|---|---|---|
| `model` | what the caller asked for | the caller |
| `model_id` | what this gateway sent to the provider | you |
| `provider_model` | what the provider says served it | **the provider** |

The third is the only value in the record the gateway did not choose, which is
why it is the one that can evidence a provider-side change. When a name resolves
to more than one identifier across the window, that is reported with the date
the second one appeared:

```
One name, more than one thing behind it:

  2026-09-15  claude
      claude-3-5-sonnet-20240620 → claude-3-5-sonnet-20241022 (the
      provider reported a different model)
```

That finding survives a clean roster table, which is the whole reason it exists.

A change to your *own* routing is reported too, and marked differently — that is
a record of something you did, not an observation about somebody else's system,
and an auditor treats the two differently.

## Coverage comes before conclusions

A clean comparison across a period that was never instrumented is not a pass. So
the entries that could not answer are counted:

```
  7 of 20 entries carry no resolved identifier. The earliest that does is
  2026-09-08, so anything before that is unevidenced for this control and no
  change made today recovers it.
```

If no entry carries one, the control reads **Unknown**, not met — and upgrading
starts the evidence accruing from that day, never retroactively.

## What even a resolved identifier cannot tell you

`provider_model` is what the provider *says* served the request. That is an
attestation, not a measurement. A backend change under a stable snapshot name
reports nothing at all, and no field in any log will show it.

Only a behavioural canary — a fixed prompt set on a schedule, outputs hashed,
drift alerted — observes that directly. Switchboard does not do this, and the
footer says so rather than letting a clean report imply coverage it does not
have.

The policy fingerprint is a weaker, separate signal: it covers your roster
including each entry's ids, so it moves when *you* repoint a name. It does not
move when the provider does.

## An empty roster is not an approval

A configuration listing no models produces no findings, and every row reads
`no roster` rather than `approved`. Reporting them approved would invent
assurance nobody supplied; reporting them unapproved would invent a finding for
every deployment that has not listed its models yet. Same rule as an empty
`tools.declare` in [agents.md](agents.md).
