# Agent inventory

```sh
switchboard agents
switchboard agents -period 2026-Q3
switchboard agents -json > inventory.json
switchboard agents -strict          # for CI
```

Every AI inventory in the compliance market is a form. Somebody types their
systems into a field once, and it is wrong the week after. That is not a small
problem, because an auditor reaches for the inventory *first* and a stale one
loses the scope question before a single control is discussed.

This one is derived from traffic instead of declared. It cannot be stale for
anything that actually ran, it cannot omit a system nobody registered, and it
needs no new collection — every field it reads was already in the record.

## What identifies an agent

The set of tools it offers.

Not the team, which names who pays. Not the subject, which names a person. One
person running two programs under one key is two entries here, because a program
is what runs. And the set of tool names a caller puts in front of a model turns
out to be remarkably distinctive: same names, same shape, request after request.
So it works as a fingerprint without anybody labelling anything, which matters —
a scheme that required agents to identify themselves would be exactly the
declaration this command exists to avoid trusting.

It is a fingerprint, not an identifier, and that cuts both ways:

- Two programs offering identical toolsets are one row.
- **A program whose toolset changes becomes a new row.** That is the useful
  direction. The day an agent's tools change is a day worth noticing, and here
  it shows up as an agent that stops and one that starts.

## The three findings

```
ab6ef7  3 tools  ·  40 requests  ·  $0.49
    teams   support
    called  search_tickets (40), read_account (14)
    !  1 never called: escalate

292db4  2 tools  ·  6 requests  ·  $0.08
    called   search_tickets (6)
    refused  wire_transfer (3)
    !! 1 not in tools.declare: wire_transfer
```

**Offered but never called** is authority nobody is using — least privilege,
measured rather than asserted. It is the row an auditor can act on the same day.

**Offered but never declared** is a program that changed without anyone saying
so. This is the shadow-AI finding, and it is the reason to derive the inventory
rather than collect it: nobody files a form about the thing they shipped on
Thursday.

**Declared but never offered** is a grant with no consumer, printed at the end.

A *refused* call counts as exercised, not as unused authority. The agent asked
and enforcement said no; recommending that the grant be removed would be the
opposite of the finding, and would quietly close the case on an attack.

## Traffic with no tools

Requests that offered no tools share one row, labelled and sorted last. They are
not one program — they are every program that did not use tools, and the log
cannot tell them apart. Splitting them by team would imply a distinction the
data does not support, so they are counted and not identified.

## What changed, and when

```sh
switchboard agents -changes -period 2026-Q3
```

An inventory says what is running. An examiner asks what changed — and that is
the question with money attached, because a SOC 2 Type II or an ISO 42001
surveillance audit is *entirely* about whether a control operated throughout a
period. A deployment whose agent quietly gained a payment tool in week three
looks identical, in any snapshot, to one that never changed.

```
   2026-09-01  appeared       A program offering 3 tools first called, as support.
!! 2026-09-01  appeared       A program nothing declared first called, as research.
                             It offers 2 tools the configuration does not know
                             about: summarise, web_search.
   2026-09-03  retired        Last call. Nothing from e15284 in the 2 weeks since.
!! 2026-09-14  changed        ab6ef7 gained check_balance, wire_transfer, and is
                             now ce9b54.
                             (inferred from toolset overlap, not recorded)
   2026-09-14  policy_changed The configuration in force changed: 998877665544
                             replaced a1b2c3d4e5f6.
```

Every line is derived from a field already in the record. A tool fingerprint
changing is a datable event; so is a policy fingerprint changing. Neither has to
be collected, which matters — an append-only log cannot be asked later for a
history it never wrote down.

### Succession is inferred, and says so every time

The log records two fingerprints. That they are *the same program* is a
conclusion, reached from overlapping toolsets, a shared team and one stopping
where the other starts. It requires half the toolset in common; below that the
claim stops being an inference and becomes a guess, and two honest rows beat one
invented history.

So every such line is printed with `(inferred from toolset overlap, not
recorded)`. A reader who mistakes it for an observation will defend it to an
auditor who can disprove it.

Retirement is measured against the end of the window rather than against now, so
re-running a closed quarter next year gives the same answer.

## Shadow skills

Undeclared tools are grouped by the set of agents that carry them. Tools offered
by exactly the same agents arrived together — which is what a bundle is.

```
Undeclared capability, grouped by what arrived together:

  8263bf  check_balance, wire_transfer
          carried by ce9b54, 2026-09-14 → 2026-09-20, 18 requests, 6 refused
```

Five undeclared names that always travel together are **one thing somebody
installed**, not five separate mistakes. Listing them individually would put five
rows in front of a reviewer and hide the fact that they are one decision, made
once, by one person who can be asked about it.

The grouping is deliberately not cleverer than that. A heuristic that merged
groups on partial overlap would report one skill where two were installed, and
the person being asked would correctly say the report is wrong.

`refused` is the line that decides urgency: a shadow skill that is present is a
governance gap, and one with refusals is being actively used.

## What it does not show

**This is what called, not what exists.** An inventory built from traffic is
complete with respect to traffic and silent about everything else: a program
that has not run since the log began does not appear, and neither does one whose
requests never reached this gateway. The footer says so on every run, because a
document that looks complete is worse than one that states its edges.

For the declared side of the picture — what the configuration authorises, and
whether calls are checked against it — see [tools.md](tools.md) and the **Model
agency** section of `switchboard controls`.
