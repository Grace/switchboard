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

## What it cannot see

**The log records the name a caller asked for, not the model id it resolved to.**
A provider repointed underneath an unchanged name — `claude` pointing at a
different `model_id` than it did last quarter — looks identical in the table
above.

That gap is closed by a different field. The policy fingerprint covers the model
roster *including each entry's id*, so a repoint moves the fingerprint even
though the name did not change. So the footer counts the distinct fingerprints
in force across the window:

```
  2 configuration fingerprints were in force across this window. The log
  records the name a caller asked for, not the model id it resolved to, so a
  provider repointed under an unchanged name looks identical above. The
  fingerprint covers the roster including its ids, so a repoint moves it —
  date one with `switchboard agents -changes`.
```

One fingerprint across the whole period means no roster change happened, and the
table is the complete answer. More than one means look, and
`switchboard agents -changes` gives the date.

What neither can tell you is *what* changed, only when. The log carries
fingerprints, not the configurations behind them; recovering the old roster
means having kept the old config.

## An empty roster is not an approval

A configuration listing no models produces no findings, and every row reads
`no roster` rather than `approved`. Reporting them approved would invent
assurance nobody supplied; reporting them unapproved would invent a finding for
every deployment that has not listed its models yet. Same rule as an empty
`tools.declare` in [agents.md](agents.md).
