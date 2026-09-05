# Assurance evidence

Two rows in an assessment cannot be answered by reading a configuration file:
whether the deployment has been adversarially tested, and whether content is
filtered at the boundary. They are obligations under EU AI Act Art. 15, MITRE
ATLAS AML.M0015 and NIST 800-53 CA-8, and no gateway config evidences either.

They default to **unknown**, which is the point. A report that omitted them
because no tool reported on them would look complete and would not be.

## Attaching a red-team run

```
switchboard controls -redteam promptfoo-results.json
switchboard controls -databricks endpoint.json -redteam promptfoo-results.json
```

Before:

```
  ??  The deployment has been adversarially tested
      Nothing attached to this switchboard assessment shows adversarial testing
      results. garak, promptfoo, PyRIT and Giskard all produce them; attach the
      output rather than leaving the obligation blank.
```

After:

```
  OK  The deployment has been adversarially tested
      Adversarial testing: promptfoo 3, 2026-08-14 (22 days ago): 44 of 47
      assertions passed, 3 failed.
```

The difference is not the status. It is that the second row names a tool, a
version, a date and a failure count — things a reviewer can check, argue with,
or ask for the detail of. `Yes` on its own is a claim somebody made.

Evidence attaches to the **deployment**, not to the report, so the same file
evidences a switchboard config and somebody else's Databricks endpoint
identically. The testing was of a deployment, not of a config format.

## Failures do not flip the status

A run with failures still marks the row met. The objective is that the
deployment *has been* adversarially tested, and it has been. What the testing
found belongs in the evidence sentence, where a reviewer reads it, rather than
collapsed into a status that cannot carry it — and a rule that punished testing
for finding something would teach people not to attach the report.

## Age is always stated

The sentence always says when the run happened, because that is a reviewer's
first question and a sentence that omits it reads as an attempt not to answer.
Past a year the wording changes to say the report is *a record of testing rather
than current assurance*.

That threshold is a switchboard default, not a rule from any regime. Regimes
expect testing to be periodic without agreeing on a period, so the report states
the age and lets the reviewer judge rather than silently scoring a two-year-old
run as current.

An undated report says `at an unrecorded time`. A report with no assertions says
so, because it evidences that a tool ran and nothing about what it found.

## Only promptfoo, deliberately

`-redteam` reads promptfoo JSON. Handed a garak or PyRIT report it refuses, and
names what it looked for:

```
no promptfoo statistics found: looked for results.stats and stats, each carrying
successes/failures. If this is a garak or PyRIT report, switchboard cannot read
it yet — it declines rather than guess at a format it has not been written
against
```

A parser written against a format nobody verified produces confident misreadings
of somebody's security evidence, which is worse than declining to read it.
Adding garak means obtaining a real report and writing the parser against it.

promptfoo's own output shape has moved between versions, so both the current
`results.stats` and the older top-level `stats` are accepted, and a `version`
field is read whether it arrives as a string or a number. What it will not do is
default: a document with no recognisable statistics is an error, because the
alternative is reporting a deployment as tested on the strength of a file that
might be anything.

## Content policy

`ContentPolicy` has no ingest yet. Declining to filter is a defensible position
— a gateway is well placed to bound what a model may *do* and badly placed to
guess what an input *means* — so `No` scores as *not addressed* rather than
unmet, with the structural controls named as the mitigation. If your regime
expects semantic filtering, that row is a gap and says so.
