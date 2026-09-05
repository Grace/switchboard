# Reconciliation

*Setting the log against the provider's own account of the same events.*

```sh
switchboard reconcile -invoice cur-2026-q3.csv -period 2026-Q3
switchboard reconcile -invoice invoice.csv -strict        # for CI
```

Every other check in switchboard reads the log against the configuration. Both
of those are ours. If the gateway is wrong about what it did, they agree with
each other and are wrong together.

This one reads the log against a document produced by the company you buy
inference from — the only record of these events that nobody in your
organisation can edit. That is the whole reason it is worth running, and it is
why an examiner reaches for it: agreement is evidence rather than assertion.

## What a disagreement means

**Tokens on the bill that the log cannot account for.** Either traffic reached
the provider without passing through this gateway, or entries are missing from
the record. The first is the one that matters, because a route around the
gateway is a route around every control attached to it — the redaction, the tool
grants, the limits, the log. This is shadow AI found from the outside, and no
amount of reading your own logs produces it.

**Tokens the log holds and the bill does not.** The gateway believes it sent
work the provider did not charge for. Less alarming and rarely nothing.

Both are findings. The report names which direction it is, in those words.

## Tokens, not requests

The obvious form of this test — compare request counts — is not answerable
against AWS, and switchboard says so rather than approximating it. A Cost and
Usage Report carries no per-request line item and no request id; it aggregates
by usage type over an hour or a day. Tokens are the quantity both sides
actually hold.

**All four token types are compared**, because that is how providers bill:
input, output, cache write and cache read, at four different unit prices. A
reconciliation that sums input and output alone undercounts anything using a
prompt cache, which is most deployments worth having — and it fails in the
direction that looks like a pass.

## Names are mapped, never guessed

AWS bills `Claude4.6Sonnet` for what this gateway invoked as
`anthropic.claude-sonnet-4-6-20260501-v1:0` under the local name
`claude-sonnet`. The resemblance is obvious to a person and worth nothing to a
program, so it is declared:

```json
{
  "reconciliation": {
    "models": {
      "Claude4.6Sonnet": "claude-sonnet",
      "Claude4.5Haiku":  "claude-haiku"
    }
  }
}
```

Several billing names may map to one model: a bill separates in-region from
cross-region routing and one service tier from another, and those are the same
model answering.

The cost of guessing is asymmetric, which is why there is no fuzzy matching. An
unmapped line produces a question somebody answers. A wrongly matched one
produces a reconciliation that balances between two different models, and nobody
goes looking to disprove a clean report. Where a name resembles a configured
model the report says so, as a suggestion, and does not act on it.

**An unmapped line is not a finding.** It is the question that comes before one:
either a mapping nobody wrote down, or a model running in this account that
never passed through the gateway. Only a person can say which, and reporting it
either way would invent the answer. Under `-strict` it fails the run, because a
comparison that silently skipped eight million tokens is not a pass.

## Getting the invoice out

```sh
./scripts/aws-invoice.sh 2026-07 2026-09
switchboard reconcile -invoice ./bedrock-invoice.csv -period 2026-07-01..2026-10-01
```

The script is all GETs. It reads Cost Explorer month by month, writes the usage
types out verbatim — switchboard already parses them, and a second parser is a
second place to be wrong about which suffix means a cache read — and keeps a
notes file distinguishing *asked and there was none* from *could not ask*. Read
that file first. A month the export could not read is not a month with no usage.

Cost Explorer charges $0.01 per request, so a year is twelve cents. It is the
one command in this repository that is not free.

**A CUR 2.0 export is the better source** and needs a Data Export configured,
which is a day's wait the first time. Pass the CUR CSV directly; both the
`line_item_usage_type` and legacy `lineItem/UsageType` spellings are read.

## Any other provider

The reconciler reads a four-column CSV, so a provider with no adapter needs a
spreadsheet and not a program:

```csv
month,model,kind,tokens,cost,currency,team
2026-08,Claude4.6Sonnet,input,12400112,186.00,USD,search
2026-08,Claude4.6Sonnet,cache_read,41000000,6.15,USD,search
```

`kind` is `input`, `output`, `cache_write` or `cache_read`. `cost`, `currency`
and `team` are optional — and an absent cost column is read as *not reported*,
not as zero.

## Whether the bill splits by team

This is the check [cost-attribution.md](cost-attribution.md) asks for and cannot
make on its own. switchboard assumes a role per caller and tags the session;
whether AWS then bills the way that expects is not observable from this side of
the call. It needs the bill.

Where the export carries an attribution tag, the report draws the same
comparison per team. **A team the log knows and the bill does not is the
signature of the three failures that document names**, in the order they usually
turn out to be: the role's trust policy allows `sts:AssumeRole` and not
`sts:TagSession`, so the tag is silently absent; the tag was never activated
under Billing → Cost allocation tags; or the bill was pulled inside the 24–48
hour lag.

The wording differs from the model findings on purpose. Tokens missing from a
model's row may never have passed through the gateway. Tokens missing from a
*team's* row are almost always on the bill, charged to somebody else — usually
the gateway's own role, which is what an untagged session looks like. Where the
model totals reconcile and the team split does not, the report says so
explicitly: that is a split landing in the wrong place, not traffic that went
missing, and sending somebody to hunt for an application that does not exist is
the whole cost of getting it wrong.

Cost Explorer cannot group by IAM principal or session tag — that data exists
only in CUR 2.0 — so the script's output reports the team split as **unknown**
rather than absent.

## What it will not report as a finding

Four cases, each of which a cruder tool reports as traffic going missing:

- **A month at the edge of the log's coverage.** Marked `~`. More than a day of
  it falls outside what the log holds, so a shortfall is expected. A log covering
  a whole January still begins a few minutes after midnight on the first, and
  that is a clock rather than a gap.
- **A month the invoice says nothing at all about.** An export that stopped short
  and a provider that billed nothing look identical from here, so it is reported
  once, as a question, rather than as a never-billed finding against every model
  in it.
- **A month on the invoice the log was not read for.** Comparing it would report
  your own `-period` as a finding.
- **Every month off by the same round factor.** A bill drawn in thousands of
  tokens against a log counting tokens disagrees by a thousand in every row at
  once. That is a unit, not a gap; the report says so ahead of the findings and
  names the `-scale` to re-run with. One month off by a thousand is still a
  finding — only all of them at once is a convention.

**Local models are excluded**, and counted. Nothing bills for a model on your
own machine, so including it would produce a permanent shortfall that is true
and means nothing.

**Entries recording no backend are kept.** They were written before the field
existed and say nothing about where they went; dropping them on a guess would
hide exactly the traffic this looks for.

## What it does not compare

**Money.** One model bills at different unit prices by service tier and by
cross-region routing, so the rate card in [pricing.md](pricing.md) prices the log
and does not reproduce the bill. The invoice is the authority on what is owed;
this compares the usage behind it.

**Rows that are not inference.** Guardrail charges, storage and evaluations
carry cost and no tokens. They are counted as skipped and named, so a clean
comparison does not read as a full account of the bill.

## Tolerance

Default 1%. Exact agreement never happens, and a report that fires every month
is one nobody reads: a request beginning at 23:59:58 is logged in one month and
may be billed in the next, an abandoned stream leaves a partial count, and CUR
aggregates and rounds. All of that is fractions of a percent on real volume. One
unlogged application is tens of percent, not one.

`-tolerance 0` compares exactly, and will fire.
