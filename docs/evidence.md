# Evidence packages

`switchboard controls` describes the configuration. `switchboard audit view`
describes the traffic. An evidence package is for the case where neither is
enough on its own, because the reader is not in the room.

```
switchboard evidence -period 2026-Q3 -profile eu-ai-act
```

It writes a directory:

| file | what it is |
|---|---|
| `audit.jsonl` | the entries for the period, **byte for byte as they were written** |
| `report.html` | the same page `audit view` serves, filtered to the period |
| `controls.json` | the control assessment of the configuration in force |
| `manifest.json` | digests over all of the above, plus the chain result |
| `VERIFY.md` | how to check it without running switchboard |

and prints one digest — the SHA-256 of `manifest.json`, which covers everything
else.

## Why the entries are copied, not rendered

The MAC covers the canonical bytes of an entry. A record that has been decoded
and re-encoded is a different sequence of bytes: field order, number formatting
and string escaping are all free to change, and the digest no longer matches.
A package of pretty-printed entries would look like evidence and verify against
nothing.

So the extractor carries the original lines (`audit.WalkRaw`). A test checks the
extracted entries the way `VERIFY.md` tells a recipient to — textual
substitution of the `mac` field, then HMAC — so the shipped instructions are
covered by the suite rather than merely written down.

## The period is half-open

`-period 2026-Q3` is 2026-07-01 **up to but not including** 2026-10-01.

Quarters written as "July 1 to September 30" overlap at the boundary with
whatever the next report calls its start. One entry counted in two reports is a
discrepancy an examiner finds and you then have to explain. Closing the interval
at one end removes the question.

Accepted: `2026-Q3`, `2026-09`, `2026`, `2026-09-04`,
`2026-07-01..2026-10-01`. Everything is UTC, because the log is written in UTC
and a boundary that moved with the reader's timezone would not be evidence of
the same thing twice.

## The digest is the part you have to do

Everything inside the package is checkable against everything else inside the
package. That proves internal consistency and nothing more: a party who could
rewrite the entries could rewrite the manifest beside them.

What closes it is recording the printed digest **somewhere the package is not**,
at the time it was produced — a ticket, a mail you did not send yourself, a
register you do not control. Then a recipient comparing the digest they were
given out of band against the one they compute has a statement that survives its
author.

`switchboard` does not do this step for you today, and `VERIFY.md` says so
rather than implying otherwise.

## What a package deliberately does not prove

`VERIFY.md` § 6, generated per package so it reflects that package's actual
state:

- **Entries may have been removed from the end.** An intact prefix of a hash
  chain is itself an intact chain. Nothing inside the file can show that entries
  once followed the last one. This is the material limit, and it is closed only
  by an external anchor of the head.
- **An unsigned log catches accident, not intent.** Without
  `SWITCHBOARD_AUDIT_KEY`, recomputing a digest needs no secret.
- **The record is only as complete as the deployment made it.** Traffic that
  went straight to a provider is not in the log and cannot be.
- **A control assessment is not an audit opinion.** `controls.json` scores a
  configuration file. It is generated from live settings so it cannot flatter
  the deployment, and it names what it could not determine — but it is a
  description of settings, not a judgement about your compliance.
- **Content is redacted and partial** where it is present at all.

## Exit status

`-strict` exits non-zero if the chain is broken or any control objective came
out unmet, so a package can be produced on a schedule and a regression noticed
without anyone opening it. `unknown` deliberately does not fail: a question the
configuration could not answer is not a finding, and failing a build on it would
teach people to stop asking.
