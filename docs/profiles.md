# Compliance profiles

*Declaring the regime you operate under, and getting a control report for the
deployment rather than for the software.*

`docs/controls.md` describes what switchboard is capable of. It is a document
about a binary, which means it is the same document for everyone, and most of
the interesting findings in a real security review are about features that
exist and are switched off.

A profile fixes that from both ends: it makes the regime's obligations
enforceable at config load, and it makes the control report specific to your
configuration.

## Declaring a regime

```json
{ "profile": "hipaa" }
```

Three are defined: `hipaa`, `finra`, `eu-ai-act`. An unrecognised value is
rejected at load rather than ignored.

**Unset, the audit floors are advisory.** switchboard cannot know which regime
applies to you — the same binary in front of the same model is a six-month
record under the EU AI Act and a six-year record under FINRA, and nothing
observable at runtime distinguishes them. So it warns and starts.

**Set, they are assertions.** You have told it the regime applies, and a
configuration that cannot satisfy it fails in front of whoever wrote it:

```
$ switchboard serve
switchboard: switchboard.json: profile "hipaa": audit.retention is 30 days but
45 CFR §164.316(b)(2)(i) asks for at least 6 years. Raise it, or set it to 0 to
keep everything
```

That error names the authority on purpose. The person reading it at three in
the morning is usually not the person who picked the number.

## What each profile asserts

| | `hipaa` | `finra` | `eu-ai-act` |
|---|---|---|---|
| Retention floor | 6 years | 6 years | 6 months |
| Authority | 45 CFR §164.316(b)(2)(i) | SEC 17a-4(b)(4), FINRA 4511(c) | EU AI Act Art. 26 |
| `audit.enabled` | required | required | required |
| `audit.required` | required | required | required |
| Person-level identity | required — §164.312(d) | required | not asserted |
| Rules, when logging content | `us_ssn`, `email`, `phone_us` | `us_ssn`, `credit_card` | none |

Two deliberate asymmetries:

**Zero retention satisfies every floor.** Zero means keep everything, so reading
it as "shorter than six years" would reject the most conservative setting there
is. What it does require is an `archive_command` — keeping everything on one
host is a promise the disk cannot keep.

**Required rules bind only when `log_content` is on.** Metadata-only auditing
has no content to redact, and demanding rules for it would be theatre.

## The report

```
switchboard controls                    # the configured profile
switchboard controls -profile hipaa     # what a regime would say about this config
switchboard controls -json              # for an assessment deliverable
switchboard controls -strict            # non-zero exit if anything is unmet, for CI
```

Every row carries its evidence, because a status with no reason attached is the
kind of claim this command exists to avoid making:

```
  OK  Log retention  45 CFR §164.316(b)(2)(i)
      audit.retention is 7 years, above the 45 CFR §164.316(b)(2)(i) floor of 6
      years, and closed segments are archived before pruning.

  ~~  Records are protected from modification  SOC 2 CC7.2 · ISO 27001 A.8.15
      Hash-chained across segments, so alteration, deletion and reordering are
      detectable. Tail truncation is not detectable from the file alone, and a
      key holder can rewrite history. Anchor the head externally.
```

`-profile` overrides the configured regime for reporting only, so you can ask
what HIPAA would say about a deployment that has not adopted it yet. And the
report loads the config *without* the profile assertion — refusing to open the
file is the least useful possible answer to "show me my gaps."

## What a profile is not

It is not compliance, and the command will tell you so. Each profile carries a
list of its own obligations that no configuration file can evidence, and they
print at the end of every report:

```
Not switchboard's to evidence — hipaa obligations that live outside this file:
  - A Business Associate Agreement with every provider in the path. Bedrock is
    HIPAA-eligible under the AWS BAA, accepted through AWS Artifact;
    eligibility is not compliance and the BAA is not switchboard's to sign.
  - PHI described in prose. Redaction is pattern-based: it catches structured
    identifiers and will not catch a diagnosis, a name, or a date of birth
    written into a clinical narrative. ...
```

The deeper limit is that a config file is a statement of intent. It shows that
redaction rules are declared, not that they match your data; that an archive
command is set, not that the bucket it writes to is immutable. Rows depending
on facts outside the file say so rather than counting themselves met.

**The regulatory table is a starting point, not an opinion.** Every citation
here — the floors especially — needs a lawyer's eyes before it goes in front of
a client or an auditor. The code enforces what the table says. Whether the table
is right about your obligations is a question for someone qualified to answer
it.
