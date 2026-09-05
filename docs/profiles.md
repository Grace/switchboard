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

Five are defined: `hipaa`, `finra`, `eu-ai-act`, `nist-800-171`,
`fedramp-moderate`. An unrecognised value is rejected at load rather than
ignored.

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

| | `hipaa` | `finra` | `eu-ai-act` | `nist-800-171` | `fedramp-moderate` |
|---|---|---|---|---|---|
| Retention floor | 6 years | 6 years | 6 months | 1 year † | 1 year † |
| Authority | 45 CFR §164.316(b)(2)(i) | SEC 17a-4(b)(4), FINRA 4511(c) | EU AI Act Art. 26 | 800-171 3.3.1 | 800-53 AU-11 |
| `audit.enabled` | required | required | required | required | required |
| `audit.required` | required | required | required | required | required |
| Person-level identity | required | required | not asserted | required | required |
| TLS, loopback included | not asserted | not asserted | not asserted | **required** | **required** |
| FIPS 140-3 mode | not asserted | not asserted | not asserted | **required** | **required** |
| Rules, when logging content | `us_ssn`, `email`, `phone_us` | `us_ssn`, `credit_card` | none | `us_ssn`, `email` | `us_ssn`, `email` |

† **A switchboard default, not a statute.** 800-53 AU-11 and 800-171 3.3.1 both
leave the retention period organization-defined — unlike HIPAA and FINRA, there
is no federal number to enforce. One year sits above the FedRAMP baseline
parameter and well above the 90 days DFARS 252.204-7012 requires media be
preserved after an incident report. Reports say so on the row rather than
presenting it as regulatory. Set your own if your SSP says otherwise; the point
is that the value should be a decision somebody made.

Two deliberate asymmetries:

**Zero retention satisfies every floor.** Zero means keep everything, so reading
it as "shorter than six years" would reject the most conservative setting there
is. What it does require is an `archive_command` — keeping everything on one
host is a promise the disk cannot keep.

**Required rules bind only when `log_content` is on.** Metadata-only auditing
has no content to redact, and demanding rules for it would be theatre.

**The government profiles refuse a plaintext listener, loopback included.**
Everywhere else switchboard allows it, because a bind that cannot leave the host
is a reasonable default. SC-8 and 3.13.8 are about the channel, and an assessor
reads a config rather than a routing table.

## FIPS 140-3

`nist-800-171` and `fedramp-moderate` require the process to be running under
the FIPS 140-3 Go Cryptographic Module, which Go ships natively from 1.24 —
module v1.0.0, CMVP certificate #5247.

Two ways in, and they are not the same thing:

```
# Build against the validated module. This also turns the mode ON by default,
# so a binary built this way needs no runtime flag.
GOFIPS140=v1.0.0 go build ./cmd/switchboard

# Or enable the mode on a normally-built binary, using the module already in
# the standard library tree.
GODEBUG=fips140=on switchboard serve

# Either way, "only" is the strict setting: non-approved algorithms return
# errors or panic rather than quietly falling back.
GODEBUG=fips140=only switchboard serve
```

Ship the `GOFIPS140` build for customers under these regimes — it makes
validated crypto a property of the artifact rather than of whether somebody
remembered an environment variable.

This is the one assertion that is a property of the binary rather than of the
config file, which is exactly why it is enforced here. A configuration correct
in every other respect, running on a build with non-validated cryptography, is
the failure most likely to survive all the way to an assessor. `switchboard
controls` reports it as a row like any other, via `crypto/fips140.Enabled()`.

Under a profile that does not ask for FIPS, the row reports as *not addressed*
rather than as a gap — it is a fact worth stating, not a finding.

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

## A note on FedRAMP

switchboard is not FedRAMP authorized, and does not need to be. FedRAMP
authorizes **cloud service offerings**. This is a self-hosted static binary that
runs inside an authorization boundary you already have, inheriting its controls
rather than establishing new ones.

Practically: there is no third-party ATO to wait on, and no vendor in your data
path to assess. A hosted gateway has to bring its own authorization, which is a
multi-year process; a binary does not.

That argument only works if your SSP makes it. The control rows are evidence for
an implementation statement — writing that statement, and having it assessed, is
yours.

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
