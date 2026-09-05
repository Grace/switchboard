# Assessing someone else's deployment

`switchboard controls` describes a switchboard config. The adapters describe
somebody else's gateway, using the same control objectives and the same
three-state scoring.

That is the more useful product, because almost nobody will replace a gateway to
find out whether their current one is defensible.

```
switchboard controls -databricks endpoint.json -profile hipaa
switchboard controls -aws ./bedrock-export -profile finra
switchboard controls -aws ./bedrock-export -redteam promptfoo-results.json -json
```

## Exports, not credentials

Every adapter reads output the customer already has permission to produce.
Nothing here authenticates to anything.

That is a commercial decision as much as a technical one. An assessment tool
that wants production access is a six-week security review before you can start;
one that reads four JSON files is an email. It also means there is never any
ambiguity about what the tool did in someone else's account: it read files.

## AWS Bedrock

`scripts/aws-export.sh` runs all of this for you and puts the result where
`-aws` expects it:

```sh
./scripts/aws-export.sh ./bedrock-export
switchboard controls -aws ./bedrock-export
```

Every call it makes is a GET; it creates and changes nothing. It also does the
one step the recipe below leaves to you — the log bucket is named inside the
logging configuration, so it takes the name from there rather than asking — and
it fetches each guardrail individually, because the list form carries only
summaries and the PII actions that decide the redaction rows come back only
from `get-guardrail`.

Where a call fails it writes a note saying the answer is **unknown** rather than
absent, and names the IAM permission to re-run with. That distinction is the
same one the report is built on: a control nobody could ask about is not a
control that is switched off.

## By hand

Four commands. Put the output in a directory and point `-aws` at it — files are
recognised by shape, not by name, and anything unrecognised is named in the
report rather than silently skipped.

```sh
mkdir bedrock-export && cd bedrock-export

aws bedrock get-model-invocation-logging-configuration --output json > logging.json
aws bedrock list-guardrails --output json                             > guardrails.json
aws cloudtrail describe-trails --output json                          > cloudtrail.json

# The bucket name comes from logging.json, s3Config.bucketName:
aws s3api get-object-lock-configuration --bucket <that-bucket> --output json > objectlock.json
```

Three rows are worth understanding before you read a report.

**Object Lock decides tamper-evidence, and the mode decides it honestly.**
COMPLIANCE mode scores as tamper-evident: for the retention period no principal,
including the account root, can delete or overwrite a log object. That is a real
control and it would be dishonest to withhold credit for it because it works
differently from a hash chain — though the report says which it is, since
immutability *prevents* an edit while a chain *reveals* one, and neither covers
what happened before the object was written. GOVERNANCE mode scores as not
tamper-evident, because `s3:BypassGovernanceRetention` overrides it: it protects
against accident, not intent.

**A guardrail is not a chokepoint.** Databricks applies AI Gateway guardrails to
everything through the endpoint. Bedrock applies a guardrail when the caller
names one in the request, so an application that omits the parameter is
unfiltered. Redaction therefore scores unbypassable-*unknown*, with a caveat
naming what to go and ask for: an IAM policy denying `bedrock:InvokeModel`
without a guardrail identifier is what turns the convention into a control, and
no export can show it.

**CloudTrail validation is a real hash chain over the wrong record.** Log file
validation detects an altered or deleted trail file. It covers API calls — that
`InvokeModel` happened, under which principal, when. It says nothing about what
was sent or returned, and gives the invocation log no protection at all.
Crediting the record with it is the easiest mistake available, so the adapter
reports the two separately and says so.

Also unknown from these exports, and named as questions rather than findings:
whether applications invoke under distinct IAM principals (spend is
unattributable if they share one role), whether an invocation is refused when
its log cannot be delivered, whether FIPS endpoints are in use, and what bounds
one caller's consumption.

## Databricks

```sh
databricks serving-endpoints get <name> -o json > endpoint.json
switchboard controls -databricks endpoint.json
```

## What the adapters will not do

They will not report a control as unmet because an export was absent. A missing
file yields *unknown*, which is a question for the operator; scoring it as a
failure invents a finding, and one invented finding is all it takes for a
customer to stop reading the report.

They are written against published shapes rather than schemas verified against
live accounts, and both vendors will drift. Verify a row against the real system
before putting it in front of anybody.

## What is not an adapter

**LangChain and LangGraph** have nothing to read. Providers, callbacks and tool
bindings are configured in application code, so assessing one means static
analysis of Python rather than parsing an export — a different and much worse
business. LangChain applications are *callers*: point one at switchboard with a
`base_url` change and the record exists.

**LangSmith, Langfuse, Helicone and Arize** are trace sinks, not control points.
They enforce nothing, so there is no control surface to assess. They are also
better at what they do — reading an agent trace to work out why it behaved that
way is their job and they are built for it. The difference is the audience:
those answer *why did my agent do that* for a developer, and this answers *prove
what your agent did* for somebody who does not trust you.
