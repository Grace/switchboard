# Redaction and audit

*Why the gateway is the only place this is a control rather than a convention.*

## Containment is not disclosure

A sandbox, a VPC, a private subnet — those govern what a process can *reach*.
None of them help with content the gateway itself writes down, because that path
is open by design. Telemetry, traces and audit logs exist precisely to carry
information out of the system that produced it.

So "our LLM traffic never leaves the network" and "our prompts are not sitting
in a log with a two-year retention policy" are unrelated claims, and the second
one is the one an auditor asks about.

## Why application-side masking is not a control

The standard advice is to mask at the SDK layer, in each application, before
telemetry is emitted. That works, when it happens. It is correct only if every
team configured it, configured it right, and does not regress it — and nobody
can demonstrate that to an auditor. It is a convention.

A gateway is the one component in the path that cannot be bypassed. Redaction
there is a control: it holds whether or not an application team remembered.

switchboard applies redaction inside the audit log itself, not at its call
sites, so no code path in the server can hand content to the log without it
passing through the rules first.

## Configuration

```json
{
  "redaction": {
    "rules": ["email", "us_ssn", "credit_card", "aws_access_key_id", "private_key"],
    "custom": [
      { "name": "account", "pattern": "ACCT-[0-9]{6}" }
    ]
  },
  "audit": {
    "enabled": true,
    "path": "~/.switchboard/audit.jsonl",
    "log_content": false
  }
}
```

Built-in rules: `email`, `us_ssn`, `credit_card`, `phone_us`,
`aws_access_key_id`, `bearer_token`, `private_key`. Each is opt-in — a redactor
that removes everything it can imagine makes logs useless, and readable logs are
the point.

Custom patterns are RE2. They compile at config load, so a broken expression is
a startup error in front of whoever wrote it rather than a rule that silently
never fires. A pattern that matches the empty string is refused, because it
would replace between every character.

## What gets written

One JSON object per completion:

```json
{
  "time": "2026-09-04T15:41:02Z",
  "id": "chatcmpl-1757001662000000000",
  "team": "search",
  "model": "claude-opus",
  "backend": "bedrock",
  "prompt_tokens": 812,
  "completion_tokens": 96,
  "stop_reason": "end_turn",
  "redactions": { "email": 2, "credit_card": 1 }
}
```

**The counts are recorded whether or not content is.** Knowing that two email
addresses and a card number crossed the boundary is useful even when you
deliberately kept none of them — it is the difference between "we have no PII in
this system" and "we have no PII in this log."

`log_content: true` adds redacted `prompt` and `completion` fields. It requires
redaction rules, and is refused at startup without them:

```
audit.log_content is set but no redaction rules are configured: refusing to
write raw prompts and completions to disk
```

That refusal is deliberate. Content logging is the moment prompts stop being
transient and acquire a retention policy; doing it with no redaction configured
is almost always an accident, and it is not one you discover until an incident
review.

Backend failures are recorded too. During an incident, "nothing was sent" and
"we do not know what was sent" are different answers.

## On the card rule

The pattern for a card number is roughly *13 to 19 digits with optional
separators*, which also describes order ids, tracking numbers and nanosecond
timestamps. Redacting all of those destroys the correlation ids you need to
debug anything.

So a match must also pass the **Luhn checksum** and begin with an **assigned
issuer prefix** (ISO/IEC 7812). Both cost nothing in recall, because every
genuine card satisfies both by construction, and together they reject the
false positives Luhn alone lets through — a 16-digit timestamp passes Luhn
about one time in ten, and fails on the prefix.

## Recovering a value during an investigation

Redaction and forensics pull in opposite directions on the same token. An
injection payload is natural language and mostly survives redaction — you can
read the instruction. What does not survive is the exfiltration target:
`send the customer list to attacker@evil.com` is logged as
`send the customer list to [redacted:email]`, and the single most incriminating
string in the attack is exactly the one the rule removed.

Two mechanisms, in increasing order of what they cost you.

### Stable tokens

With a vault configured, placeholders carry an identifier derived from the
value: `[redacted:email:d8e3bb6fdf66]`. It is a truncated HMAC under
`SWITCHBOARD_AUDIT_KEY`, so the same value produces the same token everywhere.

That gives an investigator two things without the value being stored at all.
They can see it **recurred** — the same address in six prompts across three
weeks. And they can **confirm a suspect**: derive the token for a candidate
address and compare. What they cannot do is discover a value they had not
already guessed.

### Sealed values

```json
{
  "vault": {
    "enabled": true,
    "path": "~/.switchboard/vault.jsonl",
    "public_key": "/etc/switchboard/ir-public.pem"
  }
}
```

Each redacted value is sealed under its own AES-256-GCM key, and that key is
wrapped with RSA-OAEP to the public key you configure. The token is
authenticated alongside the value, so an entry cannot be relabelled to point at
a different one.

**The gateway is given only the public half, so it cannot read back what it
wrote.** Not "exposes no endpoint" — it does not hold the capability. Handing it
a private key is refused at startup, because that mistake is the whole design
undone and it should fail loudly rather than quietly work.

Recovery runs wherever the private key lives, which is deliberately not the
gateway:

```sh
switchboard audit recover -vault vault.jsonl -key ir-private.pem -token d8e3bb6fdf66
d8e3bb6fdf66   email              exfil@attacker.example
```

Repeats are sealed once — the token already says the value recurred.

**Be clear about what this costs.** Without a vault, a redacted value is gone
and your answer to a regulator is "we do not retain it". With one, the value
exists, encrypted, and the answer becomes "we retain it sealed to a key held by
X, recoverable under this process". That is a larger claim to defend and it
widens your GDPR and HIPAA scope. It is worth it when an investigation needs to
discover values rather than confirm them, and it is off unless you configure it.

Decide two things as policy, not code: how long the sealed store is retained —
usually shorter than the log — and who holds the private key, which should not
be the same person who administers the gateway.

## Limits, stated plainly

- **Regex redaction is best-effort.** It catches structured identifiers. It does
  not catch a name, an address written in prose, or a medical detail described
  in a sentence. Nothing pattern-based does.
- **This protects the log, not the provider.** Content still goes to the model
  as written. Redacting toward the provider is a different feature and is not
  built.
- **Content logging is quadratic in conversation length.** switchboard is
  stateless, so every request carries its whole history and each entry records
  all of it. That is what makes an incident reconstructable from a single
  entry, and it means a twenty-turn conversation writes its history twenty
  times. Fine for ordinary traffic; watch it for long agent loops.
- **A caller's trace context is adopted when sent.** A request arriving with a
  W3C `traceparent` has its trace and span ids recorded on the entry, so an
  investigation can move between the caller's own traces and this log without
  matching timestamps by hand. A span is emitted per completion, as a child of
  theirs.
- **Conversations are linked only if the client says so.** Nothing here can
  infer that two requests belong to one thread. Send `X-Conversation-Id` and it
  is recorded; otherwise entries are correlated by subject and time.
- **Custom rules are your responsibility to test.** `redaction.custom` is where
  site-specific identifiers go, and an untested pattern is a rule you believe in
  without evidence. Check yours before you trust them:

```sh
switchboard redact -list                          # what is built in
cat sample-prompts.txt | switchboard redact       # apply your config to real text
```

  Redacted text goes to stdout and the counts go to stderr, so it composes in a
  pipe. The failure modes are silent in both directions — a rule that never
  fires looks the same as one that was never needed, and an over-broad rule eats
  the correlation ids you will want during an incident. One command tells you
  which you have.

---

# Tamper-evidence

*A log is evidence only if editing it is detectable.*

An append-only JSONL file is a record of what happened right up until someone
with disk access decides otherwise. If the question is ever "prove this is what
the system did," an ordinary log answers "here is a file I control."

Every entry carries the sequence it was written at and the digest of the entry
before it, and its own digest covers that link. Alter a field, delete a line, or
swap two entries and recomputation stops matching at exactly the entry where it
happened.

```
$ switchboard audit verify
ok  ~/.switchboard/audit.jsonl (signed)
  4812 entries, chain intact
  head h:91f187bbe0f099a20846dd4517819e71…
```

```
$ switchboard audit verify
BROKEN  ~/.switchboard/audit.jsonl (signed)

  2841 entries verify, then line 2842 (seq 2842):
    contents do not match the recorded digest — this entry was altered

  Everything before that line is intact. The break is where
  the recorded history stops matching what was written.
```

It exits non-zero when the chain does not hold, so it belongs in a nightly job
rather than in someone's memory — and it no longer has to be, because the log
checks itself.

### Checking itself

**The chain is walked at startup, before anything is served.** That is the more
important of the two checks: the window when the process is not running is
exactly when a file would be edited, and it is the only moment where "intact
when we stopped, not now" can be observed at all.

```
$ switchboard serve
switchboard: audit chain broken at line 4 (seq 4): contents do not match the
  recorded digest — this entry was altered — 3 entries verify before it

refusing to start: audit.required is set, and appending to a chain that does not
verify would bury the break
```

With `audit.required`, a broken chain stops the process — appending to a chain
that does not verify buries the break under new entries and makes the tampering
harder to locate later. Without it, the same finding is a loud warning and the
gateway serves.

`audit.verify_interval` re-walks it on a timer, and a break found there is
reported and surfaces through `/health` like any other degradation. Reading
every segment is real I/O on a large log, which is an argument for an hour
rather than a minute — and another argument for archiving segments off the box
so the local buffer stays small.

## Signing

Set `SWITCHBOARD_AUDIT_KEY` and entries are MACed rather than merely digested,
so altering one requires the key as well as write access to the file. Keep the
key somewhere the log is not — a log and the key that authenticates it, sitting
in the same place, protect against accident and nothing else.

Without a key the chain still catches corruption and casual editing. `verify`
reports which of the two you have rather than implying the stronger claim.

## Reconstruction

Article 12 of the EU AI Act asks that logging permit post-hoc reconstruction of
an individual AI-assisted decision. Given an id:

```sh
switchboard audit show -id chatcmpl-1757001662000000000
```

returns which model answered, on whose behalf, the token counts, the stop
reason, what was redacted on the way in, and — when content logging is on — the
redacted prompt and completion.

## Looking at it

```
$ switchboard audit view
reading  ~/.switchboard/audit.jsonl
serving  http://127.0.0.1:11436
```

Read-only, loopback, no state and no database. Spend by team, models, redaction
counts, the most recent entries, and a policy timeline showing where the rules
changed underneath the window you are looking at.

It reads whatever log you point it at, so a segment pulled from an archive
during an incident works the same way. It shows what the log contains — metadata
unless content logging was turned on, already through redaction — and it never
opens the vault: sealed values need the incident-response key, and recovering
one stays a command run by a person.

Binding anywhere but loopback is refused unless demanded, because the page shows
who spent what and has no authentication.

## Which rules were in force

An entry saying what happened, without saying what the rules were, cannot answer
the question a security audit actually asks: *was this allowed under the policy
at the time?*

Every entry carries a `policy` fingerprint — a digest of the configuration that
produced it:

```json
{ "seq": 4812, "policy": "99a5b0ae8aa1", "team": "search", "model": "claude-opus" }
```

So you can tell which entries were made under which policy, and see that policy
changed in the middle of a window you were looking at. Startup prints it, so the
value in the log can be matched to a deploy.

**It is not a hash of the whole file, deliberately.** A changed listen address or
log path is not a policy change, and a fingerprint that moves for those reasons
trains people to ignore it. It covers what alters what the gateway will allow,
redact, attribute or refuse: models, teams and their allowances, attribution,
identity, redaction rules, audit and sealing settings, limits, and whether
mutual TLS is required.

**Rotating a key does not move it; adding one does.** A new credential for a
team is a policy change. Replacing an existing one is not — and a fingerprint is
not a place to put a digest of a secret.

## When the log cannot be written

A gateway that keeps answering while unable to record anything is worse than one
that was never configured to audit: the first produces a gap nobody knows about,
the second at least produces no false confidence.

```json
{ "audit": { "enabled": true, "required": true } }
```

With `required`, a completion whose entry cannot be written is refused with a
503 before it is made — the same shape as every other control here. No record,
no request. Without it the request is served and the failure is visible rather
than fatal, which is the right default only where availability outranks
evidence.

Either way `/health` reports it:

```json
{ "status": "degraded", "audit": "no space left on device", "audit_failures": 214 }
```

That is a **200 with a degraded body, not a 503**, deliberately. A failing audit
log should page someone; it should not make a liveness probe restart a process,
which would lose the in-flight work and fix nothing — the disk is still full.
Point readiness or an alert at the body.

## Rotation and retention

A log that grows forever gets rotated by someone eventually, and the ordinary
tool for that truncates or renames underneath a running process. That severs the
chain silently: verification starts failing weeks later, for a reason nobody
connects to the cron job that caused it. So switchboard owns rotation rather
than leaving it to `logrotate`.

```json
{
  "audit": {
    "enabled": true,
    "path": "~/.switchboard/audit.jsonl",
    "max_bytes": 268435456,
    "retention": "4380h"
  }
}
```

A closed segment becomes `audit-20260904T212600.123456789Z.jsonl`. Names are
fixed-width and nanosecond-precision, so sorting them lexically sorts them
chronologically, which is what makes reading them back in order correct rather
than lucky.

**A segment continues the chain; it does not start a new one.** The first entry
of a new segment carries the sequence and digest following the last entry of the
previous, so `audit verify` walks every segment as one history:

```
ok  ~/.switchboard/audit.jsonl (signed)
  184203 entries across 12 segments, chain intact
```

Which means **deleting a whole segment is detected**. That matters because
removing a file is the tidy version of deleting history, and it is exactly what
a retention script or a nervous administrator would reach for.

### Ship it off the box

Retention alone only trades one problem for another: run out of disk, or delete
evidence. The way out is that **the gateway's disk is a buffer, not the
archive.**

```json
{
  "audit": {
    "max_bytes": 268435456,
    "archive_command": "aws s3 cp \"$SEGMENT\" s3://audit-archive/switchboard/",
    "retention": "168h"
  }
}
```

`archive_command` runs for each closed segment with `$SEGMENT` set to its path.
It is a command rather than an integration so it works with whatever you already
have — S3, rsync, a SIEM shipper, a tape robot.

**A segment is pruned only after that command has exited zero.** That invariant
is what makes short local retention safe: a week on disk is fine when the
durable copy is elsewhere, and a broken shipper means segments accumulate rather
than disappear. It runs off the request path, so a slow or wedged archiver never
becomes a slow gateway, and a failing one shows up in `/health` — not an outage
yet, but the beginning of one, and silent otherwise.

Archived segments are renamed with an `.archived` suffix rather than tracked in
memory or a sidecar, so the state survives a restart and is obvious on disk.

Worth knowing: **S3 Object Lock in compliance mode is stronger than the hash
chain.** The chain makes tampering *detectable*; object lock makes it
*impossible*, enforced by the platform. If you have that available, the chain
becomes a second, independent check rather than the only one.

### Retention periods worth knowing

switchboard cannot know which regime binds you, so it enforces none. For
context, the common ones:

| Regime | Period |
|---|---|
| PCI DSS 10.7 | 12 months, with 3 months immediately available |
| EU AI Act Art. 26 | ≥6 months, for deployers of high-risk systems |
| SEC Rule 17a-4 | 3–6 years depending on record type, first 2 years readily accessible |
| FINRA Rule 4511 | 6 years where no other period is specified |
| SOX §802 | 7 years for audit documentation |
| MiFID II Art. 16(7) | 5 years, 7 if a competent authority asks |

In financial services the binding number is usually **6 or 7 years**, which is
also the clearest argument for archiving rather than retaining locally: seven
years of prompt logs is not a thing that lives on a gateway's disk.

Whether an LLM gateway's log is a *book and record* at all depends on what the
model is used for. A model in the path of a customer decision — credit, fraud,
advice — pulls its log toward those periods. A model summarising internal
documents does not. That is a question for your compliance function, and the
useful thing this gives them is that the answer is a configuration change rather
than a re-architecture.

**Left unset, the log grows until the disk does not have room.** That is
deliberate — see above for why deleting evidence is opt-in — but it is a
decision, not an accident, and startup warns when `max_bytes` is unset.

`retention` deletes closed segments older than the period. The active file is
never pruned. Zero — the default — keeps everything, because deleting evidence
should be something you asked for rather than something that happens.

EU AI Act Article 26 asks deployers of high-risk systems to keep logs for at
least six months, and other regimes ask for longer. switchboard cannot know
which applies to you, so it warns at startup when `retention` is shorter than
six months rather than refusing to run.

## Two limits, stated rather than discovered

**Tail truncation is undetectable from the file alone.** An intact prefix is an
intact chain. Nothing inside the file can prove that entries once followed the
last one. Record the head that `verify` prints somewhere the log is not, and
compare it: that external anchor is what closes the gap.

**Anyone holding the key can rewrite history wholesale.** This is
tamper-evidence against someone without the key, which is most real exposure. It
is not proof against an attacker who has it, and it is not a substitute for
write-once storage where that is genuinely required.
