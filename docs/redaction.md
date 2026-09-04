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

## Limits, stated plainly

- **Regex redaction is best-effort.** It catches structured identifiers. It does
  not catch a name, an address written in prose, or a medical detail described
  in a sentence. Nothing pattern-based does.
- **This protects the log, not the provider.** Content still goes to the model
  as written. Redacting toward the provider is a different feature and is not
  built.
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
rather than in someone's memory.

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

## Two limits, stated rather than discovered

**Tail truncation is undetectable from the file alone.** An intact prefix is an
intact chain. Nothing inside the file can prove that entries once followed the
last one. Record the head that `verify` prints somewhere the log is not, and
compare it: that external anchor is what closes the gap.

**Anyone holding the key can rewrite history wholesale.** This is
tamper-evidence against someone without the key, which is most real exposure. It
is not proof against an attacker who has it, and it is not a substitute for
write-once storage where that is genuinely required.
