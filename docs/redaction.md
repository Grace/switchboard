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
  without evidence.
