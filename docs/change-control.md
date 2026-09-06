# Change control

*Who authorised the rules this gateway is running.*

```sh
switchboard policy key -as grace          # once, per approver
switchboard policy approve -key grace.approver.key -as grace
switchboard policy show
switchboard policy history                # the test over a period
```

A model roster, a prompt, a tool grant, a redaction rule and a rate limit all
decide what this system does in production. Almost nowhere are they under the
change control that covers application code — they are edited in a console or a
JSON file, by one person, with nothing forcing a review. That gap is the common
finding, and it is invisible to any check that only reads the configuration,
because **a configuration cannot tell you who agreed to it.**

## How it works

An approval is an Ed25519 signature over a policy fingerprint. The fingerprint
is already the digest of the policy document — see
[evidence.md](evidence.md) — so signing it binds the approval to the exact
bytes. An approval cannot be moved onto a configuration nobody read.

```json
{
  "change_control": {
    "enabled": true,
    "required": true,
    "minimum": 2,
    "approvers": [
      { "name": "grace", "public_key": "MCowBQYDK2VwAyEA…" },
      { "name": "sam",   "public_key": "MCowBQYDK2VwAyEA…" }
    ]
  }
}
```

`switchboard policy key -as grace` writes a private key at mode 0600 and prints
the block above with the public half filled in.

**The gateway holds public keys only.** This is the same shape as the
[vault](redaction.md): a signature the serving process could produce would not
be evidence that anybody else agreed to anything, so the private half lives with
whoever approves changes and never on the machine whose changes are being
approved.

## Preventive or detective, and they are not the same claim

`required: true` refuses to start on an unapproved configuration. The refusal
happens before the listener is announced, because printing *serving 1 model* and
then stopping reads as a crash rather than as a control.

```
switchboard: policy c6dcb054756e is unapproved — 0 valid signature(s), 1 required.
  Approve it:  switchboard policy approve -key KEY -as NAME
```

`required: false` serves it and logs a warning, and `switchboard policy history`
will show that period as unapproved. That is a detective control rather than a
preventive one. Both are defensible; they are different statements, and the
control report says which one this deployment made.

The gate is at startup and not per request, deliberately. A gateway that served
some requests and refused others under one configuration would produce a log
nobody can reason about. Either these rules were authorised or they were not,
and that is a property of the configuration rather than of a call.

## Why `minimum: 2`

One person who can both edit the configuration and sign for it is approving
their own change. That is true of every approval scheme ever built, and a second
signature is the only thing that addresses it.

The mechanism is honest about this. With one approver the control report's Met
row still says what one signature does not cover, rather than reading as though
the question is closed.

## The roster is inside the fingerprint

This is the part that makes it hold. `change_control` is part of the policy
document the fingerprint covers, so **adding yourself as an approver moves the
fingerprint** — and that change needs a signature from whoever could already
sign. It is not the one edit that authorises every edit after it.

The keys are inline rather than paths for the same reason. Held as a filename,
somebody could swap the file behind a name and the configuration would not
change, which is precisely the substitution this exists to make visible.

There is one unavoidable bootstrap: the first approver has nobody to approve
them. Approve it, and from then on the roster is under the same control as
everything else.

## The test over a period

An examiner does not ask whether change control is switched on today. They ask
whether every configuration the log ran under was authorised, and authorised
*before* it ran.

```
$ switchboard policy history

2 policies cited by ~/.switchboard/audit.log

POLICY        IN FORCE                 STATE       APPROVED BY
c6dcb054756e  2026-09-05 → 2026-09-05  unapproved  —
c03066154665  2026-09-06 → 2026-09-30  approved    grace

  !! 1 policy served with no valid signature. Those periods ran under rules
     nobody authorised, and the exception is dated to the day each policy
     first served — not to today.
```

Five states, and the distinctions are the point:

| State | Meaning |
|---|---|
| **approved** | Enough valid signatures, all of them before this policy served its first request. |
| **approved late** | Enough valid signatures, at least one added after it was already serving. |
| **unapproved** | No valid signature, or fewer than the minimum. |
| **unverifiable** | Signatures exist and no configured key can check them. |
| **not in force** | Change control is off, so nothing is claimed either way. |

**Late is not a soft pass.** The control is authorisation *before deployment*,
so an approval carries its own signing time and it is compared against the first
entry served under that policy. Somebody did review it, which is worth having,
and nobody authorised it in advance, which is what the control asks for.
Collapsing the two would turn this into a box that is always ticked eventually.

Lateness is never claimed without a serving time to compare against. Where the
log cannot say when a policy first ran, the report makes the weaker claim rather
than guessing.

**Unverifiable is not unapproved.** "Nobody signed this" and "we cannot tell who
signed this" are different findings with different fixes. The usual cause of the
second is an approver removed from the roster, which stops their past approvals
verifying — so record removals rather than making them silently.

**Not in force is not a failure.** With change control off, reporting every past
policy as unapproved would be a finding manufactured from a feature nobody
switched on. Switching it on begins covering the policies that come after, and
is not retroactive.

`switchboard policy history -strict` exits non-zero on anything that is not
`approved`, which is the CI form.

## What it cannot show

Signatures are checked against the roster in the configuration you are holding
now, not the roster in force at the time. Because the roster is inside the
fingerprint, a roster change is itself a change needing approval — but somebody
who can both edit the configuration and hold a key approves their own work, and
only a minimum above one addresses that.

It also says nothing about changes made outside this configuration. A prompt
template living in application code is under whatever change control covers that
code, and this cannot see it; see F2 in
[the control mapping](https://grace.github.io/writing/ai-controls-soc2/) for why
that is the usual place the reconstruction stops one step short.
