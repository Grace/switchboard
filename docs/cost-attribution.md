# Cost attribution

*Splitting one gateway's bill back out by team.*

## The problem gateways create

Amazon Bedrock attributes inference cost to the IAM principal that made the
call. That works when your applications call Bedrock directly.

It stops working the moment a gateway is in the path. A gateway authenticates
its callers at its own layer and then calls Bedrock under one service role, so
every request on the bill arrives as the same identity. The per-team split you
wanted is exactly the distinction the proxy just collapsed.

This is not a flaw in AWS's design — it is a structural consequence of proxying.
And it means the gateway, the thing that erased the identity, is the only
component still holding it.

## How switchboard puts it back

AWS's guidance for gateways is to assume a role per caller, passing the caller
as the session name and its attributes as session tags. Tagged sessions surface
in Cost and Usage Report 2.0 under an `iamPrincipal/` prefix once activated as
cost allocation tags in Billing.

switchboard does that per request:

```json
{
  "attribution": {
    "enabled": true,
    "role_arn": "arn:aws:iam::123456789012:role/switchboard-caller",
    "tag_key": "team",
    "session_duration": "15m",
    "require_caller": true
  },
  "teams": [
    { "name": "search",  "keys": ["sk-switchboard-search-…"] },
    { "name": "billing", "keys": ["sk-switchboard-billing-…"] }
  ]
}
```

Callers present their key as a bearer token:

```sh
curl http://gateway:11435/v1/chat/completions \
  -H 'authorization: Bearer sk-switchboard-search-…' \
  -H 'content-type: application/json' \
  -d '{"model": "claude-opus", "messages": [{"role":"user","content":"hi"}]}'
```

switchboard resolves the key to a team, assumes `role_arn` with
`RoleSessionName` set to the team and a session tag of `team=<name>`, and makes
the Bedrock call with those credentials. The same request now arrives at the
provider wearing an identity the bill can split on.

Credentials are cached per team and refresh before expiry, so a busy team costs
one STS call per `session_duration`, not one per request.

**Attribution and authentication are the same feature here.** switchboard cannot
invent an identity it was never given, so `teams` is both the key list and the
chargeback roster.

### Failing closed

`require_caller: true` refuses requests that present no valid key, with a 401.
Left off, unattributed requests are served against the gateway's own role and
land on the bill exactly as they do today — visible, but nobody's. Fail closed
if the bill is the point.

## What you have to set up

1. **A role for switchboard to assume**, whose trust policy allows the gateway's
   own principal to call both `sts:AssumeRole` **and `sts:TagSession`**. Missing
   `TagSession` is the usual first failure: the assume succeeds, the tag is
   silently absent, and everything still bills to one identity.
2. **The role needs the Bedrock permissions**, not the gateway's base role —
   the call is made with the assumed credentials.
3. **Activate the tag in Billing** → Cost allocation tags. Until you do, the
   sessions are tagged and the bill does not group by them. Cost Explorer shows
   it 24–48 hours later.

## Verify it before you trust it

This is implemented and unit-tested — key resolution, team validation, fail-closed
behaviour, and that the caller reaches the backend. What tests cannot cover is
whether AWS bills the way this expects, because that needs a real account and a
CUR cycle.

So check it once, deliberately: send traffic as two teams, wait for CUR, and
confirm the `iamPrincipal/` tag splits the way you expect. If it does not, the
usual causes are a missing `sts:TagSession`, an unactivated cost allocation tag,
or looking before the 24–48 hour lag.

Redaction of request and response content — the blocker for sending traces off
the box at all — is now implemented; see [redaction.md](redaction.md).

## Still not built

- **Spend caps.** No per-team token budget and no enforcement when one is
  exceeded. Visibility tells you spend climbed; it does not stop it.
- **Chargeback reporting.** No rollup or export — the data is in CUR, not in
  something finance can read without an engineer.

If you are running Bedrock for several teams and solving this some other way, I
would like to hear how. **hello@gracefulco.de**
