# Cost attribution

*What switchboard records today, what you can build from it, and what it does
not do yet.*

## The problem gateways create

Amazon Bedrock now supports granular cost attribution: spend is allocated to the
IAM identity that made the call, and Application Inference Profiles let you tag
by team or project. That works well when your applications call Bedrock
directly.

It stops working the moment a gateway is in the path. A gateway authenticates
its callers at its own layer and then calls Bedrock under one service role, so
every request in the bill arrives as the same identity. The per-team split you
wanted is exactly the information the gateway just collapsed.

This is not a flaw in AWS's design. It is a structural consequence of proxying,
and it means the gateway — the thing that erased the distinction — is the only
component still holding it.

## What switchboard records today

Every completion produces token usage accounting: prompt tokens, completion
tokens, the model that served the request, and which backend answered. That is
enough to rebuild attribution yourself if you can tell requests apart.

## Rolling it up yourself

If your callers already carry an identity, put it on the request and group by it
downstream. The usage figures are per-request, so any aggregation you can
express over your own logs works — by team, by application, by feature, by
tenant.

For a first pass, run the server behind something that already knows who is
calling, and join its access log to switchboard's usage records on request id.

## What is not built

- **Identity propagation.** switchboard does not yet take a caller identity and
  carry it through to Bedrock in a form the bill can see (an inference profile
  per team, or a session tag).
- **Spend caps.** No per-team token budget, and no enforcement when one is
  exceeded. Visibility tells you spend climbed; it does not stop it.
- **Chargeback reporting.** No rollup, no export, nothing finance can read
  without an engineer in between.
- **Redaction before telemetry leaves.** Usage records are safe, but request and
  response content is not redacted anywhere yet, which is the blocker for
  sending traces anywhere at all in a regulated network.

These are the next things to build, in roughly that order.

If you are hitting this — a platform team running Bedrock for several product
teams, and finance asking who spent what — I would like to hear how you are
solving it today. **hello@gracefulco.de**
