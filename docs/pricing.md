# Pricing

switchboard counts tokens. Turning tokens into money needs a rate, and
switchboard does not ship one.

That is a decision, not an omission. Provider prices change, they differ by
region, and they differ again by whatever your organisation negotiated. A price
list baked into a binary produces confident wrong numbers on a page somebody is
about to forward to finance — and the failure is silent, because a stale rate
looks exactly like a current one.

So the rates are declared by whoever knows what this deployment actually pays:

```json
{
  "pricing": {
    "currency": "USD",
    "models": {
      "claude-opus": {
        "input_per_mtok": 15,
        "output_per_mtok": 75,
        "cache_write_per_mtok": 18.75,
        "cache_read_per_mtok": 1.5
      },
      "claude-sonnet": { "input_per_mtok": 3,    "output_per_mtok": 15 },
      "qwen3-8b":      { "input_per_mtok": 0.04, "output_per_mtok": 0.04 }
    }
  }
}
```

Rates are per **million** tokens, split by direction and by cache, because
providers price all four differently. `currency` is a label on the figures, not
a conversion — declare the rates in the currency you are billed in.

## The cache rates are not optional if you use caching

A cache read costs a fraction of the base input rate and a cache write a premium
on it — on the Anthropic API, **0.1x** and **1.25x**. So a deployment with a
large stable system prompt, which is most of the ones worth having, is billed
almost entirely at one-tenth the input rate. Charging those tokens at the input
rate overstates cost by close to tenfold.

switchboard does not apply those multipliers for you. They differ by provider
and they change, and a default that is right for one provider is silently wrong
for the next — the same reason there is no price list at all. The figures above
are the Anthropic ones, written out so you copy them deliberately rather than
inherit them.

**A model that served cached tokens with no cache rate configured is reported as
unpriced**, exactly like a model with no rate at all. That is deliberate: the
alternative is a number that looks right and is wrong by an order of magnitude.
Leaving a cache rate out means "not configured". Setting it to `0` means "cached
tokens are free here", which is a claim, and switchboard will price it that way.

The counts themselves are recorded whether or not you have rates, because they
cannot be recovered later. Rates can be corrected and reapplied to history; what
the provider said it served from cache at a given moment is observable once, and
an append-only log that did not capture it has lost it. This is why the fields
are on the record and the rates are in the config: **record what you observed,
configure what you assume.**

Cache tokens also count against `limits.tokens_per_window`. They are cheaper,
not free, and a budget that ignored them would let a caller with a large cached
prompt consume most of a provider's capacity while charging almost nothing
against its allowance.

## Unpriced is not free

A model with no entry here contributes tokens and no money, and every surface
says so rather than summing what it has:

- the cost tile carries an `N unpriced` line;
- a banner names the models that have no rate;
- a team row whose traffic included any unpriced model shows `—` for cost, not a
  smaller number, because a partial sum understates without saying so;
- the models table marks the row `unpriced` and shows the configured rate for
  every row that has one.

With no `pricing` block at all, the page shows tokens and says *no rate card
configured*. That is the honest state of a deployment that has not told
switchboard what it pays.

## Where the rate is not the whole cost

Two things this deliberately does not model.

**Batch submissions.** Batch APIs are priced at a discount that switchboard does
not model, because nothing in an OpenAI-shaped completion request says a
submission was batched. Traffic through this gateway is synchronous by
construction, so this is a limit on packaging it alongside batch spend rather
than on the figures themselves.

**Provider-side cache behaviour you did not ask for.** The counts come from what
the backend reported. A provider that serves a cache hit without saying so
produces a figure switchboard cannot correct, and there is no way to detect it
from this side.

**The invoice itself.** For Bedrock, the authority on what you owe is Cost and
Usage Report 2.0, and the way to split it by team is session tags on an assumed
role — see [cost-attribution.md](cost-attribution.md). The rates here exist so
the page can answer "what did this person's prompts cost" at the moment you are
looking at them, without waiting a day for billing data and without leaving the
log. They are two different questions and both are worth being able to answer.

## Rates and the model roster

Rates are not validated against `models[]`. A log outlives the configuration
that produced it, and a rate for a model retired last month is exactly what
reading last month's entries needs.
