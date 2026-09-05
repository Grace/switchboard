package config

import "fmt"

// Pricing turns token counts into money.
//
// switchboard does not ship a price list. Provider prices change, they differ by
// region and by negotiated agreement, and a stale table baked into a binary
// produces confident wrong numbers on a page someone is about to forward to
// finance. So the rates are declared here, by whoever knows what this deployment
// actually pays, and a model with no rate is reported as unpriced rather than as
// zero — the two are not the same claim.
type Pricing struct {
	// Currency labels the figures. It is not converted; it is what the rates
	// below are already denominated in.
	Currency string `json:"currency,omitempty"`
	// Models maps a model name — the name callers ask for, matching models[].name
	// — to its rate.
	Models map[string]ModelPrice `json:"models,omitempty"`
}

// ModelPrice is one model's rate, per million tokens, split four ways because
// that is how providers bill.
//
// Direction is the obvious split. The cache split is the one that decides
// whether the figure is usable: a cache read is a fraction of the base input
// rate and a cache write a premium on it — on the Anthropic API, 0.1x and 1.25x
// — so pricing cached traffic at the input rate overstates it by close to an
// order of magnitude. Anyone with a large stable system prompt is mostly cached
// traffic.
//
// The cache rates are not derived from InputPerMTok by a built-in multiplier.
// The multipliers differ between providers and change, and a default that is
// right for one provider is silently wrong for the next — the same reason
// switchboard ships no price list at all.
type ModelPrice struct {
	InputPerMTok  float64 `json:"input_per_mtok"`
	OutputPerMTok float64 `json:"output_per_mtok"`
	// CacheWritePerMTok and CacheReadPerMTok price the cached parts of the
	// prompt. Leave them out for a model or provider with no prompt cache;
	// setting them to zero asserts that cached tokens are free, which is a
	// different and probably false claim.
	CacheWritePerMTok *float64 `json:"cache_write_per_mtok,omitempty"`
	CacheReadPerMTok  *float64 `json:"cache_read_per_mtok,omitempty"`
}

// Tokens is one completion's consumption, split the way it is billed. Input
// excludes the cached parts, matching how providers report them.
type Tokens struct {
	Input      int
	Output     int
	CacheWrite int
	CacheRead  int
}

// Total is everything consumed, however it was billed.
func (t Tokens) Total() int { return t.Input + t.Output + t.CacheWrite + t.CacheRead }

// Prompt is everything that went in.
func (t Tokens) Prompt() int { return t.Input + t.CacheWrite + t.CacheRead }

// Cost of one completion, and whether it could be priced at all.
//
// It reports false in two cases, and the second is the one that matters: no
// rate for the model, or cached tokens with no rate for them. Falling back to
// the input rate for cached tokens would produce a number that looks right and
// is wrong by up to tenfold, and the whole point of the second return value is
// that a figure this system cannot stand behind is not offered as one.
func (p Pricing) Cost(model string, t Tokens) (float64, bool) {
	rate, ok := p.Models[model]
	if !ok {
		return 0, false
	}
	cost := float64(t.Input)*rate.InputPerMTok/1e6 +
		float64(t.Output)*rate.OutputPerMTok/1e6

	if t.CacheWrite > 0 {
		if rate.CacheWritePerMTok == nil {
			return 0, false
		}
		cost += float64(t.CacheWrite) * *rate.CacheWritePerMTok / 1e6
	}
	if t.CacheRead > 0 {
		if rate.CacheReadPerMTok == nil {
			return 0, false
		}
		cost += float64(t.CacheRead) * *rate.CacheReadPerMTok / 1e6
	}
	return cost, true
}

func (p *Pricing) validate() error {
	if p.Currency == "" && len(p.Models) > 0 {
		p.Currency = "USD"
	}
	for name, rate := range p.Models {
		if name == "" {
			return fmt.Errorf("pricing.models has an entry with no model name")
		}
		if rate.InputPerMTok < 0 || rate.OutputPerMTok < 0 ||
			neg(rate.CacheWritePerMTok) || neg(rate.CacheReadPerMTok) {
			return fmt.Errorf("pricing.models[%q]: rates must not be negative", name)
		}
	}
	return nil
}

func neg(v *float64) bool { return v != nil && *v < 0 }
