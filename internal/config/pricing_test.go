package config

import "testing"

// A missing rate has to stay distinguishable from a rate of zero all the way
// through, because the page's honesty depends on that one bit.
func TestAMissingRateIsNotAZeroRate(t *testing.T) {
	p := Pricing{Models: map[string]ModelPrice{
		"priced": {InputPerMTok: 3, OutputPerMTok: 15},
		"free":   {InputPerMTok: 0, OutputPerMTok: 0},
	}}
	if _, ok := p.Cost("unknown", Tokens{Input: 1e6, Output: 1e6}); ok {
		t.Error("an unconfigured model reported a rate")
	}
	if cost, ok := p.Cost("free", Tokens{Input: 1e6, Output: 1e6}); !ok || cost != 0 {
		t.Errorf("a declared zero rate should price at 0, got %v ok=%v", cost, ok)
	}
	cost, ok := p.Cost("priced", Tokens{Input: 500_000, Output: 200_000})
	if !ok {
		t.Fatal("a configured model should price")
	}
	if want := 3*0.5 + 15*0.2; cost != want {
		t.Errorf("cost = %v, want %v", cost, want)
	}
}

func TestPricingRejectsNegativeRatesAndDefaultsCurrency(t *testing.T) {
	p := Pricing{Models: map[string]ModelPrice{"m": {InputPerMTok: -1}}}
	if err := p.validate(); err == nil {
		t.Error("a negative rate should be a config error, not a credit")
	}

	p = Pricing{Models: map[string]ModelPrice{"m": {InputPerMTok: 1, OutputPerMTok: 2}}}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if p.Currency != "USD" {
		t.Errorf("currency = %q, want the USD default", p.Currency)
	}

	// No rates at all is the normal state, and must not invent a currency.
	var empty Pricing
	if err := empty.validate(); err != nil || empty.Currency != "" {
		t.Errorf("empty pricing: err=%v currency=%q", err, empty.Currency)
	}
}

// A log outlives the config that produced it, so a rate for a retired model is
// a feature rather than a typo to be rejected.
func TestARateForAModelNotInTheRosterLoads(t *testing.T) {
	c := Default()
	c.Models = []Line{{Name: "current", Backend: BackendLocal, Path: "/tmp/x.gguf"}}
	c.Pricing = Pricing{Models: map[string]ModelPrice{"retired-last-month": {InputPerMTok: 1}}}
	if err := c.Validate(); err != nil {
		t.Fatalf("a rate for a model no longer served should load: %v", err)
	}
}

// The bug this whole split exists to prevent: cached traffic priced at the
// input rate is wrong by close to an order of magnitude, and silently so.
func TestCachedTokensAreNotPricedAtTheInputRate(t *testing.T) {
	read, write := 1.5, 18.75 // 0.1x and 1.25x of a 15/Mtok input rate
	p := Pricing{Models: map[string]ModelPrice{
		"cached":   {InputPerMTok: 15, OutputPerMTok: 75, CacheReadPerMTok: &read, CacheWritePerMTok: &write},
		"no-cache": {InputPerMTok: 15, OutputPerMTok: 75},
	}}

	// A request that was almost entirely a cache hit: 187,361 cached, 3 fresh.
	tk := Tokens{Input: 3, Output: 8, CacheRead: 187_361}
	got, ok := p.Cost("cached", tk)
	if !ok {
		t.Fatal("a model with cache rates should price cached traffic")
	}
	want := 3*15/1e6 + 8*75/1e6 + 187_361*read/1e6
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("cost = %v, want %v", got, want)
	}

	// Charging the same tokens at the input rate is the error being prevented.
	naive := float64(tk.Prompt())*15/1e6 + 8*75/1e6
	if naive/got < 8 {
		t.Errorf("the naive figure is only %.1fx the correct one; this test has "+
			"stopped demonstrating the problem it exists for", naive/got)
	}

	// And a model with no cache rate must refuse rather than guess.
	if _, ok := p.Cost("no-cache", tk); ok {
		t.Error("cached tokens with no cache rate should report unpriced, not a guess")
	}
	// The same model prices fine for traffic that was never cached.
	if _, ok := p.Cost("no-cache", Tokens{Input: 100, Output: 10}); !ok {
		t.Error("uncached traffic should still price without cache rates")
	}
}

// Absent and zero are different claims: one is "not configured", the other is
// "cached tokens are free here".
func TestAZeroCacheRateIsAClaimAndAnAbsentOneIsNot(t *testing.T) {
	free := 0.0
	p := Pricing{Models: map[string]ModelPrice{
		"free-cache": {InputPerMTok: 15, CacheReadPerMTok: &free},
	}}
	cost, ok := p.Cost("free-cache", Tokens{CacheRead: 1_000_000})
	if !ok {
		t.Fatal("an explicit zero cache rate should price")
	}
	if cost != 0 {
		t.Errorf("cost = %v, want 0", cost)
	}
}
