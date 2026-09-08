package gateway

// Budget-aware routing.
//
// Reasoning models spend their token budget on hidden reasoning before writing
// any answer and reserve nothing for it, so a budget that is merely too small
// yields a 200 with empty content, billed in full. Measured against gpt-5-nano
// at ParseChat's default of 1024, four of seven ordinary prompts returned zero
// visible characters, one of them "list three uses for a paperclip".
//
// Raising the default is not the fix and was ruled out on evidence: 4096 still
// returned nothing for a 500-word essay prompt, while gpt-4o-mini answered that
// same prompt inside 666 billed tokens. No static number is both sufficient for
// reasoning models and not a tax on everything else.
//
// So this is a routing problem, which is what a router is for. The gateway
// already recovers from an empty completion by failing over; this stops it
// sending a request it has already watched that model fail.

import (
	"sync"
	"time"
)

// budgetKey identifies one model at one provider. Demand is a property of the
// model, not the provider.
type budgetKey struct{ provider, model string }

// budgetFact is two observations, not a statistic. Averaging reasoning tokens is
// tempting and wrong: the same prompt consumed 1920 reasoning tokens at a budget
// of 2048 and 1152 at 4096, so a mean would be confidently wrong in both
// directions. These are things that actually happened.
type budgetFact struct {
	// emptyAt is the largest budget at which this model produced no text.
	emptyAt int
	// okAt is the smallest budget at which it produced text. Zero means never
	// observed succeeding.
	okAt int
	seen time.Time
}

// budgetTable remembers those facts per model, bounded and expiring. Model
// behaviour moves: two of the three models named in the live tests were retired
// by their providers mid-project, so a stale observation must not shadow a model
// forever.
type budgetTable struct {
	mu    sync.Mutex
	facts map[budgetKey]budgetFact
	ttl   time.Duration
	limit int
}

func newBudgetTable() *budgetTable {
	return &budgetTable{facts: map[budgetKey]budgetFact{}, ttl: 6 * time.Hour, limit: 256}
}

// skip reports whether a request at this budget should pass over this route.
//
// Only where failure was observed at this budget or higher, and only while no
// success has been seen at or below it. That second clause is what stops the
// rule latching: one success overrides any number of failures, so the table
// corrects itself rather than shadowing a model permanently.
//
// The known imprecision is that demand depends on the prompt, so a hard prompt
// failing at some budget can briefly shadow an easy prompt at the same budget.
// The success clause bounds how long that lasts. This is a heuristic that saves a
// wasted provider call, not a guarantee.
func (b *budgetTable) skip(provider, model string, budget int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	f, ok := b.facts[budgetKey{provider, model}]
	if !ok || time.Since(f.seen) > b.ttl {
		return false
	}
	if budget > f.emptyAt {
		return false
	}
	return f.okAt == 0 || budget < f.okAt
}

// observe records what a budget actually produced at a model.
func (b *budgetTable) observe(provider, model string, budget int, producedText bool) {
	if budget <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	k := budgetKey{provider, model}
	f, ok := b.facts[k]
	if !ok || time.Since(f.seen) > b.ttl {
		f = budgetFact{}
		// Bounded rather than growing with the number of models ever routed to.
		// Dropping the whole table is acceptable for a heuristic that rebuilds
		// itself from the next few requests, and is simpler than an eviction
		// policy nobody would tune.
		if len(b.facts) >= b.limit {
			b.facts = map[budgetKey]budgetFact{}
		}
	}
	if producedText {
		if f.okAt == 0 || budget < f.okAt {
			f.okAt = budget
		}
	} else if budget > f.emptyAt {
		f.emptyAt = budget
	}
	f.seen = time.Now()
	b.facts[k] = f
}
