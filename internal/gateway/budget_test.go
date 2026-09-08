package gateway

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// The measured case. gpt-5-nano at max_tokens 1024 returned zero visible
// characters for four of seven ordinary prompts, billed in full. Once that has
// been seen, sending the next identical request there spends money to learn what
// is already known.
func TestSkipsARouteAlreadySeenReturningNothing(t *testing.T) {
	var reasoning, fallback atomic.Int64
	a := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reasoning.Add(1)
		io.WriteString(w, emptyByBudget)
	}))
	defer a.Close()
	b := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallback.Add(1)
		io.WriteString(w, `{"content":[{"type":"text","text":"answered"}],"stop_reason":"end_turn"}`)
	}))
	defer b.Close()
	s := testServer(t, map[string]ProviderConfig{
		"openai":    {URL: a.URL, KeyEnv: "PROVIDER_KEY"},
		"anthropic": {URL: b.URL, KeyEnv: "PROVIDER_KEY"},
	})
	body := `{"model":"preferred","max_tokens":1024,"messages":[{"role":"user","content":"hi"}]}`

	if w := call(s, body); w.Code != 200 {
		t.Fatalf("first request: %d %s", w.Code, w.Body)
	}
	if reasoning.Load() != 1 {
		t.Fatalf("first request did not reach the reasoning model")
	}
	if w := call(s, body); w.Code != 200 {
		t.Fatalf("second request: %d %s", w.Code, w.Body)
	}
	if reasoning.Load() != 1 {
		t.Errorf("the empty route was tried again; calls = %d", reasoning.Load())
	}
	if fallback.Load() != 2 {
		t.Errorf("fallback served %d requests, want 2", fallback.Load())
	}
	if s.Metrics.BudgetSkip.Load() != 1 {
		t.Errorf("BudgetSkip = %d, want 1", s.Metrics.BudgetSkip.Load())
	}
}

// Failing at 1024 says nothing about 4096. Measured: the essay prompt that
// returned nothing at 1024 produced 1469 characters at 2048. Skipping a larger
// budget would deny a request that would have worked.
func TestALargerBudgetIsNotSkipped(t *testing.T) {
	b := newBudgetTable()
	b.observe("openai", "gpt-5-nano", 1024, false)
	if !b.skip("openai", "gpt-5-nano", 1024) {
		t.Error("the observed failing budget is not skipped")
	}
	if !b.skip("openai", "gpt-5-nano", 512) {
		t.Error("a smaller budget than one already seen failing is not skipped")
	}
	if b.skip("openai", "gpt-5-nano", 4096) {
		t.Error("a larger budget was skipped on no evidence")
	}
}

// One success overrides any number of failures, so the rule corrects itself
// rather than shadowing a model permanently. Demand depends on the prompt, so a
// hard prompt failing must not lock out an easy one at the same budget forever.
func TestSuccessClearsTheSkip(t *testing.T) {
	b := newBudgetTable()
	b.observe("openai", "gpt-5-nano", 1024, false)
	if !b.skip("openai", "gpt-5-nano", 1024) {
		t.Fatal("precondition: should be skipped")
	}
	b.observe("openai", "gpt-5-nano", 1024, true)
	if b.skip("openai", "gpt-5-nano", 1024) {
		t.Error("a success at this budget did not clear the skip")
	}
	if b.skip("openai", "gpt-5-nano", 2048) {
		t.Error("a larger budget is still skipped after a success")
	}
}

func TestColdStartSkipsNothing(t *testing.T) {
	b := newBudgetTable()
	for _, budget := range []int{1, 512, 1024, 16384} {
		if b.skip("openai", "gpt-5-nano", budget) {
			t.Errorf("skipped at %d with no observations", budget)
		}
	}
}

// The availability guard, and the case that motivated the feature: a policy
// whose routes are all reasoning models. Refusing to try is worse than trying
// and failing over, and a gateway that answers 503 without contacting anyone has
// stopped being a gateway.
func TestEveryRouteSkippedMeansNoneIsSkipped(t *testing.T) {
	var a1, b1 atomic.Int64
	a := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a1.Add(1)
		io.WriteString(w, emptyByBudget)
	}))
	defer a.Close()
	b := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b1.Add(1)
		io.WriteString(w, `{"content":[],"stop_reason":"max_tokens","usage":{"input_tokens":9,"output_tokens":1024}}`)
	}))
	defer b.Close()
	s := testServer(t, map[string]ProviderConfig{
		"openai":    {URL: a.URL, KeyEnv: "PROVIDER_KEY"},
		"anthropic": {URL: b.URL, KeyEnv: "PROVIDER_KEY"},
	})
	body := `{"model":"preferred","max_tokens":1024,"messages":[{"role":"user","content":"hi"}]}`

	call(s, body) // teaches the table that both return nothing at 1024
	before := a1.Load() + b1.Load()
	w := call(s, body)
	if a1.Load()+b1.Load() == before {
		t.Fatal("every route was skipped; the request reached no provider at all")
	}
	// It still fails, because both really do return nothing, but it fails having
	// tried rather than refusing outright.
	if w.Code != 503 || !strings.Contains(w.Body.String(), "max_tokens") {
		t.Errorf("status %d, body %s", w.Code, w.Body)
	}
}

// The table is written from the request path.
func TestBudgetTableIsConcurrencySafe(t *testing.T) {
	b := newBudgetTable()
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b.observe("openai", "gpt-5-nano", 1024, i%2 == 0)
			b.skip("openai", "gpt-5-nano", 1024)
		}(i)
	}
	wg.Wait()
}
