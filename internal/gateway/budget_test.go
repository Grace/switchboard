package gateway

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// "No text" is not one fact, and treating it as one broke this table in both
// directions. A model that hit its ceiling before writing anything is the budget
// problem the table exists for. A model that was content-filtered, or that
// finished normally with nothing to say, produced no text for a reason a larger
// budget would not fix, and recording that as a budget fact shadows a healthy
// model for the whole TTL.
func TestObserveOutcomeOnlyRecordsBudgetFacts(t *testing.T) {
	for _, tc := range []struct {
		name, finish, text string
		wantSkip           bool
	}{
		{"empty at the ceiling is a budget fact", "length", "", true},
		{"content filtered says nothing about the budget", "content_filter", "", false},
		{"finished with nothing to say says nothing about the budget", "stop", "", false},
		{"text produced at this budget is a budget fact", "stop", "hello", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBudgetTable()
			b.observeOutcome("openai", "m", 1024, tc.finish, tc.text)
			if got := b.skip("openai", "m", 1024); got != tc.wantSkip {
				t.Fatalf("skip = %v, want %v", got, tc.wantSkip)
			}
		})
	}
}

// The opposite direction, which the non-streaming path had. It recorded
// producedText unconditionally true on success, so one content-filtered response
// set okAt and silently switched budget-aware routing off for that model for six
// hours -- the whole feature, disabled by a safety filter.
func TestContentFilterDoesNotEraseARealBudgetFact(t *testing.T) {
	b := newBudgetTable()
	b.observeOutcome("openai", "m", 1024, "length", "")
	if !b.skip("openai", "m", 1024) {
		t.Fatal("a genuine empty-at-ceiling was not recorded")
	}
	b.observeOutcome("openai", "m", 1024, "content_filter", "")
	if !b.skip("openai", "m", 1024) {
		t.Fatal("a content-filtered response erased a real budget fact and disabled routing")
	}
}

// End to end on the non-streaming path, which had the opposite bug: it recorded
// producedText unconditionally true on every success, so a content-filtered
// response set okAt and switched budget-aware routing off for that model.
//
// A single provider is configured deliberately. The route is already shadowed,
// and server.chat clears the skip set when every eligible route is shadowed --
// so the request is attempted, which is exactly the state this needs to reach.
func TestContentFilteredResponseDoesNotDisableBudgetRouting(t *testing.T) {
	a := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"index":0,"message":{"content":""},"finish_reason":"content_filter"}],`+
			`"usage":{"prompt_tokens":9,"completion_tokens":0}}`)
	}))
	defer a.Close()
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: a.URL, KeyEnv: "PROVIDER_KEY"}})

	// A real budget fact, observed before this request.
	s.budgets.observe("openai", "test-model", 1024, false)
	if !s.budgets.skip("openai", "test-model", 1024) {
		t.Fatal("setup: the budget fact was not recorded")
	}

	body := `{"model":"preferred","max_tokens":1024,"messages":[{"role":"user","content":"hi"}]}`
	if w := call(s, body); w.Code != 200 {
		t.Fatalf("request: %d %s", w.Code, w.Body)
	}
	if !s.budgets.skip("openai", "test-model", 1024) {
		t.Fatal("a content-filtered response set okAt and disabled budget-aware routing")
	}
}

// End to end on the streaming path, where the bug was worst: ParseChat defaults
// max_tokens to 1024, so a single filtered stream shadowed the primary model for
// essentially all default traffic and callers were silently moved to the
// fallback -- different model, different cost.
func TestContentFilteredStreamDoesNotShadowTheModel(t *testing.T) {
	var primary, fallback atomic.Int64
	a := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primary.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"\"},\"finish_reason\":\"content_filter\"}]}\n\n")
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer a.Close()
	b := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallback.Add(1)
		io.WriteString(w, `{"content":[{"type":"text","text":"fallback"}],"stop_reason":"end_turn"}`)
	}))
	defer b.Close()
	s := testServer(t, map[string]ProviderConfig{
		"openai":    {URL: a.URL, KeyEnv: "PROVIDER_KEY"},
		"anthropic": {URL: b.URL, KeyEnv: "PROVIDER_KEY"},
	})
	body := `{"model":"preferred","stream":true,"max_tokens":1024,"messages":[{"role":"user","content":"hi"}]}`
	if w := call(s, body); w.Code != 200 {
		t.Fatalf("first request: %d %s", w.Code, w.Body)
	}
	if s.budgets.skip("openai", "test-model", 1024) {
		t.Fatal("a content-filtered stream marked the model as producing nothing at this budget")
	}
	if w := call(s, body); w.Code != 200 {
		t.Fatalf("second request: %d %s", w.Code, w.Body)
	}
	if primary.Load() != 2 {
		t.Fatalf("primary reached %d times, want 2; it was shadowed by the filtered response", primary.Load())
	}
	if fallback.Load() != 0 {
		t.Fatalf("fallback reached %d times, want 0", fallback.Load())
	}
}

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
