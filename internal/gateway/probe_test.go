package gateway

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// probeOne decides whether a provider is usable at all. Getting the pass/fail
// boundary wrong in either direction is costly: a false failure withholds a
// working provider, and a false pass is exactly the auth-only check this was
// built to avoid.
func TestProbeOnePassFailBoundary(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		body     string
		wantFail bool
	}{
		{"serves", 200, `{"choices":[{"index":0,"message":{"content":"ok"},"finish_reason":"stop"}]}`, false},
		{"bad key", 401, `{"error":{"message":"Incorrect API key provided"}}`, true},
		{"forbidden", 403, `{"error":{"message":"not permitted"}}`, true},
		{"no credits", 429, `{"error":{"message":"You have no credits remaining."}}`, true},
		{"balance too low", 400, `{"error":{"message":"Your credit balance is too low to access the Anthropic API."}}`, true},
		// A busy or throttled provider is not a misconfiguration, and failing the
		// check on it would withhold a provider that works. Gemini returned both
		// of these repeatedly during live testing while being perfectly usable.
		{"throttled", 429, `{"error":{"message":"Rate limit reached for gpt-4o-mini."}}`, false},
		{"busy", 503, `{"error":{"message":"This model is currently experiencing high demand."}}`, false},
		// A complaint about the probe's own tiny budget still proves the request
		// authenticated and the account can pay.
		{"budget too small", 400, `{"error":{"message":"Could not finish the message because max_tokens was reached."}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer h.Close()
			s := testServer(t, map[string]ProviderConfig{"openai": {URL: h.URL, KeyEnv: "PROVIDER_KEY"}})
			reason := s.probeOne(context.Background(),
				Route{Provider: "openai", Model: "test-model"},
				ProviderConfig{URL: h.URL, KeyEnv: "PROVIDER_KEY"})
			if got := reason != ""; got != tc.wantFail {
				t.Fatalf("status %d: failed=%v (%q), want failed=%v", tc.status, got, reason, tc.wantFail)
			}
		})
	}
}

func TestProbeOneUnreachableProviderFails(t *testing.T) {
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: "http://127.0.0.1:1", KeyEnv: "PROVIDER_KEY"}})
	reason := s.probeOne(context.Background(),
		Route{Provider: "openai", Model: "test-model"},
		ProviderConfig{URL: "http://127.0.0.1:1", KeyEnv: "PROVIDER_KEY"})
	if reason == "" {
		t.Fatal("an unreachable provider passed the check")
	}
}

func TestProbeProvidersWithholdsAFailedProvider(t *testing.T) {
	var calls int
	bad := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"message":"Incorrect API key provided"}}`)
	}))
	defer bad.Close()
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: bad.URL, KeyEnv: "PROVIDER_KEY"}})
	s.ProbeProviders(context.Background())

	if calls != 1 {
		t.Errorf("provider probed %d times, want exactly 1", calls)
	}
	if s.Metrics.ProviderProbeFailed.Load() != 1 {
		t.Errorf("ProviderProbeFailed = %d, want 1", s.Metrics.ProviderProbeFailed.Load())
	}
	// Withheld from routing, so a request tries something else instead of
	// repeating a failure the gateway already knows about.
	if s.circuits["openai"].allow() {
		t.Error("a provider that failed its check is still offered to routing")
	}
	// Not a health failure: the provider may be perfectly healthy and only the
	// credentials wrong. Counting it would open the breaker against a service
	// that works.
	if s.circuits["openai"].failures != 0 {
		t.Errorf("failed check counted as a provider health failure: %d", s.circuits["openai"].failures)
	}
}

// Providers absent from local config are not probed: the policy may name a route
// this deployment deliberately does not carry credentials for.
func TestProbeProvidersSkipsUnconfiguredRoutes(t *testing.T) {
	var calls int
	h := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		io.WriteString(w, `{"choices":[{"index":0,"message":{"content":"ok"},"finish_reason":"stop"}]}`)
	}))
	defer h.Close()
	// testPolicy routes to openai, anthropic and gemini; only one is configured.
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: h.URL, KeyEnv: "PROVIDER_KEY"}})
	s.ProbeProviders(context.Background())
	if calls != 1 {
		t.Fatalf("probed %d times, want 1 (only the configured provider)", calls)
	}
	if s.Metrics.ProviderProbeFailed.Load() != 0 {
		t.Error("an unconfigured route was counted as a failure")
	}
}

// The regression this fix exists for. A latch made /readyz stay 503 until the
// process restarted, even after routing had already recovered.
func TestStrictReadinessRecoversWithoutRestart(t *testing.T) {
	fail := true
	h := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":{"message":"Incorrect API key provided"}}`)
			return
		}
		io.WriteString(w, `{"choices":[{"index":0,"message":{"content":"hello"},"finish_reason":"stop"}]}`)
	}))
	defer h.Close()
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: h.URL, KeyEnv: "PROVIDER_KEY"}})
	s.C.ProviderCheckStrict = true

	if !s.readyz() {
		t.Fatal("not ready before the check has run")
	}
	s.ProbeProviders(context.Background())
	if s.readyz() {
		t.Fatal("strict mode stayed ready despite a failed provider check")
	}
	// It must still serve. Refusing requests would deadlock recovery, because a
	// successful request is the only thing that clears a failed check.
	if !s.ready() {
		t.Fatal("strict mode stopped serving entirely; recovery can never happen")
	}

	// The provider recovers. Routing returns via the breaker's half-open probe,
	// and readiness must follow rather than waiting for a restart.
	fail = false
	// cooldown deliberately never shortens an existing wait, so expire it the
	// way the breaker's own tests do rather than fighting that rule.
	s.circuits["openai"].mu.Lock()
	s.circuits["openai"].until = time.Now().Add(-time.Second)
	s.circuits["openai"].mu.Unlock()
	if w := call(s, chat); w.Code != 200 {
		t.Fatalf("recovered provider did not serve: %d %s", w.Code, w.Body)
	}
	if !s.readyz() {
		t.Fatal("readiness did not recover after a successful request through the provider")
	}
}

// Default mode must not gate readiness at all, or one unreachable provider would
// take down a gateway whose entire purpose is to route around that.
func TestNonStrictReadinessIgnoresAFailedCheck(t *testing.T) {
	bad := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"message":"Incorrect API key provided"}}`)
	}))
	defer bad.Close()
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: bad.URL, KeyEnv: "PROVIDER_KEY"}})
	s.ProbeProviders(context.Background())
	if !s.readyz() {
		t.Fatal("a failed check made the default configuration unready")
	}
}

func TestAwaitPolicyReturnsOnCancelledContext(t *testing.T) {
	s := testServer(t, map[string]ProviderConfig{})
	s.Policies = &PolicyStore{Tenant: "tenant-a"} // no policy will ever arrive
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan *Policy, 1)
	go func() { done <- s.awaitPolicy(ctx) }()
	select {
	case p := <-done:
		if p != nil {
			t.Fatal("returned a policy that does not exist")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("awaitPolicy ignored a cancelled context")
	}
}

func TestProbeProvidersLogsNothingWhenPolicyNeverArrives(t *testing.T) {
	s := testServer(t, map[string]ProviderConfig{})
	s.Policies = &PolicyStore{Tenant: "tenant-a"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.ProbeProviders(ctx) // must return rather than block
	if s.Metrics.ProviderProbeFailed.Load() != 0 {
		t.Error("counted a failure without a policy to probe against")
	}
	_ = strings.TrimSpace("")
}
