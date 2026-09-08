package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const success = `{"choices":[{"index":0,"message":{"content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":1}}`

func testServer(t *testing.T, providers map[string]ProviderConfig) *Server {
	t.Helper()
	t.Setenv("LOCAL_TOKEN", strings.Repeat("x", 32))
	t.Setenv("CP_TOKEN", strings.Repeat("y", 32))
	t.Setenv("PROVIDER_KEY", "test-only")
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	p := &PolicyStore{Tenant: "tenant-a", Keys: map[string]ed25519.PublicKey{"k": pub}}
	if e := p.Apply(signed(t, testPolicy(), key, "k"), false); e != nil {
		t.Fatal(e)
	}
	c := Config{Tenant: "tenant-a", Listen: "127.0.0.1:8080", Providers: providers, DataDir: t.TempDir(), LocalTokenEnv: "LOCAL_TOKEN", ControlTokenEnv: "CP_TOKEN", ControlURL: "http://127.0.0.1:1", Concurrency: 2, Rate: 1000, Burst: 1000, RetryRate: 100, MaxAttempts: 3, TimeoutSeconds: 2, QueueSize: 4, SpoolBytes: 1 << 20, AllowLocalHTTP: true}
	s := New(c, p, &Metrics{}, nil)
	useTestTransport(s.HTTP)
	return s
}
func call(s *Server, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 32))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

const chat = `{"model":"preferred","messages":[{"role":"user","content":"hi"}]}`

func TestFailoverAndControlDown(t *testing.T) {
	var first, second atomic.Int64
	a := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { first.Add(1); w.WriteHeader(503) }))
	defer a.Close()
	b := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		second.Add(1)
		io.WriteString(w, `{"content":[{"type":"text","text":"rescued"}],"stop_reason":"end_turn"}`)
	}))
	defer b.Close()
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: a.URL, KeyEnv: "PROVIDER_KEY"}, "anthropic": {URL: b.URL, KeyEnv: "PROVIDER_KEY"}})
	s.syncOnce(context.Background())
	w := call(s, chat)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "rescued") || first.Load() != 1 || second.Load() != 1 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if s.Metrics.PolicyErrors.Load() != 1 {
		t.Fatal("control down not observed")
	}
}
func TestNoReplayAfterAcceptanceOrAmbiguity(t *testing.T) {
	for _, status := range []int{200, 400, 401, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var fallback atomic.Int64
			a := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				io.WriteString(w, `{"broken":true}`)
			}))
			defer a.Close()
			b := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fallback.Add(1) }))
			defer b.Close()
			s := testServer(t, map[string]ProviderConfig{"openai": {URL: a.URL, KeyEnv: "PROVIDER_KEY"}, "anthropic": {URL: b.URL, KeyEnv: "PROVIDER_KEY"}})
			w := call(s, chat)
			if w.Code < 400 || fallback.Load() != 0 {
				t.Fatal("unsafe replay")
			}
		})
	}
}
func TestLimitsAndAuth(t *testing.T) {
	s := testServer(t, nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(chat)))
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	s.C.Providers = map[string]ProviderConfig{"openai": {URL: "http://127.0.0.1:1", KeyEnv: "PROVIDER_KEY"}}
	s.slots <- struct{}{}
	s.slots <- struct{}{}
	if w := call(s, chat); w.Code != 429 {
		t.Fatal(w.Code)
	}
	<-s.slots
	<-s.slots
	s.rate = newBucket(1, 1)
	s.rate.allow()
	if call(s, chat).Code != 429 {
		t.Fatal("rate limit")
	}
	s.Draining.Store(true)
	if call(s, chat).Code != 503 {
		t.Fatal("drain")
	}
}
func TestUnsupportedInputs(t *testing.T) {
	for _, b := range []string{`{"model":"preferred","tools":[],"messages":[{"role":"user","content":"hi"}]}`, `{"model":"preferred","messages":[{"role":"tool","content":"hi"}]}`, `{"model":"preferred","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`, `{"model":"preferred","messages":[{"role":"assistant","content":"hi"}]}`, chat + `{}`} {
		if _, e := ParseChat([]byte(b)); e == nil {
			t.Fatal("accepted unsupported input", b)
		}
	}
}
func TestCircuitSingleProbe(t *testing.T) {
	c := &circuit{}
	for i := 0; i < 3; i++ {
		c.result(true)
	}
	if c.allow() {
		t.Fatal("open circuit allowed")
	}
	c.until = time.Now().Add(-time.Second)
	if !c.allow() || c.allow() {
		t.Fatal("single probe violated")
	}
	c.result(false)
	if !c.allow() {
		t.Fatal("circuit did not close")
	}
}
func TestRetryBudget(t *testing.T) {
	var calls atomic.Int64
	a := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(429) }))
	defer a.Close()
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: a.URL, KeyEnv: "PROVIDER_KEY"}, "anthropic": {URL: a.URL, KeyEnv: "PROVIDER_KEY"}})
	s.retry = newBucket(1, 1)
	s.retry.allow()
	if call(s, chat).Code != 503 || calls.Load() != 1 {
		t.Fatal("retry budget exceeded")
	}
}
func TestIdempotencyRejected(t *testing.T) {
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: "http://127.0.0.1:1", KeyEnv: "PROVIDER_KEY"}})
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(chat))
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 32))
	r.Header.Set("Idempotency-Key", "abc")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}

// Verbatim from the real Anthropic API. Reported as 400, which the routing loop
// used to read as "this request is malformed" and refuse to fail over on, while
// a funded provider sat unused in the same policy.
const anthropicNoCredit = `{"type":"error","error":{"type":"invalid_request_error","message":` +
	`"Your credit balance is too low to access the Anthropic API. Please go to Plans & Billing to upgrade or purchase credits."}}`

func TestAccountFailureFailsOver(t *testing.T) {
	var first, second atomic.Int64
	a := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first.Add(1)
		w.WriteHeader(400)
		io.WriteString(w, anthropicNoCredit)
	}))
	defer a.Close()
	b := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		second.Add(1)
		io.WriteString(w, `{"content":[{"type":"text","text":"rescued"}],"stop_reason":"end_turn"}`)
	}))
	defer b.Close()
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: a.URL, KeyEnv: "PROVIDER_KEY"}, "anthropic": {URL: b.URL, KeyEnv: "PROVIDER_KEY"}})
	w := call(s, chat)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "rescued") {
		t.Fatalf("no failover on an unpayable account: %d %s", w.Code, w.Body)
	}
	if first.Load() != 1 || second.Load() != 1 {
		t.Fatalf("attempts: first=%d second=%d", first.Load(), second.Load())
	}
	if w.Header().Get("X-Switchboard-Provider") != "anthropic" {
		t.Errorf("caller cannot see which provider answered: %q", w.Header().Get("X-Switchboard-Provider"))
	}
	if s.Metrics.AccountFailover.Load() != 1 {
		t.Errorf("AccountFailover = %d, want 1", s.Metrics.AccountFailover.Load())
	}
	// The provider is healthy; only this account cannot pay. Blaming the
	// provider would open the breaker against a service that is working.
	if s.circuits["openai"].failures != 0 {
		t.Errorf("an unpayable account was counted as a provider health failure")
	}
}

// The counterpart, and the more important direction: a request that is genuinely
// malformed would be refused identically everywhere, so replaying it across
// every provider multiplies the waste instead of avoiding it.
func TestMalformedRequestDoesNotFailOver(t *testing.T) {
	var fallback atomic.Int64
	a := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		io.WriteString(w, `{"error":{"message":"messages: at least one message is required"}}`)
	}))
	defer a.Close()
	b := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fallback.Add(1) }))
	defer b.Close()
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: a.URL, KeyEnv: "PROVIDER_KEY"}, "anthropic": {URL: b.URL, KeyEnv: "PROVIDER_KEY"}})
	w := call(s, chat)
	if fallback.Load() != 0 {
		t.Fatal("a malformed request was replayed to a second provider")
	}
	// The caller should learn why, not just that something was rejected.
	if !strings.Contains(w.Body.String(), "at least one message is required") {
		t.Errorf("provider's own reason not surfaced: %s", w.Body)
	}
}

// A reasoning model can spend its whole token budget on hidden reasoning and
// return no visible text, billed in full. Measured on gpt-5-nano: 1024 tokens
// in, 1024 spent reasoning, zero characters out. Reporting that as a 200 charges
// the caller for an empty answer.
const emptyByBudget = `{"choices":[{"index":0,"message":{"content":""},"finish_reason":"length"}],` +
	`"usage":{"prompt_tokens":9,"completion_tokens":1024,"completion_tokens_details":{"reasoning_tokens":1024}}}`

func TestEmptyCompletionFailsOver(t *testing.T) {
	var second atomic.Int64
	a := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, emptyByBudget)
	}))
	defer a.Close()
	b := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		second.Add(1)
		io.WriteString(w, `{"content":[{"type":"text","text":"rescued"}],"stop_reason":"end_turn"}`)
	}))
	defer b.Close()
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: a.URL, KeyEnv: "PROVIDER_KEY"}, "anthropic": {URL: b.URL, KeyEnv: "PROVIDER_KEY"}})
	w := call(s, chat)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "rescued") {
		t.Fatalf("an empty completion was returned as success: %d %s", w.Code, w.Body)
	}
	if second.Load() != 1 {
		t.Fatalf("second provider called %d times", second.Load())
	}
	if s.Metrics.EmptyCompletion.Load() != 1 {
		t.Errorf("EmptyCompletion = %d, want 1", s.Metrics.EmptyCompletion.Load())
	}
}

// When no provider can produce output, the caller must be told that rather than
// receiving a generic routing failure, because the fix is theirs to make.
func TestAllProvidersEmptyNamesTheCause(t *testing.T) {
	a := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, emptyByBudget)
	}))
	defer a.Close()
	// The same failure in Anthropic's shape: the budget ran out before any
	// content block was produced.
	b := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"content":[],"stop_reason":"max_tokens","usage":{"input_tokens":9,"output_tokens":1024}}`)
	}))
	defer b.Close()
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: a.URL, KeyEnv: "PROVIDER_KEY"}, "anthropic": {URL: b.URL, KeyEnv: "PROVIDER_KEY"}})
	w := call(s, chat)
	if w.Code != 503 {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if !strings.Contains(w.Body.String(), "max_tokens") {
		t.Errorf("failure does not name the cause: %s", w.Body)
	}
}

// The streaming equivalent. Failover is only legitimate here because the frame
// carrying the truncation reason is held back, so no byte has reached the client.
func TestEmptyStreamFailsOverBeforeAnyByteIsSent(t *testing.T) {
	var second atomic.Int64
	a := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"length\"}]}\n\n")
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer a.Close()
	b := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		second.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"rescued\"}}\n\n")
		io.WriteString(w, "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\n")
		io.WriteString(w, "data: {\"type\":\"message_stop\"}\n\n")
	}))
	defer b.Close()
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: a.URL, KeyEnv: "PROVIDER_KEY"}, "anthropic": {URL: b.URL, KeyEnv: "PROVIDER_KEY"}})
	w := call(s, `{"model":"preferred","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	if second.Load() != 1 {
		t.Fatalf("empty stream did not fail over; second provider called %d times", second.Load())
	}
	if !strings.Contains(w.Body.String(), "rescued") {
		t.Fatalf("body: %s", w.Body)
	}
	if s.Metrics.EmptyCompletion.Load() != 1 {
		t.Errorf("EmptyCompletion = %d, want 1", s.Metrics.EmptyCompletion.Load())
	}
}
