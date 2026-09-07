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
