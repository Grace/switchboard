package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func idemServer(t *testing.T, providers map[string]ProviderConfig) *Server {
	t.Helper()
	s := testServer(t, providers)
	store, err := NewIdemStore(t.TempDir(), time.Minute, 1<<20, s.Metrics)
	if err != nil {
		t.Fatal(err)
	}
	s.Idem = store
	return s
}

func callKeyed(s *Server, body, key string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 32))
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// The entire point. A retried key must not reach the provider again, because
// the second call is the one that charges twice.
func TestDuplicateKeyDoesNotCallTheProviderAgain(t *testing.T) {
	var calls atomic.Int64
	h := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, success)
	}))
	defer h.Close()
	s := idemServer(t, map[string]ProviderConfig{"openai": {URL: h.URL, KeyEnv: "PROVIDER_KEY"}})

	first := callKeyed(s, chat, "key-1")
	if first.Code != 200 {
		t.Fatalf("first request: %d %s", first.Code, first.Body)
	}
	second := callKeyed(s, chat, "key-1")
	if second.Code != 200 {
		t.Fatalf("replay: %d %s", second.Code, second.Body)
	}
	if calls.Load() != 1 {
		t.Fatalf("provider called %d times; the duplicate was charged", calls.Load())
	}
	if first.Body.String() != second.Body.String() {
		t.Error("replay returned a different body than the original")
	}
	if second.Header().Get("X-Switchboard-Replayed") != "true" {
		t.Error("a replay is indistinguishable from a fresh generation")
	}
	if s.Metrics.IdempotentReplay.Load() != 1 {
		t.Errorf("IdempotentReplay = %d, want 1", s.Metrics.IdempotentReplay.Load())
	}
}

// Answering a reused key with the first response would be silently wrong.
func TestSameKeyDifferentBodyIsRefused(t *testing.T) {
	h := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, success)
	}))
	defer h.Close()
	s := idemServer(t, map[string]ProviderConfig{"openai": {URL: h.URL, KeyEnv: "PROVIDER_KEY"}})
	callKeyed(s, chat, "key-2")
	w := callKeyed(s, `{"model":"preferred","messages":[{"role":"user","content":"different"}]}`, "key-2")
	if w.Code != 422 {
		t.Fatalf("status = %d, want 422; a different body got the first answer", w.Code)
	}
}

// The case the feature exists for: a transport error leaves generation genuinely
// ambiguous, so the key must stay held rather than let a retry pay again.
func TestUnknownOutcomeIsStickyAndRefusesRetry(t *testing.T) {
	s := idemServer(t, map[string]ProviderConfig{"openai": {URL: "https://openai.test", KeyEnv: "PROVIDER_KEY"}})
	s.HTTP.Transport = &failingTransport{}

	if w := callKeyed(s, chat, "key-3"); w.Code != 502 {
		t.Fatalf("first attempt: %d %s", w.Code, w.Body)
	}
	w := callKeyed(s, chat, "key-3")
	if w.Code != 409 {
		t.Fatalf("retry after an unknown outcome returned %d, want 409; it could charge twice", w.Code)
	}
	if !strings.Contains(w.Body.String(), "unknown") {
		t.Errorf("the refusal does not explain why: %s", w.Body)
	}
	if s.Metrics.IdempotentUnknown.Load() != 1 {
		t.Errorf("IdempotentUnknown = %d, want 1", s.Metrics.IdempotentUnknown.Load())
	}
}

// Holding a key after an unambiguous failure would be wrong in the other
// direction: the caller can fix the request, and should be able to retry.
func TestUnambiguousFailureReleasesTheKey(t *testing.T) {
	var calls atomic.Int64
	fail := true
	h := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if fail {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":{"message":"messages: at least one message is required"}}`)
			return
		}
		io.WriteString(w, success)
	}))
	defer h.Close()
	s := idemServer(t, map[string]ProviderConfig{"openai": {URL: h.URL, KeyEnv: "PROVIDER_KEY"}})

	if w := callKeyed(s, chat, "key-4"); w.Code != 400 {
		t.Fatalf("first attempt: %d", w.Code)
	}
	fail = false
	if w := callKeyed(s, chat, "key-4"); w.Code != 200 {
		t.Fatalf("retry after a provider 400 returned %d; the key was burned by a fixable error", w.Code)
	}
	if calls.Load() != 2 {
		t.Errorf("provider calls = %d, want 2", calls.Load())
	}
}

// Two requests arriving together must not both reach the provider.
func TestConcurrentDuplicatesReachTheProviderOnce(t *testing.T) {
	var calls atomic.Int64
	h := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(40 * time.Millisecond)
		io.WriteString(w, success)
	}))
	defer h.Close()
	s := idemServer(t, map[string]ProviderConfig{"openai": {URL: h.URL, KeyEnv: "PROVIDER_KEY"}})

	// Two, not more: testServer sets concurrency to 2, and extra goroutines would
	// be shed with 429 by the admission limiter before idempotency ever saw them.
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i := range codes {
		wg.Add(1)
		go func(i int) { defer wg.Done(); codes[i] = callKeyed(s, chat, "key-5").Code }(i)
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("provider called %d times for one key", calls.Load())
	}
	ok, conflict := 0, 0
	for _, c := range codes {
		switch c {
		case 200:
			ok++
		case 409:
			conflict++
		}
	}
	if ok != 1 || ok+conflict != len(codes) {
		t.Fatalf("codes = %v; want exactly one 200 and the rest 409", codes)
	}
}

// Off unless configured: entries hold customer content, so an upgrade must not
// silently start storing it.
func TestIdempotencyRefusedWhenNotConfigured(t *testing.T) {
	h := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, success) }))
	defer h.Close()
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: h.URL, KeyEnv: "PROVIDER_KEY"}})
	w := callKeyed(s, chat, "key-6")
	if w.Code != 400 || !strings.Contains(w.Body.String(), "idempotency_ttl_seconds") {
		t.Fatalf("status %d, body %s; want a 400 naming the setting that enables it", w.Code, w.Body)
	}
}

func TestExpiredEntryIsTreatedAsAbsent(t *testing.T) {
	var calls atomic.Int64
	h := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, success)
	}))
	defer h.Close()
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: h.URL, KeyEnv: "PROVIDER_KEY"}})
	store, err := NewIdemStore(t.TempDir(), time.Nanosecond, 1<<20, s.Metrics)
	if err != nil {
		t.Fatal(err)
	}
	s.Idem = store

	callKeyed(s, chat, "key-7")
	time.Sleep(2 * time.Millisecond)
	if w := callKeyed(s, chat, "key-7"); w.Code != 200 {
		t.Fatalf("expired entry did not behave as absent: %d", w.Code)
	}
	if calls.Load() != 2 {
		t.Errorf("provider calls = %d, want 2", calls.Load())
	}
}

// A replayed stream carries the same answer, not the original frame timing.
// docs/API.md says so; this asserts the answer part.
func TestStreamReplayDeliversTheSameAnswer(t *testing.T) {
	var calls atomic.Int64
	h := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"one two\"}}\n\n")
		io.WriteString(w, "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\n")
		io.WriteString(w, "data: {\"type\":\"message_stop\"}\n\n")
	}))
	defer h.Close()
	s := idemServer(t, map[string]ProviderConfig{"anthropic": {URL: h.URL, KeyEnv: "PROVIDER_KEY"}})
	body := `{"model":"preferred","stream":true,"messages":[{"role":"user","content":"hi"}]}`

	first := callKeyed(s, body, "stream-key")
	if first.Code != 200 || !strings.Contains(first.Body.String(), "one two") {
		t.Fatalf("first stream: %d %s", first.Code, first.Body)
	}
	second := callKeyed(s, body, "stream-key")
	if calls.Load() != 1 {
		t.Fatalf("provider called %d times; the replayed stream was charged", calls.Load())
	}
	if !strings.Contains(second.Body.String(), "one two") {
		t.Errorf("replayed stream lost the answer: %s", second.Body)
	}
	if !strings.Contains(second.Body.String(), "[DONE]") {
		t.Errorf("replayed stream has no terminator: %s", second.Body)
	}
	if second.Header().Get("X-Switchboard-Replayed") != "true" {
		t.Error("replayed stream is indistinguishable from a fresh one")
	}
}
