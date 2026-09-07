package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExpiredCacheRetainsVersionAndCanRecover(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	s := &PolicyStore{Tenant: "tenant-a", Keys: map[string]ed25519.PublicKey{"k": pub}}
	p := testPolicy()
	p.Version = 10
	p.IssuedAt = time.Now().Unix() - 100
	p.ExpiresAt = time.Now().Unix() - 1
	if e := s.Restore(signed(t, p, key, "k")); e != nil {
		t.Fatal(e)
	}
	if s.Current() != nil {
		t.Fatal("expired policy active")
	}
	p = testPolicy()
	p.Version = 9
	if s.Apply(signed(t, p, key, "k"), false) == nil {
		t.Fatal("lost high-water mark")
	}
	p.Version = 11
	if e := s.Apply(signed(t, p, key, "k"), false); e != nil || s.Current() == nil {
		t.Fatal(e)
	}
}

type failingTransport struct{ calls int }

func (f *failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.calls++
	return nil, errors.New("ambiguous failure")
}
func TestTransportAmbiguityNotReplayed(t *testing.T) {
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: "https://api.openai.com", KeyEnv: "PROVIDER_KEY"}, "anthropic": {URL: "https://api.anthropic.com", KeyEnv: "PROVIDER_KEY"}})
	f := &failingTransport{}
	s.HTTP.Transport = f
	if call(s, chat).Code != 502 || f.calls != 1 {
		t.Fatal("ambiguous request replayed")
	}
}
func TestCancelledRequestNotReplayed(t *testing.T) {
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: "https://api.openai.com", KeyEnv: "PROVIDER_KEY"}})
	f := &failingTransport{}
	s.HTTP.Transport = f
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(chat)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 32))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 502 || s.circuits["openai"].failures != 0 {
		t.Fatal("cancellation penalized provider")
	}
}
func TestMetricsHistogram(t *testing.T) {
	m := &Metrics{}
	m.ObserveLatency(300)
	m.ObserveLatency(800)
	w := httptest.NewRecorder()
	m.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(w.Body.String(), `switchboard_request_duration_milliseconds_bucket{le="500"} 1`) || !strings.Contains(w.Body.String(), "switchboard_request_duration_milliseconds_count 2") {
		t.Fatal(w.Body.String())
	}
}
