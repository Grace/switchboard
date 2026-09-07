package gateway

import (
	"net/http"
	"testing"
	"time"
)

func TestRetryAfterParsing(t *testing.T) {
	for _, tc := range []struct {
		name, header string
		want         time.Duration
	}{
		{"absent", "", 0},
		{"seconds", "20", 20 * time.Second},
		{"seconds with spaces", "  5 ", 5 * time.Second},
		{"zero means nothing useful", "0", 0},
		{"negative is ignored", "-30", 0},
		{"garbage is ignored", "soon", 0},
		// An uncapped value would park a route indefinitely, and the header is
		// reachable by anything upstream that can set a response header.
		{"absurd value is capped", "999999", maxCooldown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryAfter(tc.header); got != tc.want {
				t.Fatalf("retryAfter(%q) = %v, want %v", tc.header, got, tc.want)
			}
		})
	}
}

func TestRetryAfterHTTPDate(t *testing.T) {
	// http.TimeFormat, not time.RFC1123: HTTP requires the IMF-fixdate form
	// ending in GMT, and RFC1123 renders a UTC time as "UTC", which is not
	// conformant and is correctly rejected.
	future := time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)
	got := retryAfter(future)
	if got < 20*time.Second || got > 31*time.Second {
		t.Fatalf("an HTTP-date 30s out gave %v, want roughly 30s", got)
	}
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	if got := retryAfter(past); got != 0 {
		t.Fatalf("a date in the past gave %v, want 0", got)
	}
}

// A cooldown is a provider asking to be left alone. It must withhold the route
// without counting as evidence the provider is unhealthy, or a rate limit would
// trip the breaker against a provider that is working.
func TestCooldownDoesNotTripTheBreaker(t *testing.T) {
	c := &circuit{}
	for i := 0; i < 10; i++ {
		c.cooldown(time.Millisecond)
	}
	if c.failures != 0 {
		t.Fatalf("cooldown recorded %d failures, want 0", c.failures)
	}
	time.Sleep(5 * time.Millisecond)
	if !c.allow() {
		t.Fatal("route still withheld after its cooldown elapsed")
	}
}

func TestCooldownWithholdsThenReleases(t *testing.T) {
	c := &circuit{}
	c.cooldown(50 * time.Millisecond)
	if c.allow() {
		t.Fatal("route admitted during its cooldown")
	}
	time.Sleep(60 * time.Millisecond)
	if !c.allow() {
		t.Fatal("route not admitted after the cooldown elapsed")
	}
}

// Two providers can ask for different waits; the longer one must win, or a
// short cooldown arriving second would cut a long one short.
func TestCooldownExtendsButNeverShortens(t *testing.T) {
	c := &circuit{}
	c.cooldown(2 * time.Second)
	long := c.until
	c.cooldown(10 * time.Millisecond)
	if c.until.Before(long) {
		t.Fatal("a shorter cooldown shortened a longer one")
	}
}

// Three failures still open the breaker: separating 429 from 503 must not
// weaken the mechanism for genuine unhealthiness.
func TestBreakerStillOpensOnRealFailures(t *testing.T) {
	c := &circuit{}
	for i := 0; i < 3; i++ {
		if !c.allow() {
			t.Fatalf("attempt %d refused before the breaker should have opened", i)
		}
		c.result(true)
	}
	if c.allow() {
		t.Fatal("breaker did not open after three failures")
	}
}
