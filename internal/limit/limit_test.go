package limit

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func at(t time.Time) func() time.Time { return func() time.Time { return t } }

func newAt(t *testing.T, def Limits, now time.Time) *Limiter {
	t.Helper()
	l := New(def, nil)
	l.now = at(now)
	return l
}

func exceeded(t *testing.T, err error) *Exceeded {
	t.Helper()
	var e *Exceeded
	if !errors.As(err, &e) {
		t.Fatalf("want *Exceeded, got %T: %v", err, err)
	}
	return e
}

func TestUnconfiguredIsUnlimited(t *testing.T) {
	l := newAt(t, Limits{}, time.Now())
	for i := 0; i < 100; i++ {
		rel, err := l.Acquire("search")
		if err != nil {
			t.Fatalf("request %d refused with no limits set: %v", i, err)
		}
		rel()
	}
	var nilLimiter *Limiter
	if _, err := nilLimiter.Acquire("x"); err != nil {
		t.Errorf("a nil limiter should admit everything, got %v", err)
	}
}

func TestConcurrencyCeiling(t *testing.T) {
	l := newAt(t, Limits{Concurrent: 2}, time.Now())

	a, err := l.Acquire("search")
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.Acquire("search")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Acquire("search"); err == nil {
		t.Fatal("the third concurrent request must be refused")
	} else if e := exceeded(t, err); e.Limit != "concurrency" {
		t.Errorf("limit = %q", e.Limit)
	}

	a()
	if _, err := l.Acquire("search"); err != nil {
		t.Errorf("a slot freed should admit the next request: %v", err)
	}
	b()
}

// Releasing twice must not free a slot that was never held.
func TestReleaseIsIdempotent(t *testing.T) {
	l := newAt(t, Limits{Concurrent: 1}, time.Now())
	rel, _ := l.Acquire("t")
	rel()
	rel()
	rel()

	a, err := l.Acquire("t")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Acquire("t"); err == nil {
		t.Error("repeated releases should not have inflated the ceiling")
	}
	a()
}

func TestRequestRateRefillsOverTime(t *testing.T) {
	now := time.Now()
	l := newAt(t, Limits{RequestsPerMinute: 60}, now)

	for i := 0; i < 60; i++ {
		rel, err := l.Acquire("t")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		rel()
	}
	_, err := l.Acquire("t")
	if err == nil {
		t.Fatal("the 61st request in the same instant must be refused")
	}
	e := exceeded(t, err)
	if e.Limit != "request rate" {
		t.Errorf("limit = %q", e.Limit)
	}
	if e.RetryAfter <= 0 || e.RetryAfter > time.Minute {
		t.Errorf("retry after = %s, should be about a second at 60/min", e.RetryAfter)
	}

	// One second later, one more request is allowed.
	l.now = at(now.Add(time.Second))
	if rel, err := l.Acquire("t"); err != nil {
		t.Errorf("a second of refill should admit one request: %v", err)
	} else {
		rel()
	}
}

// The budget is the limit finance cares about, and the only one a patient
// caller cannot wait out.
func TestTokenBudgetStopsSpend(t *testing.T) {
	now := time.Now()
	l := newAt(t, Limits{TokensPerWindow: 1000, Window: time.Hour}, now)

	rel, err := l.Acquire("search")
	if err != nil {
		t.Fatal(err)
	}
	rel()
	l.Charge("search", 1200) // one completion overshoots

	_, err = l.Acquire("search")
	if err == nil {
		t.Fatal("a team over budget must be refused")
	}
	e := exceeded(t, err)
	if e.Limit != "token budget" {
		t.Errorf("limit = %q", e.Limit)
	}
	if e.RetryAfter <= 0 || e.RetryAfter > time.Hour {
		t.Errorf("retry after = %s, want the remainder of the window", e.RetryAfter)
	}

	// The window rolls and the allowance returns.
	l.now = at(now.Add(time.Hour + time.Second))
	if rel, err := l.Acquire("search"); err != nil {
		t.Errorf("a new window should restore the budget: %v", err)
	} else {
		rel()
	}
}

// Charging afterwards means one request of overshoot, which is deliberate:
// reserving would need to predict a completion's length.
func TestOvershootIsBoundedToOneRequest(t *testing.T) {
	l := newAt(t, Limits{TokensPerWindow: 100, Window: time.Hour}, time.Now())
	rel, _ := l.Acquire("t")
	rel()
	l.Charge("t", 10000)

	if _, err := l.Acquire("t"); err == nil {
		t.Fatal("the next request must be refused, however far the overshoot went")
	}
	used, allowed := l.Spent("t")
	if used != 10000 || allowed != 100 {
		t.Errorf("Spent = %d/%d", used, allowed)
	}
}

func TestTeamsAreIndependent(t *testing.T) {
	l := newAt(t, Limits{Concurrent: 1}, time.Now())
	a, err := l.Acquire("search")
	if err != nil {
		t.Fatal(err)
	}
	if rel, err := l.Acquire("billing"); err != nil {
		t.Errorf("one team's ceiling must not bind another: %v", err)
	} else {
		rel()
	}
	a()
}

func TestPerTeamOverrides(t *testing.T) {
	l := New(Limits{Concurrent: 1, Window: time.Hour},
		map[string]Limits{"search": {Concurrent: 3}})
	l.now = at(time.Now())

	var rels []func()
	for i := 0; i < 3; i++ {
		rel, err := l.Acquire("search")
		if err != nil {
			t.Fatalf("override should allow 3, failed at %d: %v", i, err)
		}
		rels = append(rels, rel)
	}
	if _, err := l.Acquire("search"); err == nil {
		t.Error("the override's own ceiling should still bind")
	}
	// A team without an override gets the default.
	if _, err := l.Acquire("other"); err != nil {
		t.Errorf("default should admit one: %v", err)
	}
	for _, r := range rels {
		r()
	}
}

// Unattributed callers share one allowance, so an anonymous flood is bounded
// even when require_caller is off.
func TestUnattributedCallersShareABucket(t *testing.T) {
	l := newAt(t, Limits{Concurrent: 1}, time.Now())
	a, err := l.Acquire("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Acquire(""); err == nil {
		t.Error("unattributed requests must share a ceiling")
	} else if e := exceeded(t, err); e.Error() == "" || !contains(e.Error(), "unattributed") {
		t.Errorf("the message should name them, got %q", e.Error())
	}
	a()
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestConcurrentAcquireIsRaceFree(t *testing.T) {
	l := New(Limits{Concurrent: 5, RequestsPerMinute: 10000, Window: time.Hour}, nil)

	var wg sync.WaitGroup
	var admitted int
	var mu sync.Mutex
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := l.Acquire("t")
			if err != nil {
				return
			}
			mu.Lock()
			admitted++
			mu.Unlock()
			l.Charge("t", 10)
			rel()
		}()
	}
	wg.Wait()
	if admitted == 0 {
		t.Error("nothing was admitted")
	}
}
