// Package limit bounds what a caller may consume.
//
// This is MITRE ATLAS AML.M0004, Limit Model Queries — the defence against a
// runaway caller and against denial of wallet, which with metered inference are
// the same incident seen from two directions.
//
// It is deliberately a structural control. Nothing here inspects content or
// forms an opinion about what a request means; it counts, and it refuses. A
// gateway is well placed to do that and badly placed to guess at intent.
//
// Three limits, because they fail differently. A request rate bounds how fast a
// caller can ask. A concurrency ceiling bounds how much work is in flight at
// once, which is what protects a shared local model from one caller. A token
// budget over a window bounds spend, which is the one finance cares about and
// the only one that survives a caller who is patient.
package limit

import (
	"fmt"
	"sync"
	"time"
)

// Limits is a caller's allowance. A zero field is unlimited, so a partial
// configuration restricts only what it names.
type Limits struct {
	RequestsPerMinute int           `json:"requests_per_minute,omitempty"`
	Concurrent        int           `json:"concurrent,omitempty"`
	TokensPerWindow   int           `json:"tokens_per_window,omitempty"`
	Window            time.Duration `json:"-"`
}

// Empty reports whether this allowance constrains anything.
func (l Limits) Empty() bool {
	return l.RequestsPerMinute == 0 && l.Concurrent == 0 && l.TokensPerWindow == 0
}

// Exceeded says which limit stopped a request and when it will not.
//
// The distinction matters to whoever is holding the 429: "slow down" and "your
// team has spent its budget for the day" need different responses, and a
// generic refusal makes someone guess.
type Exceeded struct {
	Limit      string
	Team       string
	RetryAfter time.Duration
	Detail     string
}

func (e *Exceeded) Error() string {
	who := e.Team
	if who == "" {
		who = "unattributed callers"
	}
	return fmt.Sprintf("%s: %s limit reached (%s)", who, e.Limit, e.Detail)
}

// Limiter enforces allowances per caller.
type Limiter struct {
	def   Limits
	teams map[string]Limits

	now func() time.Time
	mu  sync.Mutex
	st  map[string]*state
}

type state struct {
	// Token bucket for the request rate.
	allowance float64
	lastFill  time.Time

	inflight int

	spent       int
	windowStart time.Time
}

// New builds a limiter with a default allowance and per-team overrides.
func New(def Limits, teams map[string]Limits) *Limiter {
	if def.Window == 0 {
		def.Window = 24 * time.Hour
	}
	for name, l := range teams {
		if l.Window == 0 {
			l.Window = def.Window
			teams[name] = l
		}
	}
	return &Limiter{def: def, teams: teams, now: time.Now, st: map[string]*state{}}
}

func (l *Limiter) limitsFor(team string) Limits {
	if v, ok := l.teams[team]; ok {
		return v
	}
	return l.def
}

// Acquire admits one request, returning the function that releases it.
//
// The release is returned rather than deferred internally because a streaming
// completion holds its slot until the last token, not until the handler
// returns.
func (l *Limiter) Acquire(team string) (func(), error) {
	if l == nil {
		return func() {}, nil
	}
	lim := l.limitsFor(team)
	if lim.Empty() {
		return func() {}, nil
	}

	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	s := l.st[team]
	if s == nil {
		s = &state{allowance: float64(lim.RequestsPerMinute), lastFill: now, windowStart: now}
		l.st[team] = s
	}

	// Spend first: a caller over budget should be told that, not told to slow
	// down, because slowing down will not help them.
	if lim.TokensPerWindow > 0 {
		if now.Sub(s.windowStart) >= lim.Window {
			s.spent, s.windowStart = 0, now
		}
		if s.spent >= lim.TokensPerWindow {
			return nil, &Exceeded{
				Limit: "token budget", Team: team,
				RetryAfter: lim.Window - now.Sub(s.windowStart),
				Detail: fmt.Sprintf("%d of %d tokens used this %s",
					s.spent, lim.TokensPerWindow, lim.Window),
			}
		}
	}

	if lim.Concurrent > 0 && s.inflight >= lim.Concurrent {
		return nil, &Exceeded{
			Limit: "concurrency", Team: team, RetryAfter: time.Second,
			Detail: fmt.Sprintf("%d requests already in flight, ceiling is %d",
				s.inflight, lim.Concurrent),
		}
	}

	if lim.RequestsPerMinute > 0 {
		perSecond := float64(lim.RequestsPerMinute) / 60
		s.allowance += now.Sub(s.lastFill).Seconds() * perSecond
		if s.allowance > float64(lim.RequestsPerMinute) {
			s.allowance = float64(lim.RequestsPerMinute)
		}
		s.lastFill = now

		if s.allowance < 1 {
			wait := time.Duration((1 - s.allowance) / perSecond * float64(time.Second))
			return nil, &Exceeded{
				Limit: "request rate", Team: team, RetryAfter: wait,
				Detail: fmt.Sprintf("%d requests per minute", lim.RequestsPerMinute),
			}
		}
		s.allowance--
	}

	s.inflight++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			if s.inflight > 0 {
				s.inflight--
			}
		})
	}, nil
}

// Charge records tokens actually consumed.
//
// Charging afterwards rather than reserving up front means a caller can overrun
// its budget by one request. Reserving would need a prediction of how many
// tokens a completion will use, which is not knowable, and the alternative —
// refusing anything that might overrun — turns a budget into a much lower one.
// One request of overshoot is the honest price of that.
func (l *Limiter) Charge(team string, tokens int) {
	if l == nil || tokens <= 0 {
		return
	}
	lim := l.limitsFor(team)
	if lim.TokensPerWindow == 0 {
		return
	}

	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	s := l.st[team]
	if s == nil {
		s = &state{allowance: float64(lim.RequestsPerMinute), lastFill: now, windowStart: now}
		l.st[team] = s
	}
	if now.Sub(s.windowStart) >= lim.Window {
		s.spent, s.windowStart = 0, now
	}
	s.spent += tokens
}

// Spent reports current usage against the window, for reporting.
func (l *Limiter) Spent(team string) (used, allowed int) {
	if l == nil {
		return 0, 0
	}
	lim := l.limitsFor(team)
	l.mu.Lock()
	defer l.mu.Unlock()
	if s := l.st[team]; s != nil {
		if l.now().Sub(s.windowStart) < lim.Window {
			used = s.spent
		}
	}
	return used, lim.TokensPerWindow
}
