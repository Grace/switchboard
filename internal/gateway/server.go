package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type bucket struct {
	mu          sync.Mutex
	tokens      float64
	last        time.Time
	rate, burst float64
}

func newBucket(rate, burst int) *bucket {
	return &bucket{tokens: float64(burst), last: time.Now(), rate: float64(rate), burst: float64(burst)}
}
func (b *bucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens = min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type circuit struct {
	mu       sync.Mutex
	failures int
	until    time.Time
	probe    bool
}

func (c *circuit) allow() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.until.IsZero() {
		return true
	}
	if time.Now().Before(c.until) || c.probe {
		return false
	}
	c.probe = true
	return true
}

// wouldAllow is allow() without the claim. allow() sets probe as a side effect,
// which is correct when a route is being taken and wrong when a route is merely
// being counted -- a counting pass that called allow() would consume the
// half-open probe for a request that never went anywhere.
//
// It exists because eligibility used to be decided by two passes over different
// predicates. The pre-pass counted a route eligible on {configured, streams};
// the loop additionally required the breaker to allow it. So with a
// budget-shadowed route beside one whose breaker is open, eligible was 2 and
// len(skip) was 1, the "everything was skipped, try anyway" fallback did not
// fire, and the request 503'd having contacted nobody -- the exact outcome the
// comment below says must never happen.
func (c *circuit) wouldAllow() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.until.IsZero() || (!time.Now().Before(c.until) && !c.probe)
}

func (c *circuit) result(failed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.probe = false
	if !failed {
		c.failures = 0
		c.until = time.Time{}
		return
	}
	c.failures++
	if c.failures >= 3 {
		c.until = time.Now().Add(15 * time.Second)
	}
}
func (c *circuit) release() { c.mu.Lock(); c.probe = false; c.mu.Unlock() }

// cooldown withholds a provider for a period it asked for, without recording a
// failure. A 429 means this caller is over quota while the provider itself is
// healthy, so counting it toward the breaker would open the circuit against a
// provider that is working. Extends an existing wait, never shortens it.
func (c *circuit) cooldown(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.probe = false
	if until := time.Now().Add(d); until.After(c.until) {
		c.until = until
	}
}

// emptyRoute records a provider that answered and produced nothing, so an
// exhausted request can name what happened instead of failing anonymously.
// Bounded by construction: MaxAttempts is validated 1-3.
type emptyRoute struct {
	provider, model string
	budget          int // the caller's max_tokens
	reasoning       int // tokens the provider reported spending on hidden reasoning
}

func (e emptyRoute) String() string {
	// Only what was measured. The budget a route would actually have needed is
	// not a stable property: the same prompt was observed spending 1920 reasoning
	// tokens at a budget of 2048 and 1152 at 4096. Suggesting a number that then
	// also fails would be worse than suggesting none.
	if e.reasoning > 0 {
		return fmt.Sprintf("%s/%s spent all %d tokens on internal reasoning and returned none",
			e.provider, e.model, e.reasoning)
	}
	return fmt.Sprintf("%s/%s returned no output", e.provider, e.model)
}

// errStreamEmpty reports a stream that ended having produced no text and,
// crucially, having written nothing to the client. It is not a provider failure:
// the provider answered correctly and the answer was empty. Because no bytes
// were sent, the request may still fail over, which is the only window in which
// that is allowed.
var errStreamEmpty = errors.New("stream produced no output")

// accountCooldown withholds a provider whose account cannot serve. Longer than
// the breaker's 15 seconds, because no credits will not resolve in 15 seconds,
// and short enough that topping up a balance does not require a restart.
const accountCooldown = 60 * time.Second

// maxCooldown bounds what a provider can ask for. Retry-After is attacker- and
// bug-reachable, and an unbounded value would park a route indefinitely.
const maxCooldown = 5 * time.Minute

// retryAfter reads the delay a provider asked for. RFC 9110 permits either a
// number of seconds or an HTTP date. Anything unparseable, negative or beyond
// maxCooldown yields zero, meaning "no usable instruction".
func retryAfter(h string) time.Duration {
	if h == "" {
		return 0
	}
	if n, err := strconv.Atoi(strings.TrimSpace(h)); err == nil {
		if n <= 0 {
			return 0
		}
		return min(time.Duration(n)*time.Second, maxCooldown)
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := time.Until(t); d > 0 {
			return min(d, maxCooldown)
		}
	}
	return 0
}

type Server struct {
	C           Config
	Policies    *PolicyStore
	Metrics     *Metrics
	Telemetry   *Telemetry
	HTTP        *http.Client
	Bedrock     *BedrockSigner
	slots       chan struct{}
	rate, retry *bucket
	circuits    map[string]*circuit
	// budgets remembers which models have been seen returning nothing at a given
	// token budget, so a request is not sent to a route already watched fail.
	budgets *budgetTable
	// temps remembers which models refused a temperature, so the 400 is paid
	// once per model rather than on every request. See temperature.go.
	temps *temperatureTable
	// Idem is nil unless idempotency_ttl_seconds is set. Nil means the feature is
	// off and a key is refused, which is the behaviour before it existed.
	Idem *idemStore
	// Capture is nil unless capture_ttl_seconds is set, and nil is the default.
	// Nil means no prompt or completion is written anywhere, which is the
	// behaviour before this existed and the behaviour a deployment gets unless
	// someone asked for otherwise.
	Capture  *captureStore
	Draining atomic.Bool
	// unhealthy holds providers the startup check rejected, and is cleared per
	// provider by a real request succeeding through it. A plain latch would have
	// meant readiness could never follow routing back to healthy: the breaker's
	// half-open probe restores routing on its own, but /readyz would have stayed
	// 503 until the process restarted. Only consulted when ProviderCheckStrict.
	unhealthyMu sync.Mutex
	unhealthy   map[string]bool
}

func New(c Config, p *PolicyStore, m *Metrics, t *Telemetry) *Server {
	return &Server{C: c, Policies: p, Metrics: m, Telemetry: t, HTTP: client(time.Duration(c.TimeoutSeconds) * time.Second), slots: make(chan struct{}, c.Concurrency), rate: newBucket(c.Rate, c.Burst), retry: newBucket(c.RetryRate, c.RetryRate), circuits: map[string]*circuit{"openai": {}, "anthropic": {}, "gemini": {}, "bedrock": {}}, budgets: newBudgetTable(), temps: newTemperatureTable()}
}

// ready reports whether this gateway can serve a request. It deliberately does
// not consider the startup provider check: one broken provider is precisely the
// situation failover exists for, and refusing to serve would turn a degraded
// deployment into an unavailable one.
func (s *Server) ready() bool {
	p := s.Policies.Current()
	if s.Draining.Load() || p == nil {
		return false
	}
	for _, r := range p.Routes {
		if _, ok := s.C.Providers[r.Provider]; ok {
			return true
		}
	}
	return false
}

// readyz answers a different question from ready: not "can I serve this
// request" but "should the orchestrator keep this task". In strict mode a
// provider that failed its startup check is treated as a deployment fault, so
// this reports unhealthy and lets the platform replace the task.
//
// Keeping the two separate matters. Gating ready() on the same condition
// deadlocked recovery: the gateway refused every request, and the only thing
// that clears a failed check is a request succeeding.
func (s *Server) readyz() bool {
	if !s.ready() {
		return false
	}
	return !(s.C.ProviderCheckStrict && s.anyUnhealthy())
}
func (s *Server) markUnhealthy(provider string) {
	s.unhealthyMu.Lock()
	defer s.unhealthyMu.Unlock()
	if s.unhealthy == nil {
		s.unhealthy = map[string]bool{}
	}
	s.unhealthy[provider] = true
}

// markHealthy is called when a real request has succeeded through a provider,
// which is stronger evidence than the startup check and supersedes it.
func (s *Server) markHealthy(provider string) {
	s.unhealthyMu.Lock()
	defer s.unhealthyMu.Unlock()
	if len(s.unhealthy) > 0 {
		delete(s.unhealthy, provider)
	}
}

func (s *Server) anyUnhealthy() bool {
	s.unhealthyMu.Lock()
	defer s.unhealthyMu.Unlock()
	return len(s.unhealthy) > 0
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if !s.readyz() {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	})
	mux.Handle("GET /metrics", s.Metrics)
	if s.C.EnablePprof {
		// Authenticated, unlike /metrics. Counters are safe to expose on
		// loopback; a heap dump is not, because it carries provider keys and
		// prompt text to anything sharing the task's network namespace.
		//
		// Registered explicitly rather than by importing net/http/pprof for its
		// init side effect, which installs on DefaultServeMux, a mux this server
		// never serves.
		guard := func(h http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				if !s.authorized(r) {
					problem(w, 401, "unauthorized")
					return
				}
				h(w, r)
			}
		}
		mux.HandleFunc("GET /debug/pprof/", guard(pprof.Index))
		mux.HandleFunc("GET /debug/pprof/cmdline", guard(pprof.Cmdline))
		mux.HandleFunc("GET /debug/pprof/profile", guard(pprof.Profile))
		mux.HandleFunc("GET /debug/pprof/symbol", guard(pprof.Symbol))
		mux.HandleFunc("GET /debug/pprof/trace", guard(pprof.Trace))
	}
	mux.HandleFunc("POST /v1/chat/completions", s.chat)
	mux.HandleFunc("GET /runtime", func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			problem(w, 401, "unauthorized")
			return
		}
		p := s.Policies.Current()
		w.Header().Set("Content-Type", "application/json")
		if p == nil {
			w.Write([]byte(`{"ready":false}`))
			return
		}
		w.Write(jsonBytes(map[string]any{"ready": s.readyz(), "serving": s.ready(),
			"policy_version": p.Version, "policy_expires_at": p.ExpiresAt}))
	})
	return mux
}
func (s *Server) authorized(r *http.Request) bool {
	a := sha256.Sum256([]byte(r.Header.Get("Authorization")))
	b := sha256.Sum256([]byte("Bearer " + os.Getenv(s.C.LocalTokenEnv)))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
func problem(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(jsonBytes(map[string]any{"error": map[string]any{"message": msg, "type": "switchboard_error", "code": status}}))
}
func traceIDs(h string) (string, string) {
	parts := strings.Split(h, "-")
	if len(parts) == 4 && parts[0] == "00" && len(parts[1]) == 32 && len(parts[2]) == 16 && len(parts[3]) == 2 {
		a, e := hex.DecodeString(parts[1])
		b, f := hex.DecodeString(parts[2])
		_, g := hex.DecodeString(parts[3])
		if e == nil && f == nil && g == nil && strings.Trim(string(a), "\x00") != "" && strings.Trim(string(b), "\x00") != "" {
			// Lowercased, because hex.DecodeString accepts A-F and the control
			// plane does not: its Event model constrains trace_id to
			// ^[0-9a-f]{32}$. An uppercase id was therefore accepted here,
			// echoed back, spooled, then rejected on ingest and deleted as
			// deterministically refused -- so a client that uppercases its trace
			// ids lost every event, with no symptom but a rising drop counter.
			// W3C traceparent is defined in lowercase hex, so nothing is lost by
			// normalising and the id still matches the one the caller sent.
			return strings.ToLower(parts[1]), strings.ToLower(parts[2])
		}
	}
	return randomID(16), ""
}

// routable reports whether this route could be attempted right now, applying
// every gate that does not depend on how far the loop has already got. One
// predicate, so the pre-pass that decides "was everything skipped" and the loop
// that does the skipping cannot disagree about what counts.
//
// Deliberately excludes the attempt budget, which is a property of the loop's
// progress rather than of the route.
func (s *Server) routable(route Route, stream bool) bool {
	if _, ok := s.C.Providers[route.Provider]; !ok {
		return false
	}
	if stream && !streams(route.Provider) {
		return false
	}
	return s.circuits[route.Provider].wouldAllow()
}

func (s *Server) chat(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id := randomID(16)
	trace, parent := traceIDs(r.Header.Get("traceparent"))
	event := Event{ID: randomID(16), RequestID: id, TraceID: trace, SpanID: randomID(8), ParentID: parent, Start: start.UnixNano(), Status: 500}
	w.Header().Set("X-Request-ID", id)
	w.Header().Set("traceparent", "00-"+trace+"-"+event.SpanID+"-01")
	s.Metrics.Requests.Add(1)
	// Held here rather than written at each success site so that every outcome is
	// captured from one place: a 401, a policy refusal and a provider failure are
	// exactly the requests someone asks about later, and three write sites on the
	// success paths would have recorded none of them.
	var capturedPrompt, capturedCompletion json.RawMessage
	var capturedText string
	defer func() {
		event.End = time.Now().UnixNano()
		s.Metrics.ObserveLatency(time.Since(start).Milliseconds())
		if event.Status >= 400 {
			s.Metrics.Errors.Add(1)
		}
		if s.Telemetry != nil {
			s.Telemetry.Emit(event)
		}
		if s.Capture != nil {
			// Best effort, and deliberately after Emit. Capture is an operator
			// convenience; telemetry and the response are the product, and a full
			// disk must not be able to cost either of them. A refused write
			// increments telemetry_disk_errors_total and is otherwise silent here.
			_ = s.Capture.Write(&captureRecord{
				RequestID: id, TraceID: trace, PolicyVersion: event.PolicyVersion,
				Provider: event.Provider, Model: event.Model, Attempts: event.Attempts,
				Status: event.Status, Fault: event.Fault, Stored: time.Now().Unix(),
				Prompt: capturedPrompt, Completion: capturedCompletion, Text: capturedText,
			})
		}
		slog.Info("inference", "request_id", id, "trace_id", trace, "status", event.Status, "provider", event.Provider, "attempts", event.Attempts, "duration_ms", time.Since(start).Milliseconds())
	}()
	fail := func(status int, msg string) { event.Status = status; problem(w, status, msg) }
	if !s.authorized(r) {
		fail(401, "unauthorized")
		return
	}
	if !s.ready() {
		fail(503, "no valid routing policy or draining")
		return
	}
	// Exactly-once generation still cannot be guaranteed across provider APIs or
	// task loss. With a store configured the key narrows the window in which that
	// ambiguity costs money; without one, refusing is more honest than accepting
	// a header whose contract nothing here would keep.
	idemKey := r.Header.Get("Idempotency-Key")
	idemSettled := false
	if idemKey != "" && s.Idem == nil {
		fail(400, "idempotency keys are unsupported; set idempotency_ttl_seconds to enable them, "+
			"and do not automatically replay ambiguous inference failures")
		return
	}
	if !s.rate.allow() {
		s.Metrics.Rejected.Add(1)
		w.Header().Set("Retry-After", "1")
		fail(429, "rate limit")
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		s.Metrics.Rejected.Add(1)
		w.Header().Set("Retry-After", "1")
		fail(429, "concurrency limit")
		return
	}
	s.Metrics.Active.Add(1)
	defer s.Metrics.Active.Add(-1)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	b, e := io.ReadAll(r.Body)
	if e != nil {
		fail(413, "request body too large or unreadable")
		return
	}
	// Recorded after the size check and before parsing, so a body that fails to
	// parse is still captured: "what did the caller actually send" is the whole
	// question when a request is rejected as malformed.
	capturedPrompt = json.RawMessage(b)
	c, e := ParseChat(b)
	if e != nil {
		fail(400, e.Error())
		return
	}
	// Claimed after the body is read, because an entry binds to the body hash: the
	// same key with a different request is a client bug, and answering it with the
	// first response would be silently wrong.
	if idemKey != "" {
		prior, ie := s.Idem.begin(idemKey, b)
		switch {
		case errors.Is(ie, errIdemMismatch):
			fail(422, "this Idempotency-Key was already used with a different request body")
			return
		case errors.Is(ie, errIdemConflict):
			fail(409, "this Idempotency-Key is in use, or its original outcome is unknown and "+
				"replaying it could charge a second time")
			return
		case prior != nil:
			s.replay(w, prior, id, start.Unix(), &event)
			return
		}
		// Nothing recorded an outcome yet. A path that returns without doing so
		// leaves a running entry, which expires with the TTL rather than being
		// held forever.
		defer func() {
			if !idemSettled {
				s.Idem.release(idemKey)
			}
		}()
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.C.TimeoutSeconds)*time.Second)
	defer cancel()
	p := s.Policies.Current()
	if p == nil {
		fail(503, "policy expired")
		return
	}
	// Before any route is chosen. A request the policy refuses is as much a
	// routing decision as one it serves, and is the case someone is most likely
	// to ask about afterwards.
	event.PolicyVersion = p.Version
	// Decided before the loop, because the answer depends on all the routes: if
	// every eligible one would be skipped, none is. Refusing to try is worse than
	// trying and failing over, and a gateway that returns 503 without contacting
	// anyone has stopped being a gateway. A policy whose routes are all reasoning
	// models is exactly the case this exists for, and exactly the case that would
	// otherwise be refused outright.
	//
	// The count has to reason over the same gates the loop applies, or the
	// fallback compares against the wrong denominator and declines to fire. The
	// breaker is read without claiming the half-open probe, since nothing is
	// being attempted yet.
	skip := map[int]bool{}
	eligible := 0
	for i, route := range p.Routes {
		if !s.routable(route, c.Stream) {
			continue
		}
		eligible++
		if s.budgets.skip(route.Provider, route.Model, c.MaxTokens) {
			skip[i] = true
		}
	}
	if len(skip) == eligible {
		skip = map[int]bool{}
	}

	// Providers that answered and produced no text, so an exhausted loop can say
	// which ones and why rather than reporting a generic routing failure.
	var empties []emptyRoute
	for i, route := range p.Routes {
		pc, ok := s.C.Providers[route.Provider]
		if !ok {
			continue
		}
		if skip[i] {
			// Observed returning nothing at this budget, and never observed
			// succeeding at or below it. Trying anyway spends the caller's money
			// to learn what is already known.
			s.Metrics.BudgetSkip.Add(1)
			continue
		}
		if event.Attempts >= s.C.MaxAttempts {
			break
		}
		if c.Stream && !streams(route.Provider) {
			continue
		}
		if !s.circuits[route.Provider].allow() {
			continue
		}
		if event.Attempts > 0 {
			if !s.retry.allow() {
				s.circuits[route.Provider].release()
				break
			}
			s.Metrics.Retries.Add(1)
			timer := time.NewTimer(time.Duration(25+time.Now().UnixNano()%75) * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				s.circuits[route.Provider].release()
				fail(504, "deadline exceeded; generation outcome may be unknown")
				return
			case <-timer.C:
			}
		}
		event.Attempts++
		event.Provider = route.Provider
		event.Model = route.Model
		sent := c
		if sent.Temperature != nil && s.temps.omit(route.Provider, route.Model) {
			// Known refuser. Paying the 400 again on every request would be a
			// tax on a fact already established.
			sent.Temperature = nil
			s.Metrics.TemperatureDropped.Add(1)
		}
		req, e := upstream(ctx, sent, route, pc, s.Bedrock)
		if e != nil {
			s.circuits[route.Provider].release()
			fail(500, "adapter configuration")
			return
		}
		req.Header.Set("X-Request-ID", id)
		res, e := s.HTTP.Do(req)
		if e == nil && res.StatusCode >= 400 && sent.Temperature != nil {
			// One immediate retry without the field, if the provider said the
			// field is the problem. Safe, and for a specific reason: a 400 means
			// this request was rejected before anything was generated, so nothing
			// was accepted and nothing was billed. The no-replay-after-acceptance
			// rule applies to accepted requests and not to this.
			//
			// This is the first request against a model nobody has tried a
			// temperature on. Learning here is what makes it the only one that
			// pays the round trip.
			peek, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
			res.Body.Close()
			if rejectsTemperature(res.StatusCode, peek) {
				s.temps.observe(route.Provider, route.Model)
				s.Metrics.TemperatureDropped.Add(1)
				slog.Info("provider refused temperature; retrying without it",
					"request_id", id, "provider", route.Provider, "model", route.Model)
				sent.Temperature = nil
				if req, e = upstream(ctx, sent, route, pc, s.Bedrock); e != nil {
					s.circuits[route.Provider].release()
					fail(500, "adapter configuration")
					return
				}
				req.Header.Set("X-Request-ID", id)
				res, e = s.HTTP.Do(req)
			} else {
				// Not a temperature problem. Hand the body back so the existing
				// classification reads exactly what it would have read.
				res.Body = io.NopCloser(bytes.NewReader(peek))
			}
		}
		if e != nil {
			if r.Context().Err() != nil {
				s.circuits[route.Provider].release()
			} else {
				s.circuits[route.Provider].result(true)
			}
			idemSettled = s.settleUnknown(idemKey, hashBody(b))
			fail(502, "provider transport failed; outcome unknown, no automatic replay")
			return
		}
		if res.StatusCode != 200 {
			status := res.StatusCode
			// The body is read before deciding, because the status code alone
			// cannot separate an account that cannot pay from a request that is
			// malformed. Anthropic reports "credit balance is too low" as a 400,
			// which used to be treated as the caller's fault and never failed
			// over. Bounded: this is an error path and only the message matters.
			errBody, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
			res.Body.Close()
			wait := retryAfter(res.Header.Get("Retry-After"))
			// Recorded on the event as well as switched on, so the span carries
			// why a provider refused rather than only that one did. The last
			// classification wins, which means a span can show status 200 with a
			// fault set: that is a request that succeeded by routing around a
			// refusal, and reading it beside attempts is the whole point. A
			// successful request that cost two providers is not the same event as
			// one that cost one, and until now they were indistinguishable.
			f := classify(status, errBody)
			event.Fault = f.String()
			switch f {
			case faultAccount:
				// This account cannot serve at all. The provider is healthy, so
				// this is a cooldown rather than a health failure, but a long
				// one: it will not clear in the breaker's 15 seconds, and the
				// real OpenAI response carried no Retry-After whatsoever, which
				// previously released the circuit and re-attempted a dead
				// account on every single request.
				s.circuits[route.Provider].cooldown(max(wait, accountCooldown))
				s.Metrics.AccountFailover.Add(1)
				slog.Warn("provider account cannot serve; failing over", "request_id", id,
					"provider", route.Provider, "status", status, "reason", providerReason(errBody))
				continue
			case faultRateLimit:
				// Rate limited: the provider is fine, this caller is over quota.
				// Fail over, respect any stated wait, but do not count it as a
				// health failure.
				if wait > 0 {
					s.circuits[route.Provider].cooldown(wait)
				} else {
					s.circuits[route.Provider].release()
				}
				s.Metrics.RateLimited.Add(1)
				continue
			case faultDegraded:
				// Provider degraded. This is what the breaker is for.
				s.circuits[route.Provider].result(true)
				if wait > 0 {
					s.circuits[route.Provider].cooldown(wait)
				}
				continue
			}
			// Terminal: this request would fail the same way at every provider,
			// so failing over would only multiply the waste. Carry the
			// provider's own words, because "provider rejected request" made a
			// token-budget problem indistinguishable from a malformed one.
			s.circuits[route.Provider].result(false)
			msg := "provider rejected request"
			if reason := providerReason(errBody); reason != "" {
				msg += ": " + reason
			}
			if status == 400 || status == 422 {
				fail(400, msg)
			} else {
				fail(502, msg+"; not replayed")
			}
			return
		}
		var streamed streamResult
		// A 200 means this provider authenticated and served, which is stronger
		// evidence than the startup check and supersedes a rejection from it.
		s.markHealthy(route.Provider)
		// The caller cannot otherwise tell which provider answered, or that an
		// earlier one was skipped. Without this, a failover is invisible to
		// everything except the logs and the telemetry spool.
		w.Header().Set("X-Switchboard-Provider", route.Provider)
		w.Header().Set("X-Switchboard-Attempts", strconv.Itoa(event.Attempts))

		// Acceptance (HTTP 200) commits this generation. No body/stream error may fail over.
		if c.Stream {
			err := s.stream(w, res, route, id, start.Unix(), &streamed)
			res.Body.Close()
			if errors.Is(err, errStreamEmpty) {
				// The provider answered and said nothing, without sending a
				// byte. It is healthy, so the circuit closes; the request is
				// still unanswered, so it moves on.
				s.circuits[route.Provider].result(false)
				s.budgets.observe(route.Provider, route.Model, c.MaxTokens, false)
				empties = append(empties, emptyRoute{provider: route.Provider, model: route.Model, budget: c.MaxTokens})
				s.Metrics.EmptyCompletion.Add(1)
				slog.Warn("provider produced no output within the token budget", "request_id", id,
					"provider", route.Provider, "model", route.Model, "max_tokens", c.MaxTokens)
				continue
			}
			event.Status = 200
			s.circuits[route.Provider].result(err != nil)
			if err != nil {
				event.Status = 502
				idemSettled = s.settleUnknown(idemKey, hashBody(b))
			} else {
				s.budgets.observe(route.Provider, route.Model, c.MaxTokens, streamed.text != "")
				if len(empties) > 0 {
					s.Metrics.EmptyCompletionRecovered.Add(1)
				}
				// The assembled answer, not the frames. Replaying frame timing
				// would be a different feature and a dishonest one to imply.
				capturedText = streamed.text
				if idemKey != "" {
					s.Idem.finish(idemKey, &idemEntry{
						State: idemDone, BodyHash: hashBody(b), Stored: time.Now().Unix(),
						Status: 200, Stream: true, Text: streamed.text, Finish: streamed.finish,
					})
					idemSettled = true
				}
			}
			return
		}
		data, e := io.ReadAll(io.LimitReader(res.Body, 8<<20+1))
		res.Body.Close()
		if e != nil || len(data) > 8<<20 {
			s.circuits[route.Provider].result(true)
			idemSettled = s.settleUnknown(idemKey, hashBody(b))
			fail(502, "incomplete provider response; not replayed")
			return
		}
		n, _, e := normalize(route.Provider, data, false)
		if n.UsageMismatch {
			s.Metrics.UsageMismatch.Add(1)
		}
		s.circuits[route.Provider].result(e != nil)
		if e != nil {
			idemSettled = s.settleUnknown(idemKey, hashBody(b))
			fail(502, "unsupported or incomplete provider response; not replayed")
			return
		}
		if n.Finish == "length" && n.Text == "" {
			// The provider succeeded and produced nothing. A reasoning model
			// spends its budget on hidden reasoning before writing any answer
			// and does not reserve room for one, so a budget that is merely too
			// small yields a 200 with empty content, billed in full. Measured on
			// gpt-5-nano: 1024 tokens in, 1024 spent reasoning, zero characters
			// out. Returning that as success charges for an empty answer.
			//
			// The provider is healthy, so the circuit was already reset above.
			// Nothing has been written to the client yet, so failing over does
			// not violate the no-replay-after-acceptance rule.
			s.budgets.observe(route.Provider, route.Model, c.MaxTokens, false)
			empties = append(empties, emptyRoute{route.Provider, route.Model, c.MaxTokens, n.Reasoning})
			s.Metrics.EmptyCompletion.Add(1)
			slog.Warn("provider produced no output within the token budget", "request_id", id,
				"provider", route.Provider, "model", route.Model,
				"max_tokens", c.MaxTokens, "reasoning_tokens", n.Reasoning)
			continue
		}
		s.budgets.observe(route.Provider, route.Model, c.MaxTokens, true)
		if len(empties) > 0 {
			s.Metrics.EmptyCompletionRecovered.Add(1)
		}
		event.Status = 200
		body := jsonBytes(completion(id, route, n, start.Unix()))
		capturedCompletion = body
		if idemKey != "" {
			s.Idem.finish(idemKey, &idemEntry{
				State: idemDone, BodyHash: hashBody(b), Stored: time.Now().Unix(),
				Status: 200, Response: body,
			})
			idemSettled = true
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
		return
	}
	w.Header().Set("Retry-After", "1")
	if len(empties) > 0 {
		s.Metrics.EmptyCompletionFailed.Add(1)
		// Name the routes. Without this the caller sees a routing failure and
		// cannot tell that the fix is theirs, or which model to stop asking.
		parts := make([]string, 0, len(empties))
		for _, e := range empties {
			parts = append(parts, e.String())
		}
		fail(503, fmt.Sprintf("no provider produced output within max_tokens=%d: %s; retry with a higher max_tokens",
			c.MaxTokens, strings.Join(parts, "; ")))
		return
	}
	fail(503, "routes unavailable or retry budget exhausted")
}
func (s *Server) stream(w http.ResponseWriter, res *http.Response, route Route, id string, created int64, out *streamResult) error {
	body := res.Body
	ct := strings.ToLower(res.Header.Get("Content-Type"))
	switch {
	case strings.HasPrefix(ct, "text/event-stream"):
	case route.Provider == "bedrock" && strings.Contains(ct, "eventstream"):
		// Bedrock speaks AWS event-stream framing. Translating it here rather
		// than teaching this function a second wire format keeps the deadline,
		// finish tracking, empty-completion detection and no-replay rule below
		// applying to all four providers identically.
		body = bedrockSSE(res.Body, 8<<20)
		defer body.Close()
	default:
		problem(w, 502, "expected provider event stream")
		return errors.New("wrong content type")
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	rc := http.NewResponseController(w)
	finished := false
	terminal := false
	// wrote records whether any byte has reached the client. Once one has, this
	// generation is committed and no failover is permitted.
	wrote := false
	// pending holds a frame carrying a truncation finish reason and no text. A
	// reasoning model can consume the whole budget without writing an answer,
	// and that frame is the first thing it sends. Emitting it immediately would
	// commit an empty response; holding it keeps failover available until the
	// stream proves it has something to say.
	var pending any
	// Providers repeat cumulative usage on every frame, so without this a single
	// response would be counted as several mismatches.
	mismatchCounted := false
	err := readSSE(body, func(b []byte) error {
		if string(b) == "[DONE]" {
			if route.Provider != "openai" || !finished {
				return errors.New("premature DONE")
			}
			terminal = true
			return streamComplete
		}
		n, done, e := normalize(route.Provider, b, true)
		if e != nil {
			return e
		}
		if n.UsageMismatch && !mismatchCounted {
			s.Metrics.UsageMismatch.Add(1)
			mismatchCounted = true
		}
		if finished && n.Text != "" {
			return errors.New("text after finish")
		}
		if n.Finish != "" {
			finished = true
		}
		if n.Text != "" || n.Finish != "" {
			ch := chunk(id, route, n, created)
			if !wrote && n.Text == "" && n.Finish == "length" {
				pending = ch
				return nil
			}
			rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if e := writeSSE(w, ch); e != nil {
				return e
			}
			wrote = true
			if out != nil {
				out.text += n.Text
				if n.Finish != "" {
					out.finish = n.Finish
				}
			}
		}
		if done && route.Provider != "openai" {
			if !finished {
				return errors.New("missing finish reason")
			}
			terminal = true
			return streamComplete
		}
		return nil
	})
	rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if (err == nil || errors.Is(err, streamComplete)) && terminal {
		if pending != nil && !wrote {
			// Nothing was ever sent, so the caller is still owed an answer and
			// another provider may be able to give one.
			return errStreamEmpty
		}
		if pending != nil {
			if e := writeSSE(w, pending); e != nil {
				return e
			}
		}
		_, e := fmt.Fprint(w, "data: [DONE]\n\n")
		if e == nil {
			e = rc.Flush()
		}
		return e
	}
	writeSSE(w, map[string]any{"error": map[string]any{"message": "upstream stream interrupted; do not automatically replay", "type": "stream_error", "request_id": id}})
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return err
}

// ProbeProviders sends one real request to every provider the current policy
// routes to, once, after the first signed policy verifies.
//
// It sends a completion rather than hitting an auth-only endpoint, because an
// auth-only check does not answer the question. Measured during live testing:
// GET /v1/models returned 200 on an OpenAI key whose account had no credits,
// minutes before a completion on the same key returned 429. A check that passes
// while every real request fails is worse than no check, because it converts an
// obvious failure into a confident one.
//
// It runs after policy rather than at boot because the models to probe come from
// the signed policy, and hardcoding model names is what broke the live tests:
// two of three named models were retired by their providers between being
// written and being run.
func (s *Server) ProbeProviders(ctx context.Context) {
	p := s.awaitPolicy(ctx)
	if p == nil {
		return
	}
	seen := map[string]bool{}
	for _, route := range p.Routes {
		if seen[route.Provider] {
			continue
		}
		seen[route.Provider] = true
		pc, ok := s.C.Providers[route.Provider]
		if !ok {
			continue
		}
		if reason := s.probeOne(ctx, route, pc); reason != "" {
			s.Metrics.ProviderProbeFailed.Add(1)
			s.markUnhealthy(route.Provider)
			// Withheld rather than removed. The breaker's half-open probe restores
			// routing on its own once the account is funded or the key replaced,
			// and the first request that then succeeds through this provider
			// clears it here too, so readiness recovers without a restart.
			s.circuits[route.Provider].cooldown(accountCooldown)
			slog.Error("provider check failed", "provider", route.Provider,
				"model", route.Model, "reason", reason, "strict", s.C.ProviderCheckStrict)
			continue
		}
		slog.Info("provider check passed", "provider", route.Provider, "model", route.Model)
	}
}

// awaitPolicy blocks until a signed policy is live. There is no callback on that
// transition, so this polls, the same way the readiness probe and the smoke test
// already do.
func (s *Server) awaitPolicy(ctx context.Context) *Policy {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		if p := s.Policies.Current(); p != nil {
			return p
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// probeOne returns "" when the provider is usable, or the reason it is not.
// Only credentials and account state are being tested here, so a rate limit, a
// busy provider or a complaint about the tiny token budget all count as passes:
// each of them proves the request was authenticated and the account can pay.
func (s *Server) probeOne(ctx context.Context, route Route, pc ProviderConfig) string {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := upstream(ctx, Chat{
		MaxTokens: 8,
		Messages:  []Message{{Role: "user", Content: "ping"}},
	}, route, pc, s.Bedrock)
	if err != nil {
		return "request could not be built: " + err.Error()
	}
	res, err := s.HTTP.Do(req)
	if err != nil {
		return "provider unreachable: " + err.Error()
	}
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	res.Body.Close()
	switch {
	case res.StatusCode == 200:
		return ""
	case res.StatusCode == 401 || res.StatusCode == 403:
		if reason := providerReason(body); reason != "" {
			return "credentials rejected: " + reason
		}
		return "credentials rejected"
	case classify(res.StatusCode, body) == faultAccount:
		if reason := providerReason(body); reason != "" {
			return "account cannot serve: " + reason
		}
		return "account cannot serve"
	}
	return ""
}

func (s *Server) Sync(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		s.syncOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (s *Server) syncOnce(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", trimURL(s.C.ControlURL)+"/v1/policy", nil)
	req.Header.Set("Authorization", "Bearer "+os.Getenv(s.C.ControlTokenEnv))
	res, e := s.HTTP.Do(req)
	if e != nil {
		s.Metrics.PolicyErrors.Add(1)
		return
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 65537))
	if e != nil || res.StatusCode != 200 || s.Policies.Apply(b, true) != nil {
		s.Metrics.PolicyErrors.Add(1)
	}
}
func Healthcheck(addr string) int {
	c := client(2 * time.Second)
	res, e := c.Get("http://" + addr + "/readyz")
	if e != nil {
		return 1
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		return 1
	}
	return 0
}

// streamResult carries what a completed stream said, so an idempotent replay can
// deliver the same answer. It is the assembled content rather than the provider's
// frames: replay gives the same answer, not the original timing.
type streamResult struct {
	text   string
	finish string
}

// settleUnknown marks a key ambiguous. Deliberately sticky: releasing it would
// let a retry pay a second time for work that may already have happened, which is
// the exact failure an idempotency key is bought to prevent.
//
// The body hash is carried through. Without it the entry no longer matches its
// own request, and a retry is refused as a body mismatch rather than as the
// ambiguity it actually is, which tells the caller the wrong thing.
func (s *Server) settleUnknown(key string, bodyHash string) bool {
	if key == "" {
		return false
	}
	s.Idem.finish(key, &idemEntry{State: idemUnknown, BodyHash: bodyHash, Stored: time.Now().Unix()})
	return true
}

// replay serves a stored outcome without contacting any provider.
func (s *Server) replay(w http.ResponseWriter, e *idemEntry, id string, created int64, event *Event) {
	event.Status = e.Status
	// Named so a caller can tell a replay from a fresh generation; without it the
	// two are indistinguishable and a retry looks like it cost money.
	w.Header().Set("X-Switchboard-Replayed", "true")
	if !e.Stream {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(e.Status)
		w.Write(e.Response)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	writeSSE(w, chunk(id, Route{}, normalized{Text: e.Text, Finish: e.Finish}, created))
	fmt.Fprint(w, "data: [DONE]\n\n")
}
