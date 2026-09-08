package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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
	Draining    atomic.Bool
}

func New(c Config, p *PolicyStore, m *Metrics, t *Telemetry) *Server {
	return &Server{C: c, Policies: p, Metrics: m, Telemetry: t, HTTP: client(time.Duration(c.TimeoutSeconds) * time.Second), slots: make(chan struct{}, c.Concurrency), rate: newBucket(c.Rate, c.Burst), retry: newBucket(c.RetryRate, c.RetryRate), circuits: map[string]*circuit{"openai": {}, "anthropic": {}, "gemini": {}, "bedrock": {}}}
}
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
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if !s.ready() {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	})
	mux.Handle("GET /metrics", s.Metrics)
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
		w.Write(jsonBytes(map[string]any{"ready": s.ready(), "policy_version": p.Version, "policy_expires_at": p.ExpiresAt}))
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
			return parts[1], parts[2]
		}
	}
	return randomID(16), ""
}
func (s *Server) chat(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id := randomID(16)
	trace, parent := traceIDs(r.Header.Get("traceparent"))
	event := Event{ID: randomID(16), RequestID: id, TraceID: trace, SpanID: randomID(8), ParentID: parent, Start: start.UnixNano(), Status: 500}
	w.Header().Set("X-Request-ID", id)
	w.Header().Set("traceparent", "00-"+trace+"-"+event.SpanID+"-01")
	s.Metrics.Requests.Add(1)
	defer func() {
		event.End = time.Now().UnixNano()
		s.Metrics.ObserveLatency(time.Since(start).Milliseconds())
		if event.Status >= 400 {
			s.Metrics.Errors.Add(1)
		}
		if s.Telemetry != nil {
			s.Telemetry.Emit(event)
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
	// Exactly-once generation cannot be guaranteed across provider APIs or task loss.
	// Reject this header instead of falsely acknowledging an idempotency contract.
	if r.Header.Get("Idempotency-Key") != "" {
		fail(400, "idempotency keys are unsupported; do not automatically replay ambiguous inference failures")
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
	c, e := ParseChat(b)
	if e != nil {
		fail(400, e.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.C.TimeoutSeconds)*time.Second)
	defer cancel()
	p := s.Policies.Current()
	if p == nil {
		fail(503, "policy expired")
		return
	}
	for _, route := range p.Routes {
		pc, ok := s.C.Providers[route.Provider]
		if !ok {
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
		req, e := upstream(ctx, c, route, pc, s.Bedrock)
		if e != nil {
			s.circuits[route.Provider].release()
			fail(500, "adapter configuration")
			return
		}
		req.Header.Set("X-Request-ID", id)
		res, e := s.HTTP.Do(req)
		if e != nil {
			if r.Context().Err() != nil {
				s.circuits[route.Provider].release()
			} else {
				s.circuits[route.Provider].result(true)
			}
			fail(502, "provider transport failed; outcome unknown, no automatic replay")
			return
		}
		if res.StatusCode != 200 {
			status := res.StatusCode
			res.Body.Close()
			wait := retryAfter(res.Header.Get("Retry-After"))
			switch status {
			case 429:
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
			case 503:
				// Provider degraded. This is what the breaker is for.
				s.circuits[route.Provider].result(true)
				if wait > 0 {
					s.circuits[route.Provider].cooldown(wait)
				}
				continue
			}
			s.circuits[route.Provider].result(false)
			if status == 400 || status == 422 {
				fail(400, "provider rejected request")
			} else {
				fail(502, "provider rejected request; not replayed")
			}
			return
		}
		// The caller cannot otherwise tell which provider answered, or that an
		// earlier one was skipped. Without this, a failover is invisible to
		// everything except the logs and the telemetry spool.
		w.Header().Set("X-Switchboard-Provider", route.Provider)
		w.Header().Set("X-Switchboard-Attempts", strconv.Itoa(event.Attempts))

		// Acceptance (HTTP 200) commits this generation. No body/stream error may fail over.
		if c.Stream {
			event.Status = 200
			err := s.stream(w, res, route, id, start.Unix())
			res.Body.Close()
			s.circuits[route.Provider].result(err != nil)
			if err != nil {
				event.Status = 502
			}
			return
		}
		data, e := io.ReadAll(io.LimitReader(res.Body, 8<<20+1))
		res.Body.Close()
		if e != nil || len(data) > 8<<20 {
			s.circuits[route.Provider].result(true)
			fail(502, "incomplete provider response; not replayed")
			return
		}
		n, _, e := normalize(route.Provider, data, false)
		if n.UsageMismatch {
			s.Metrics.UsageMismatch.Add(1)
		}
		s.circuits[route.Provider].result(e != nil)
		if e != nil {
			fail(502, "unsupported or incomplete provider response; not replayed")
			return
		}
		event.Status = 200
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonBytes(completion(id, route, n, start.Unix())))
		return
	}
	w.Header().Set("Retry-After", "1")
	fail(503, "routes unavailable or retry budget exhausted")
}
func (s *Server) stream(w http.ResponseWriter, res *http.Response, route Route, id string, created int64) error {
	if !strings.HasPrefix(strings.ToLower(res.Header.Get("Content-Type")), "text/event-stream") {
		problem(w, 502, "expected provider event stream")
		return errors.New("wrong content type")
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	rc := http.NewResponseController(w)
	finished := false
	terminal := false
	// Providers repeat cumulative usage on every frame, so without this a single
	// response would be counted as several mismatches.
	mismatchCounted := false
	err := readSSE(res.Body, func(b []byte) error {
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
			rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if e := writeSSE(w, chunk(id, route, n, created)); e != nil {
				return e
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
