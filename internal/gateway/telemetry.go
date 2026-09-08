package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Metrics struct {
	Requests, Errors, Retries, Rejected, Dropped, DiskErrors, ExportErrors, PolicyErrors, SpoolUsed, SpoolCount, Active, LatencyMS, Completed atomic.Int64
	// RateLimited counts provider 429s, which are deliberately not Errors:
	// the provider was healthy and the request failed over.
	RateLimited atomic.Int64
	// UsageMismatch counts responses whose own token totals did not add up. It is
	// a billing-integrity signal: a provider changing how it accounts for tokens
	// shows up here rather than as silent revenue drift.
	UsageMismatch atomic.Int64
	// EmptyCompletion counts responses that succeeded and carried no text. A
	// reasoning model can spend an entire token budget on hidden reasoning and
	// return nothing, billed in full, which would otherwise look like success.
	//
	// This is counted PER ROUTE, so one request can advance it more than once.
	// The two counters below are per request, and are what an alarm should use:
	// this one cannot distinguish a request that recovered from one that failed,
	// which is the distinction an operator actually needs.
	EmptyCompletion atomic.Int64
	// EmptyCompletionRecovered: a later route answered. The caller got a real
	// response, but paid two providers and waited for both. Wasted spend and
	// latency rather than lost service, so it warrants a higher alarm threshold.
	EmptyCompletionRecovered atomic.Int64
	// EmptyCompletionFailed: every attempted route came back empty and the caller
	// got a 503. This is lost service and warrants a low threshold.
	EmptyCompletionFailed atomic.Int64
	// AccountFailover counts requests moved to another provider because an
	// account could not serve at all: no credits, balance too low, quota gone.
	// Distinct from RateLimited, which is transient and self-clearing.
	AccountFailover atomic.Int64
	// ProviderProbeFailed counts providers rejected by the startup check.
	ProviderProbeFailed atomic.Int64
	// IdempotentReplay counts responses served from the idempotency store rather
	// than from a provider. Every one is a generation not paid for twice.
	IdempotentReplay atomic.Int64
	// IdempotentConflict counts keys refused because they were still in use, or
	// reused with a different request body.
	IdempotentConflict atomic.Int64
	// IdempotentUnknown counts retries refused because the original outcome is
	// genuinely unknown. A rising figure here means real ambiguity is being
	// caught rather than silently paid for twice.
	IdempotentUnknown atomic.Int64
	// Goroutines, HeapAlloc, HeapObjects and HeapSys are sampled from the
	// runtime rather than counted, and exist to make unbounded growth
	// attributable. A 30-minute soak found resident memory rising linearly with
	// requests served and not falling when load stopped; these four separate the
	// three explanations that observation leaves open.
	//
	// Goroutines rising with requests is a goroutine leak and needs nothing
	// further. HeapObjects and HeapAlloc rising together is object retention.
	// HeapSys rising while HeapAlloc stays flat is fragmentation or memory the
	// runtime has kept rather than objects the program is holding, which a heap
	// profile would not explain.
	Goroutines, HeapAlloc, HeapObjects, HeapSys atomic.Int64
	LatencyBuckets                              [7]atomic.Int64
	LogDropped                                  *atomic.Int64
}

var latencyBounds = [7]int64{100, 500, 1000, 5000, 15000, 60000, 90000}

func (m *Metrics) ObserveLatency(ms int64) {
	m.LatencyMS.Add(ms)
	m.Completed.Add(1)
	for i, b := range latencyBounds {
		if ms <= b {
			m.LatencyBuckets[i].Add(1)
		}
	}
}

// series is one exported metric. Counters and gauges are listed once, here, so
// the Prometheus endpoint and the OTLP exporter cannot drift apart: a counter
// added to one and forgotten in the other is invisible in exactly the place
// someone is looking for it.
type series struct {
	name, kind string
	v          *atomic.Int64
}

// sampleRuntime refreshes the four runtime gauges. ReadMemStats stops the
// world, which is normally the argument against calling it, but series() is
// read only by a Prometheus scrape and by the exporter every metricInterval, so
// the pause is tens of microseconds a couple of times a minute. That reasoning
// depends on the heap staying small: the pause scales with heap size, and a
// heap large enough to make this expensive is one these gauges should have
// caught long before. runtime/metrics is the non-stop-the-world alternative if
// that ever stops being true, at the cost of a samples slice and string lookups
// that buy nothing at this cadence.
func (m *Metrics) sampleRuntime() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	m.Goroutines.Store(int64(runtime.NumGoroutine()))
	m.HeapAlloc.Store(int64(ms.HeapAlloc))
	m.HeapObjects.Store(int64(ms.HeapObjects))
	m.HeapSys.Store(int64(ms.HeapSys))
}

// series has a side effect: it samples the runtime gauges before returning, so
// every consumer sees current values. That is here rather than in the two
// callers for the same reason the list itself is here — a caller that forgot to
// sample would export stale numbers, which is the drift this list exists to
// prevent, and harder to notice than a missing metric.
func (m *Metrics) series() []series {
	m.sampleRuntime()
	s := []series{
		{"requests_total", "counter", &m.Requests},
		{"errors_total", "counter", &m.Errors},
		{"retries_total", "counter", &m.Retries},
		{"rate_limited_total", "counter", &m.RateLimited},
		{"usage_mismatch_total", "counter", &m.UsageMismatch},
		{"empty_completion_total", "counter", &m.EmptyCompletion},
		{"empty_completion_recovered_total", "counter", &m.EmptyCompletionRecovered},
		{"empty_completion_failed_total", "counter", &m.EmptyCompletionFailed},
		{"account_failover_total", "counter", &m.AccountFailover},
		{"provider_probe_failed_total", "counter", &m.ProviderProbeFailed},
		{"idempotent_replay_total", "counter", &m.IdempotentReplay},
		{"idempotent_conflict_total", "counter", &m.IdempotentConflict},
		{"idempotent_unknown_total", "counter", &m.IdempotentUnknown},
		{"rejected_total", "counter", &m.Rejected},
		{"telemetry_dropped_total", "counter", &m.Dropped},
		{"telemetry_disk_errors_total", "counter", &m.DiskErrors},
		{"telemetry_export_errors_total", "counter", &m.ExportErrors},
		{"policy_errors_total", "counter", &m.PolicyErrors},
		{"spool_bytes", "gauge", &m.SpoolUsed},
		{"spool_events", "gauge", &m.SpoolCount},
		{"active_requests", "gauge", &m.Active},
		{"goroutines", "gauge", &m.Goroutines},
		{"heap_alloc_bytes", "gauge", &m.HeapAlloc},
		{"heap_objects", "gauge", &m.HeapObjects},
		{"heap_sys_bytes", "gauge", &m.HeapSys},
	}
	if m.LogDropped != nil {
		s = append(s, series{"log_dropped_total", "counter", m.LogDropped})
	}
	return s
}

func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	for _, v := range m.series() {
		fmt.Fprintf(w, "# TYPE switchboard_%s %s\nswitchboard_%s %d\n", v.name, v.kind, v.name, v.v.Load())
	}
	fmt.Fprintln(w, "# TYPE switchboard_request_duration_milliseconds histogram")
	for i, b := range latencyBounds {
		fmt.Fprintf(w, "switchboard_request_duration_milliseconds_bucket{le=\"%d\"} %d\n", b, m.LatencyBuckets[i].Load())
	}
	fmt.Fprintf(w, "switchboard_request_duration_milliseconds_bucket{le=\"+Inf\"} %d\nswitchboard_request_duration_milliseconds_sum %d\nswitchboard_request_duration_milliseconds_count %d\n", m.Completed.Load(), m.LatencyMS.Load(), m.Completed.Load())
}

type Event struct {
	ID        string `json:"id"`
	RequestID string `json:"request_id"`
	TraceID   string `json:"trace_id"`
	SpanID    string `json:"span_id"`
	ParentID  string `json:"parent_id,omitempty"`
	Provider  string `json:"provider"`
	Status    int    `json:"status"`
	Attempts  int    `json:"attempts"`
	Start     int64  `json:"start_ns"`
	End       int64  `json:"end_ns"`
}

func randomID(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic("system randomness unavailable")
	}
	return hex.EncodeToString(b)
}

type Telemetry struct {
	c     Config
	m     *Metrics
	queue chan Event
	otlp  chan Event
	wg    sync.WaitGroup
	http  *http.Client
	dir   string
	// perEvent is set once when the control plane turns out to have no batch
	// route, so the fallback is decided a single time rather than per tick.
	perEvent atomic.Bool
	// start anchors cumulative counters. OTLP requires every point of a
	// cumulative series to carry the same start time, so a consumer can tell a
	// counter reset from a process restart.
	start time.Time
}

func NewTelemetry(c Config, m *Metrics) (*Telemetry, error) {
	dir := filepath.Join(c.DataDir, "spool")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	files, e := os.ReadDir(dir)
	if e != nil {
		return nil, e
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".json") {
			i, e := f.Info()
			if e != nil {
				return nil, e
			}
			m.SpoolUsed.Add(i.Size())
			m.SpoolCount.Add(1)
		}
	}
	return &Telemetry{c: c, m: m, queue: make(chan Event, c.QueueSize), otlp: make(chan Event, c.QueueSize), http: client(5 * time.Second), dir: dir, start: time.Now()}, nil
}
func (t *Telemetry) Emit(e Event) {
	if t.c.OTLPURL != "" {
		select {
		case t.otlp <- e:
		default:
			t.m.ExportErrors.Add(1)
		}
	}
	select {
	case t.queue <- e:
	default:
		t.m.Dropped.Add(1)
	}
}

// metricInterval is how often counters are pushed. Slow enough to be
// insignificant against inference latency, fast enough that an alarm on lost
// service is not minutes stale.
const metricInterval = 30 * time.Second

func (t *Telemetry) Start(ctx context.Context) {
	if t.c.OTLPMetricsURL != "" {
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			ticker := time.NewTicker(metricInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					t.exportMetrics(ctx)
				}
			}
		}()
	}
	t.wg.Add(3)
	go func() {
		defer t.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case e := <-t.otlp:
				t.exportOTLP(ctx, e)
			}
		}
	}()
	go func() {
		defer t.wg.Done()
		for {
			select {
			case e := <-t.queue:
				t.persist(e)
			case <-ctx.Done():
				for {
					select {
					case e := <-t.queue:
						t.persist(e)
					default:
						return
					}
				}
			}
		}
	}()
	go func() {
		defer t.wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				t.deliver(ctx)
			}
		}
	}()
}
func (t *Telemetry) Wait() { t.wg.Wait() }
func (t *Telemetry) persist(e Event) {
	b := jsonBytes(e)
	if t.m.SpoolUsed.Load()+int64(len(b)) > t.c.SpoolBytes || t.m.SpoolCount.Load() >= 10000 {
		t.m.Dropped.Add(1)
		return
	}
	if err := atomicFile(filepath.Join(t.dir, e.ID+".json"), b); err != nil {
		t.m.DiskErrors.Add(1)
		t.m.Dropped.Add(1)
		return
	}
	t.m.SpoolUsed.Add(int64(len(b)))
	t.m.SpoolCount.Add(1)
}

// deliverBatch is how many events go in one request, and deliverBatches how many
// requests one tick may issue. Delivery used to be one POST per event issued
// sequentially, so its real ceiling was round-trip bound: comfortable against a
// control plane in the same task, roughly twenty per second across a network at
// 50 ms. A spool that cannot drain grows to its cap and then drops events, and
// the events are billing and audit records.
const (
	deliverBatch   = 200
	deliverBatches = 5
)

// spooled is one file waiting to be sent, kept with its size so the accounting
// gauges can be corrected exactly when it is removed.
type spooled struct {
	path  string
	id    string
	size  int64
	event json.RawMessage
}

func (t *Telemetry) deliver(ctx context.Context) {
	files, e := os.ReadDir(t.dir)
	if e != nil {
		t.m.DiskErrors.Add(1)
		return
	}
	batch := make([]spooled, 0, deliverBatch)
	sentBatches := 0
	for _, f := range files {
		if ctx.Err() != nil || sentBatches >= deliverBatches {
			return
		}
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		path := filepath.Join(t.dir, f.Name())
		b, e := os.ReadFile(path)
		if e != nil || len(b) > 8192 {
			t.m.DiskErrors.Add(1)
			continue
		}
		var event Event
		if json.Unmarshal(b, &event) != nil {
			t.m.DiskErrors.Add(1)
			continue
		}
		batch = append(batch, spooled{path: path, id: event.ID, size: int64(len(b)), event: b})
		if len(batch) < deliverBatch {
			continue
		}
		if !t.send(ctx, batch) {
			return
		}
		batch, sentBatches = batch[:0], sentBatches+1
	}
	if len(batch) > 0 && sentBatches < deliverBatches {
		t.send(ctx, batch)
	}
}

// send delivers one batch and removes exactly what the control plane
// acknowledged. It reports whether the exchange succeeded, so a failing tick
// stops rather than hammering an unreachable control plane.
func (t *Telemetry) send(ctx context.Context, batch []spooled) bool {
	if t.perEvent.Load() {
		return t.sendPerEvent(ctx, batch)
	}
	body := make([]byte, 0, 256*len(batch))
	body = append(body, []byte(`{"events":[`)...)
	for i, s := range batch {
		if i > 0 {
			body = append(body, ',')
		}
		body = append(body, s.event...)
	}
	body = append(body, []byte(`]}`)...)

	res, e := t.post(ctx, "/v1/telemetry/batch", body)
	if e != nil {
		t.m.ExportErrors.Add(1)
		return false
	}
	ack, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	res.Body.Close()
	// An older control plane has no batch route. Fall back for the rest of this
	// process and say so, because "your control plane predates batching" should
	// be visible rather than inferred from throughput.
	if res.StatusCode == 404 || res.StatusCode == 405 {
		if t.perEvent.CompareAndSwap(false, true) {
			slog.Info("control plane has no batch telemetry route; falling back to one request per event",
				"url", trimURL(t.c.ControlURL)+"/v1/telemetry")
		}
		return t.sendPerEvent(ctx, batch)
	}
	// A pointer distinguishes an absent field from an empty list. An empty list is
	// a legitimate answer, meaning every event in the batch was rejected as
	// malformed; an absent one means whatever answered is not the batch route.
	var a struct {
		Accepted *[]string `json:"accepted"`
	}
	if res.StatusCode != 200 {
		t.m.ExportErrors.Add(1)
		return false
	}
	if json.Unmarshal(ack, &a) != nil || a.Accepted == nil {
		// 200 from something that is not the batch route: an older control plane
		// behind a proxy that does not 404, for instance. Falling back is strictly
		// better than looping forever acknowledging nothing, which would grow the
		// spool to its cap and then drop billing records.
		if t.perEvent.CompareAndSwap(false, true) {
			slog.Info("control plane did not answer the batch route as expected; falling back to one request per event",
				"status", res.StatusCode)
		}
		return t.sendPerEvent(ctx, batch)
	}
	ok := make(map[string]bool, len(*a.Accepted))
	for _, id := range *a.Accepted {
		ok[id] = true
	}
	// The control plane processed the whole batch and reported what it took, so
	// anything sent and not acknowledged was refused deterministically and will be
	// refused again. Keeping it would retry it every tick forever and eventually
	// fill the spool, so it is dropped and counted: losing one malformed event is
	// better than losing every event queued behind it.
	for _, sp := range batch {
		if ok[sp.id] {
			t.remove(sp)
			continue
		}
		t.m.Dropped.Add(1)
		t.remove(sp)
	}
	return true
}

// sendPerEvent is the original path, kept for control planes without the batch
// route rather than deleted, so this change is safe to deploy in either order.
func (t *Telemetry) sendPerEvent(ctx context.Context, batch []spooled) bool {
	for _, sp := range batch {
		res, e := t.post(ctx, "/v1/telemetry", sp.event)
		if e != nil {
			t.m.ExportErrors.Add(1)
			return false
		}
		ack, e := io.ReadAll(io.LimitReader(res.Body, 8193))
		res.Body.Close()
		var a struct {
			ID string `json:"id"`
		}
		if e != nil || res.StatusCode != 200 || json.Unmarshal(ack, &a) != nil || a.ID != sp.id {
			t.m.ExportErrors.Add(1)
			return false
		}
		t.remove(sp)
	}
	return true
}

func (t *Telemetry) post(ctx context.Context, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", trimURL(t.c.ControlURL)+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv(t.c.ControlTokenEnv))
	req.Header.Set("Content-Type", "application/json")
	return t.http.Do(req)
}

func (t *Telemetry) remove(sp spooled) {
	if os.Remove(sp.path) != nil {
		t.m.DiskErrors.Add(1)
		return
	}
	t.m.SpoolUsed.Add(-sp.size)
	t.m.SpoolCount.Add(-1)
}

// exportMetrics pushes every counter and gauge over OTLP. It exists because
// nothing collects /metrics in a shipped deployment: the endpoint is bound to
// loopback with the rest of the gateway, and the collector that would scrape it
// is an opt-in sidecar absent from both CloudFormation templates and the sample
// task definition. Without this, every counter here is unreadable in production.
//
// Histograms are deliberately not exported. The latency histogram needs a
// different OTLP shape and bucket encoding, and claiming histogram support
// without it would be worse than omitting it.
func (t *Telemetry) exportMetrics(ctx context.Context) {
	now := strconv.FormatInt(time.Now().UnixNano(), 10)
	start := strconv.FormatInt(t.start.UnixNano(), 10)
	metrics := make([]any, 0, 20)
	for _, s := range t.m.series() {
		point := map[string]any{"asInt": strconv.FormatInt(s.v.Load(), 10), "timeUnixNano": now}
		m := map[string]any{"name": "switchboard." + s.name, "unit": "1"}
		if s.kind == "counter" {
			point["startTimeUnixNano"] = start
			// 2 is CUMULATIVE: the value is a running total since start, not a
			// delta, which is what an atomic counter actually is.
			m["sum"] = map[string]any{"aggregationTemporality": 2, "isMonotonic": true, "dataPoints": []any{point}}
		} else {
			m["gauge"] = map[string]any{"dataPoints": []any{point}}
		}
		metrics = append(metrics, m)
	}
	metrics = append(metrics, t.latencyHistogram(now, start))
	body := map[string]any{"resourceMetrics": []any{map[string]any{
		"resource":     map[string]any{"attributes": []any{map[string]any{"key": "service.name", "value": map[string]any{"stringValue": "switchboard-gateway"}}}},
		"scopeMetrics": []any{map[string]any{"scope": map[string]any{"name": "switchboard", "version": "1.0.0"}, "metrics": metrics}},
	}}}
	req, err := http.NewRequestWithContext(ctx, "POST", t.c.OTLPMetricsURL, bytes.NewReader(jsonBytes(body)))
	if err != nil {
		t.m.ExportErrors.Add(1)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := t.http.Do(req)
	if err != nil {
		t.m.ExportErrors.Add(1)
		return
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, 8192))
	res.Body.Close()
	if res.StatusCode != 200 || bytes.Contains(b, []byte("rejectedDataPoints")) {
		t.m.ExportErrors.Add(1)
	}
}

// latencyHistogram encodes the request-duration histogram for OTLP.
//
// The one thing here that is easy to get silently wrong: Prometheus buckets are
// cumulative and OTLP bucketCounts are not. LatencyBuckets[i] holds every request
// at or below latencyBounds[i], including all earlier buckets, while OTLP wants
// the count falling within each bucket plus one overflow bucket. Emitting the
// cumulative values directly would produce a plausible-looking histogram that is
// wrong everywhere except the first bucket.
//
// len(bucketCounts) must be exactly len(explicitBounds)+1 or consumers reject or
// misread the point.
func (t *Telemetry) latencyHistogram(now, start string) map[string]any {
	// Read each counter once. They are individually atomic but not a consistent
	// snapshot, so differencing re-read values could produce nonsense.
	cumulative := make([]int64, len(latencyBounds))
	for i := range latencyBounds {
		cumulative[i] = t.m.LatencyBuckets[i].Load()
	}
	count := t.m.Completed.Load()
	sum := t.m.LatencyMS.Load()

	counts := make([]string, 0, len(latencyBounds)+1)
	prev := int64(0)
	for _, c := range cumulative {
		// Clamped: a request completing between two of the loads above can leave
		// a difference momentarily negative, which is not a real value.
		counts = append(counts, strconv.FormatInt(max(c-prev, 0), 10))
		prev = c
	}
	counts = append(counts, strconv.FormatInt(max(count-prev, 0), 10)) // the +Inf bucket

	bounds := make([]any, 0, len(latencyBounds))
	for _, b := range latencyBounds {
		bounds = append(bounds, b)
	}
	return map[string]any{
		"name": "switchboard.request_duration_milliseconds",
		"unit": "ms",
		"histogram": map[string]any{
			"aggregationTemporality": 2,
			"dataPoints": []any{map[string]any{
				"startTimeUnixNano": start,
				"timeUnixNano":      now,
				"count":             strconv.FormatInt(count, 10),
				"sum":               float64(sum),
				"bucketCounts":      counts,
				"explicitBounds":    bounds,
			}},
		},
	}
}

// OTLP/HTTP JSON encoding follows the OpenTelemetry protobuf JSON mapping.
func (t *Telemetry) exportOTLP(ctx context.Context, e Event) {
	span := map[string]any{"traceId": e.TraceID, "spanId": e.SpanID, "name": "switchboard.inference", "kind": 2, "startTimeUnixNano": strconv.FormatInt(e.Start, 10), "endTimeUnixNano": strconv.FormatInt(e.End, 10), "attributes": []any{map[string]any{"key": "gen_ai.provider.name", "value": map[string]any{"stringValue": e.Provider}}, map[string]any{"key": "http.response.status_code", "value": map[string]any{"intValue": strconv.Itoa(e.Status)}}}}
	if e.ParentID != "" {
		span["parentSpanId"] = e.ParentID
	}
	if e.Status >= 400 {
		span["status"] = map[string]any{"code": 2}
	}
	body := map[string]any{"resourceSpans": []any{map[string]any{"resource": map[string]any{"attributes": []any{map[string]any{"key": "service.name", "value": map[string]any{"stringValue": "switchboard-gateway"}}}}, "scopeSpans": []any{map[string]any{"scope": map[string]any{"name": "switchboard", "version": "1.0.0"}, "spans": []any{span}}}}}}
	req, _ := http.NewRequestWithContext(ctx, "POST", t.c.OTLPURL, bytes.NewReader(jsonBytes(body)))
	req.Header.Set("Content-Type", "application/json")
	res, err := t.http.Do(req)
	if err != nil {
		t.m.ExportErrors.Add(1)
		return
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, 8192))
	res.Body.Close()
	if res.StatusCode != 200 || bytes.Contains(b, []byte("rejectedSpans")) {
		t.m.ExportErrors.Add(1)
	}
}
