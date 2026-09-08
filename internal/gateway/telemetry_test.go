package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDurableReplayAndAck(t *testing.T) {
	var ok atomic.Bool
	cp := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ok.Load() {
			w.WriteHeader(503)
			return
		}
		var e Event
		json.NewDecoder(r.Body).Decode(&e)
		w.Write(jsonBytes(map[string]string{"id": e.ID}))
	}))
	defer cp.Close()
	c := Config{DataDir: t.TempDir(), ControlURL: cp.URL, QueueSize: 1, SpoolBytes: 1 << 20}
	m := &Metrics{}
	tel, e := NewTelemetry(c, m)
	if e != nil {
		t.Fatal(e)
	}
	useTestTransport(tel.http)
	tel.persist(Event{ID: randomID(16)})
	tel.deliver(context.Background())
	if m.SpoolCount.Load() != 1 {
		t.Fatal("unacknowledged event deleted")
	}
	m2 := &Metrics{}
	restarted, e := NewTelemetry(c, m2)
	if e != nil {
		t.Fatal(e)
	}
	if m2.SpoolCount.Load() != 1 {
		t.Fatal("spool lost on restart")
	}
	ok.Store(true)
	useTestTransport(restarted.http)
	restarted.deliver(context.Background())
	if m2.SpoolCount.Load() != 0 {
		t.Fatal("ack did not remove event")
	}
	files, _ := os.ReadDir(restarted.dir)
	if len(files) != 0 {
		t.Fatal("spool not empty")
	}
}
func TestTelemetryNeverWaitsForDiskOrNetwork(t *testing.T) {
	c := Config{DataDir: t.TempDir(), QueueSize: 1, SpoolBytes: 1}
	m := &Metrics{}
	tel, _ := NewTelemetry(c, m)
	start := time.Now()
	for i := 0; i < 10000; i++ {
		tel.Emit(Event{})
	}
	if time.Since(start) > time.Second || m.Dropped.Load() != 9999 {
		t.Fatal("queue blocked")
	}
	tel.persist(Event{ID: randomID(16)})
	if m.SpoolCount.Load() != 0 {
		t.Fatal("disk cap ignored")
	}
}
func TestOTLPIndependentOfControlPlane(t *testing.T) {
	got := make(chan bool, 1)
	collector := testHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["resourceSpans"] != nil {
			got <- true
		}
		w.Write([]byte(`{}`))
	}))
	defer collector.Close()
	c := Config{DataDir: t.TempDir(), ControlURL: "http://127.0.0.1:1", OTLPURL: collector.URL, QueueSize: 2, SpoolBytes: 1 << 20}
	tel, _ := NewTelemetry(c, &Metrics{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	useTestTransport(tel.http)
	tel.Start(ctx)
	tel.Emit(Event{ID: randomID(16), TraceID: randomID(16), SpanID: randomID(8), Start: 1, End: 2})
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("OTLP blocked on control plane")
	}
	cancel()
	tel.Wait()
}

// A counter that is declared but left out of the export list is invisible, which
// is the same as not having it. These three exist to make provider faults
// observable, so silently not exporting them would defeat the point.
func TestProviderFaultCountersAreExported(t *testing.T) {
	m := &Metrics{}
	m.EmptyCompletion.Add(3)
	m.AccountFailover.Add(2)
	m.ProviderProbeFailed.Add(1)
	w := httptest.NewRecorder()
	m.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	for _, want := range []string{
		"switchboard_empty_completion_total 3",
		"switchboard_account_failover_total 2",
		"switchboard_provider_probe_failed_total 1",
	} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("metrics output is missing %q", want)
		}
	}
}

// Nothing collects /metrics in a shipped deployment: the endpoint is loopback
// only and the scraping collector is an opt-in sidecar absent from both
// templates. These assert the push path that makes the counters readable.
func TestOTLPMetricsExport(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := &Metrics{}
	m.EmptyCompletionFailed.Add(7)
	m.Active.Add(3)
	tel := &Telemetry{c: Config{OTLPMetricsURL: srv.URL}, m: m, http: srv.Client(), start: time.Now()}
	tel.exportMetrics(context.Background())

	var body struct {
		ResourceMetrics []struct {
			ScopeMetrics []struct {
				Metrics []struct {
					Name string `json:"name"`
					Sum  *struct {
						AggregationTemporality int  `json:"aggregationTemporality"`
						IsMonotonic            bool `json:"isMonotonic"`
						DataPoints             []struct {
							AsInt             string `json:"asInt"`
							StartTimeUnixNano string `json:"startTimeUnixNano"`
						} `json:"dataPoints"`
					} `json:"sum"`
					Gauge *struct {
						DataPoints []struct {
							AsInt             string `json:"asInt"`
							StartTimeUnixNano string `json:"startTimeUnixNano"`
						} `json:"dataPoints"`
					} `json:"gauge"`
				} `json:"metrics"`
			} `json:"scopeMetrics"`
		} `json:"resourceMetrics"`
	}
	if err := json.Unmarshal(got, &body); err != nil {
		t.Fatalf("exported body is not valid OTLP JSON: %v\n%s", err, got)
	}
	if len(body.ResourceMetrics) != 1 || len(body.ResourceMetrics[0].ScopeMetrics) != 1 {
		t.Fatalf("unexpected envelope: %s", got)
	}
	seen := map[string]bool{}
	for _, mt := range body.ResourceMetrics[0].ScopeMetrics[0].Metrics {
		seen[mt.Name] = true
		switch mt.Name {
		case "switchboard.empty_completion_failed_total":
			if mt.Sum == nil {
				t.Fatal("a counter was not exported as a sum")
			}
			// Cumulative and monotonic: the value is a running total, and a
			// consumer must be able to tell a reset from a restart.
			if mt.Sum.AggregationTemporality != 2 || !mt.Sum.IsMonotonic {
				t.Errorf("counter temporality=%d monotonic=%v", mt.Sum.AggregationTemporality, mt.Sum.IsMonotonic)
			}
			if mt.Sum.DataPoints[0].AsInt != "7" {
				t.Errorf("value = %q, want 7", mt.Sum.DataPoints[0].AsInt)
			}
			if mt.Sum.DataPoints[0].StartTimeUnixNano == "" {
				t.Error("cumulative point carries no start time")
			}
		case "switchboard.active_requests":
			if mt.Gauge == nil {
				t.Fatal("a gauge was exported as a sum")
			}
			if mt.Gauge.DataPoints[0].AsInt != "3" {
				t.Errorf("gauge = %q, want 3", mt.Gauge.DataPoints[0].AsInt)
			}
		}
	}
	// The whole point of the shared series() list: a counter added in one place
	// and forgotten in the other is invisible exactly where someone looks.
	for _, want := range []string{
		"switchboard.requests_total",
		"switchboard.empty_completion_recovered_total",
		"switchboard.empty_completion_failed_total",
		"switchboard.account_failover_total",
		"switchboard.active_requests",
	} {
		if !seen[want] {
			t.Errorf("metric %q was not exported", want)
		}
	}
}

func TestOTLPMetricsCountsExportFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	m := &Metrics{}
	tel := &Telemetry{c: Config{OTLPMetricsURL: srv.URL}, m: m, http: srv.Client(), start: time.Now()}
	tel.exportMetrics(context.Background())
	if m.ExportErrors.Load() != 1 {
		t.Errorf("ExportErrors = %d, want 1", m.ExportErrors.Load())
	}
}

// An unset endpoint must send nothing at all, so a deployment with no collector
// is not making a request every interval to somewhere it was never told about.
func TestOTLPMetricsDisabledWhenURLEmpty(t *testing.T) {
	var called atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called.Add(1) }))
	defer srv.Close()
	tel := &Telemetry{c: Config{}, m: &Metrics{}, queue: make(chan Event, 1), otlp: make(chan Event, 1),
		http: srv.Client(), dir: t.TempDir(), start: time.Now()}
	ctx, cancel := context.WithCancel(context.Background())
	tel.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()
	tel.wg.Wait()
	if called.Load() != 0 {
		t.Errorf("exported %d times with no endpoint configured", called.Load())
	}
}

// Prometheus buckets are cumulative; OTLP bucketCounts are not. Emitting the
// cumulative values directly would produce a histogram that looks plausible and
// is wrong in every bucket but the first, which is worse than not exporting one.
func TestOTLPHistogramBucketsAreDifferenced(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := &Metrics{}
	// latencyBounds is [100 500 1000 5000 15000 60000 90000].
	// Two land in the first bucket, one in the second, one past every bound.
	for _, ms := range []int64{10, 50, 300, 200000} {
		m.ObserveLatency(ms)
	}
	tel := &Telemetry{c: Config{OTLPMetricsURL: srv.URL}, m: m, http: srv.Client(), start: time.Now()}
	tel.exportMetrics(context.Background())

	var body struct {
		ResourceMetrics []struct {
			ScopeMetrics []struct {
				Metrics []struct {
					Name      string `json:"name"`
					Histogram *struct {
						AggregationTemporality int `json:"aggregationTemporality"`
						DataPoints             []struct {
							Count          string   `json:"count"`
							Sum            float64  `json:"sum"`
							BucketCounts   []string `json:"bucketCounts"`
							ExplicitBounds []int64  `json:"explicitBounds"`
						} `json:"dataPoints"`
					} `json:"histogram"`
				} `json:"metrics"`
			} `json:"scopeMetrics"`
		} `json:"resourceMetrics"`
	}
	if err := json.Unmarshal(got, &body); err != nil {
		t.Fatalf("not valid OTLP JSON: %v", err)
	}
	var h *struct {
		Count          string   `json:"count"`
		Sum            float64  `json:"sum"`
		BucketCounts   []string `json:"bucketCounts"`
		ExplicitBounds []int64  `json:"explicitBounds"`
	}
	var temporality int
	for _, mt := range body.ResourceMetrics[0].ScopeMetrics[0].Metrics {
		if mt.Name == "switchboard.request_duration_milliseconds" {
			if mt.Histogram == nil || len(mt.Histogram.DataPoints) != 1 {
				t.Fatal("histogram missing or has no data point")
			}
			temporality = mt.Histogram.AggregationTemporality
			h = &mt.Histogram.DataPoints[0]
		}
	}
	if h == nil {
		t.Fatalf("latency histogram was not exported: %s", got)
	}
	if temporality != 2 {
		t.Errorf("aggregationTemporality = %d, want 2 (cumulative)", temporality)
	}
	// The invariant a consumer relies on.
	if len(h.BucketCounts) != len(h.ExplicitBounds)+1 {
		t.Fatalf("bucketCounts=%d bounds=%d; must differ by exactly one",
			len(h.BucketCounts), len(h.ExplicitBounds))
	}
	if len(h.ExplicitBounds) != len(latencyBounds) {
		t.Errorf("bounds = %v, want %v", h.ExplicitBounds, latencyBounds)
	}
	// The arithmetic check that catches a cumulative-vs-per-bucket mistake even
	// when every individual value looks reasonable.
	var total int64
	for _, c := range h.BucketCounts {
		n, err := strconv.ParseInt(c, 10, 64)
		if err != nil {
			t.Fatalf("bucket count %q is not an integer", c)
		}
		if n < 0 {
			t.Errorf("negative bucket count %d", n)
		}
		total += n
	}
	if h.Count != "4" || total != 4 {
		t.Errorf("count=%q, buckets sum to %d; want both 4", h.Count, total)
	}
	// And by value, not only by sum: 10ms and 50ms both fall at or below 100.
	if h.BucketCounts[0] != "2" {
		t.Errorf("first bucket = %q, want 2 (10ms and 50ms)", h.BucketCounts[0])
	}
	if h.BucketCounts[1] != "1" {
		t.Errorf("second bucket = %q, want 1 (300ms)", h.BucketCounts[1])
	}
	// 200000ms exceeds every bound and belongs in the overflow bucket.
	if h.BucketCounts[len(h.BucketCounts)-1] != "1" {
		t.Errorf("overflow bucket = %q, want 1 (200000ms)", h.BucketCounts[len(h.BucketCounts)-1])
	}
	if h.Sum != float64(m.LatencyMS.Load()) {
		t.Errorf("sum = %v, want %d", h.Sum, m.LatencyMS.Load())
	}
}

// The runtime gauges exist to attribute the linear memory growth recorded in
// docs/VALIDATION.md. They are sampled rather than counted, so the thing worth
// asserting is that a consumer sees live values and that both export paths
// agree on their type.
func TestRuntimeGaugesAreExported(t *testing.T) {
	m := &Metrics{}
	w := httptest.NewRecorder()
	m.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	out := w.Body.String()

	for _, name := range []string{"goroutines", "heap_alloc_bytes", "heap_objects", "heap_sys_bytes"} {
		if !strings.Contains(out, "# TYPE switchboard_"+name+" gauge") {
			t.Errorf("%s is not declared as a gauge", name)
		}
	}
	// A zero here would mean the sample never ran: a live process always has at
	// least the goroutine running this test.
	if m.Goroutines.Load() < 1 {
		t.Errorf("goroutines = %d, want at least 1", m.Goroutines.Load())
	}
	if m.HeapAlloc.Load() < 1 || m.HeapSys.Load() < 1 || m.HeapObjects.Load() < 1 {
		t.Errorf("heap gauges not sampled: alloc=%d objects=%d sys=%d",
			m.HeapAlloc.Load(), m.HeapObjects.Load(), m.HeapSys.Load())
	}
}

// series() samples on every call rather than once, so a scrape reports the
// process as it is now and not as it was when the struct was built.
func TestRuntimeGaugesResampleOnEveryRead(t *testing.T) {
	m := &Metrics{}
	const sentinel = -1
	for i := 0; i < 2; i++ {
		m.Goroutines.Store(sentinel)
		m.HeapAlloc.Store(sentinel)
		m.series()
		if m.Goroutines.Load() == sentinel || m.HeapAlloc.Load() == sentinel {
			t.Fatalf("read %d did not resample: goroutines=%d heap_alloc=%d",
				i+1, m.Goroutines.Load(), m.HeapAlloc.Load())
		}
	}
}

// The series list exists so the Prometheus endpoint and the OTLP exporter
// cannot drift. A gauge exported as a cumulative sum would be read as a running
// total and misinterpreted, so assert the shape rather than only the name.
func TestRuntimeGaugesExportAsGaugesOverOTLP(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	tel := &Telemetry{c: Config{OTLPMetricsURL: srv.URL}, m: &Metrics{}, http: srv.Client(), start: time.Now()}
	tel.exportMetrics(context.Background())

	var body struct {
		ResourceMetrics []struct {
			ScopeMetrics []struct {
				Metrics []struct {
					Name  string          `json:"name"`
					Sum   json.RawMessage `json:"sum"`
					Gauge *struct {
						DataPoints []struct {
							AsInt string `json:"asInt"`
						} `json:"dataPoints"`
					} `json:"gauge"`
				} `json:"metrics"`
			} `json:"scopeMetrics"`
		} `json:"resourceMetrics"`
	}
	if err := json.Unmarshal(got, &body); err != nil {
		t.Fatalf("exported body is not valid OTLP JSON: %v\n%s", err, got)
	}
	want := map[string]bool{
		"switchboard.goroutines": false, "switchboard.heap_alloc_bytes": false,
		"switchboard.heap_objects": false, "switchboard.heap_sys_bytes": false,
	}
	for _, mt := range body.ResourceMetrics[0].ScopeMetrics[0].Metrics {
		if _, ok := want[mt.Name]; !ok {
			continue
		}
		if mt.Sum != nil {
			t.Errorf("%s exported as a sum; it is a gauge", mt.Name)
		}
		if mt.Gauge == nil || len(mt.Gauge.DataPoints) != 1 {
			t.Errorf("%s has no gauge data point", mt.Name)
			continue
		}
		if v, err := strconv.ParseInt(mt.Gauge.DataPoints[0].AsInt, 10, 64); err != nil || v < 1 {
			t.Errorf("%s = %q, want a positive sampled value", mt.Name, mt.Gauge.DataPoints[0].AsInt)
		}
		want[mt.Name] = true
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("%s missing from the OTLP payload", name)
		}
	}
}
