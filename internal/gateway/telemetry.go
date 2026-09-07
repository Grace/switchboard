package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Metrics struct {
	Requests, Errors, Retries, Rejected, Dropped, DiskErrors, ExportErrors, PolicyErrors, SpoolUsed, SpoolCount, Active, LatencyMS, Completed atomic.Int64
	LatencyBuckets                                                                                                                            [7]atomic.Int64
	LogDropped                                                                                                                                *atomic.Int64
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

func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	for _, v := range []struct {
		name, kind string
		v          *atomic.Int64
	}{{"requests_total", "counter", &m.Requests}, {"errors_total", "counter", &m.Errors}, {"retries_total", "counter", &m.Retries}, {"rejected_total", "counter", &m.Rejected}, {"telemetry_dropped_total", "counter", &m.Dropped}, {"telemetry_disk_errors_total", "counter", &m.DiskErrors}, {"telemetry_export_errors_total", "counter", &m.ExportErrors}, {"policy_errors_total", "counter", &m.PolicyErrors}, {"spool_bytes", "gauge", &m.SpoolUsed}, {"spool_events", "gauge", &m.SpoolCount}, {"active_requests", "gauge", &m.Active}} {
		fmt.Fprintf(w, "# TYPE switchboard_%s %s\nswitchboard_%s %d\n", v.name, v.kind, v.name, v.v.Load())
	}
	fmt.Fprintln(w, "# TYPE switchboard_request_duration_milliseconds histogram")
	for i, b := range latencyBounds {
		fmt.Fprintf(w, "switchboard_request_duration_milliseconds_bucket{le=\"%d\"} %d\n", b, m.LatencyBuckets[i].Load())
	}
	fmt.Fprintf(w, "switchboard_request_duration_milliseconds_bucket{le=\"+Inf\"} %d\nswitchboard_request_duration_milliseconds_sum %d\nswitchboard_request_duration_milliseconds_count %d\n", m.Completed.Load(), m.LatencyMS.Load(), m.Completed.Load())
	if m.LogDropped != nil {
		fmt.Fprintf(w, "# TYPE switchboard_log_dropped_total counter\nswitchboard_log_dropped_total %d\n", m.LogDropped.Load())
	}
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
	return &Telemetry{c: c, m: m, queue: make(chan Event, c.QueueSize), otlp: make(chan Event, c.QueueSize), http: client(5 * time.Second), dir: dir}, nil
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
func (t *Telemetry) Start(ctx context.Context) {
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
func (t *Telemetry) deliver(ctx context.Context) {
	files, e := os.ReadDir(t.dir)
	if e != nil {
		t.m.DiskErrors.Add(1)
		return
	}
	sent := 0
	for _, f := range files {
		if ctx.Err() != nil || sent >= 100 {
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
		req, _ := http.NewRequestWithContext(ctx, "POST", trimURL(t.c.ControlURL)+"/v1/telemetry", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+os.Getenv(t.c.ControlTokenEnv))
		req.Header.Set("Content-Type", "application/json")
		res, e := t.http.Do(req)
		if e != nil {
			t.m.ExportErrors.Add(1)
			return
		}
		ack, e := io.ReadAll(io.LimitReader(res.Body, 8193))
		res.Body.Close()
		var a struct {
			ID string `json:"id"`
		}
		if e != nil || res.StatusCode != 200 || json.Unmarshal(ack, &a) != nil || a.ID != event.ID {
			t.m.ExportErrors.Add(1)
			return
		}
		if os.Remove(path) != nil {
			t.m.DiskErrors.Add(1)
			return
		}
		t.m.SpoolUsed.Add(-int64(len(b)))
		t.m.SpoolCount.Add(-1)
		sent++
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
