package gateway

import (
	"context"
	"encoding/json"
	"net/http"

	"os"
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
