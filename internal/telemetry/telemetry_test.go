package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// collector stands in for an OTLP/HTTP receiver, recording what arrives.
type collector struct {
	*httptest.Server
	mu   sync.Mutex
	hits int
	body []byte
}

func newCollector(t *testing.T) *collector {
	t.Helper()
	c := &collector{}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.hits++
		c.body = b
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(c.Close)
	return c
}

func (c *collector) received() (int, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.body
}

func meterTo(t *testing.T, c *collector) *Meter {
	t.Helper()
	m, err := New(context.Background(), Config{
		Endpoint: strings.TrimPrefix(c.URL, "http://"),
		Insecure: true,
		Interval: 50 * time.Millisecond,
		Version:  "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Shutdown(context.Background()) })
	return m
}

// No endpoint means no telemetry, rather than a fallback somewhere surprising.
func TestNoEndpointIsNoMeter(t *testing.T) {
	m, err := New(context.Background(), Config{})
	if err != nil || m != nil {
		t.Fatalf("New with no endpoint = %v, %v; want nil, nil", m, err)
	}
	// And a nil meter must be safe to call.
	m.Completion(context.Background(), "t", "m", "b", "ok", 1, 1)
	m.Refused(context.Background(), "rate", "t")
	m.Redacted(context.Background(), map[string]int{"email": 1})
	if err := m.Shutdown(context.Background()); err != nil {
		t.Errorf("nil shutdown: %v", err)
	}
}

// A collector that is briefly unreachable must not stop the gateway starting.
func TestUnreachableCollectorDoesNotFailStartup(t *testing.T) {
	m, err := New(context.Background(), Config{
		Endpoint: "127.0.0.1:1", Insecure: true, Interval: time.Second,
	})
	if err != nil {
		t.Fatalf("an unreachable collector must not fail construction: %v", err)
	}
	m.Completion(context.Background(), "t", "m", "bedrock", "ok", 10, 5)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = m.Shutdown(ctx) // may error; must not hang or panic
}

func TestCompletionsReachTheCollector(t *testing.T) {
	c := newCollector(t)
	m := meterTo(t, c)

	for i := 0; i < 3; i++ {
		m.Completion(context.Background(), "search", "claude-opus", "bedrock", "ok", 800, 40)
	}
	if err := m.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	hits, body := c.received()
	if hits == 0 {
		t.Fatal("nothing was exported")
	}
	for _, want := range []string{"switchboard.requests", "search", "claude-opus", "bedrock"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("export missing %q", want)
		}
	}
}

// The count travels; the value never does.
func TestRedactionCountsExportWithoutValues(t *testing.T) {
	c := newCollector(t)
	m := meterTo(t, c)

	m.Redacted(context.Background(), map[string]int{"email": 11, "credit_card": 2})
	m.Shutdown(context.Background())

	_, body := c.received()
	s := string(body)
	if !strings.Contains(s, "switchboard.redactions") || !strings.Contains(s, "email") {
		t.Errorf("redaction counts not exported: %s", truncate(s))
	}
	// Nothing resembling a value should be anywhere near it.
	for _, forbidden := range []string{"@", "4111"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("export contains %q, which should never leave with a count", forbidden)
		}
	}
}

func TestRefusalsCarryTheLimitAndTeam(t *testing.T) {
	c := newCollector(t)
	m := meterTo(t, c)

	m.Refused(context.Background(), "token budget", "billing")
	m.Shutdown(context.Background())

	_, body := c.received()
	for _, want := range []string{"switchboard.refusals", "token budget", "billing"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("export missing %q", want)
		}
	}
}

// An unattributed caller must still be counted, under a name that says so.
func TestUnattributedCallersAreLabelled(t *testing.T) {
	c := newCollector(t)
	m := meterTo(t, c)

	m.Completion(context.Background(), "", "qwen3-8b", "local", "ok", 5, 5)
	m.Shutdown(context.Background())

	_, body := c.received()
	if !strings.Contains(string(body), "unattributed") {
		t.Error("an unattributed completion should be labelled, not dropped")
	}
}

func truncate(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

var _ = json.Marshal
