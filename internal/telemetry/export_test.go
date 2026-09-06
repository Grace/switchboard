package telemetry

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func (c *collector) header(name string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.headers.Get(name)
}

func tracerTo(t *testing.T, c *collector, cfg Config) *Tracer {
	t.Helper()
	cfg.Endpoint = strings.TrimPrefix(c.URL, "http://")
	cfg.Insecure = true
	cfg.Version = "test"
	tr, err := NewTracer(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Shutdown(context.Background()) })
	return tr
}

// Without headers switchboard can reach a collector on your own network and
// nothing beyond it, because every hosted backend authenticates this way.
func TestHeadersReachTheBackendOnBothSignals(t *testing.T) {
	c := newCollector(t)
	hdr := map[string]string{"x-honeycomb-team": "secret-key", "x-honeycomb-dataset": "switchboard"}

	tr := tracerTo(t, c, Config{Headers: hdr})
	_, span := tr.Start(context.Background(), "claude-sonnet", "search", "")
	Finish(span, Outcome{AuditID: "a1", Recorded: true}, nil)
	if err := tr.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := c.header("x-honeycomb-team"); got != "secret-key" {
		t.Errorf("trace export sent x-honeycomb-team = %q", got)
	}

	m, err := New(context.Background(), Config{
		Endpoint: strings.TrimPrefix(c.URL, "http://"), Insecure: true,
		Interval: 50 * time.Millisecond, Version: "test", Headers: hdr,
	})
	if err != nil {
		t.Fatal(err)
	}
	m.Completion(context.Background(), "search", "claude-sonnet", "bedrock", "ok", 10, 5)
	if err := m.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := c.header("x-honeycomb-dataset"); got != "switchboard" {
		t.Errorf("metric export sent x-honeycomb-dataset = %q", got)
	}
}

// The fingerprint is what lets an event in a backend that samples and expires
// be resolved, later, against the archived configuration that produced it.
func TestSpansCarryThePolicyFingerprint(t *testing.T) {
	c := newCollector(t)
	tr := tracerTo(t, c, Config{Policy: "4f4c581392f8"})
	_, span := tr.Start(context.Background(), "claude-sonnet", "search", "")
	Finish(span, Outcome{AuditID: "a1", Recorded: true}, nil)
	tr.Shutdown(context.Background())

	if _, body := c.received(); !strings.Contains(string(body), "4f4c581392f8") {
		t.Fatal("no policy fingerprint on the exported span")
	}
}

// A request that happened and was not written down is the gap the evidence tier
// exists to close, so it belongs in the tool people actually watch.
func TestAnUnrecordedCompletionSaysSoOnTheSpan(t *testing.T) {
	c := newCollector(t)
	tr := tracerTo(t, c, Config{})
	_, span := tr.Start(context.Background(), "claude-sonnet", "search", "")
	Finish(span, Outcome{AuditID: "a1", Recorded: false}, nil)
	tr.Shutdown(context.Background())

	_, body := c.received()
	if !strings.Contains(string(body), "switchboard.audit.recorded") {
		t.Fatal("the span does not say whether the completion was recorded")
	}
}

// A refusal is either an attack that was stopped or a permission somebody
// needs. A trace showing only successful calls is silent about both.
func TestRefusalsAreCountedOnTheSpan(t *testing.T) {
	c := newCollector(t)
	tr := tracerTo(t, c, Config{})
	_, span := tr.Start(context.Background(), "claude-sonnet", "support", "")
	Tools(span, []string{"search", "wire_transfer"}, []Invocation{
		{Name: "search", ID: "c1"},
		{Name: "wire_transfer", ID: "c2", Refused: true, Reason: "tool_not_permitted"},
	})
	Finish(span, Outcome{AuditID: "a1", Recorded: true}, nil)
	tr.Shutdown(context.Background())

	body := string(mustBody(t, c))
	for _, want := range []string{"switchboard.tools.refused", "tool_not_permitted", "wire_transfer"} {
		if !strings.Contains(body, want) {
			t.Errorf("export is missing %q", want)
		}
	}
}

// Cached tokens bill at a fraction of the input rate, so folding them into
// input produces a cost chart that is wrong by close to an order of magnitude
// for any deployment with a large stable prompt.
func TestCacheTokensAreTheirOwnFields(t *testing.T) {
	c := newCollector(t)
	tr := tracerTo(t, c, Config{})
	_, span := tr.Start(context.Background(), "claude-sonnet", "search", "")
	Finish(span, Outcome{
		AuditID: "a1", Recorded: true,
		PromptTokens: 100, ReplyTokens: 50,
		CacheReadTokens: 4000, CacheWriteTokens: 200,
	}, nil)
	tr.Shutdown(context.Background())

	body := string(mustBody(t, c))
	for _, want := range []string{"cache_read_tokens", "cache_write_tokens"} {
		if !strings.Contains(body, want) {
			t.Errorf("export is missing %q", want)
		}
	}
}

// The boundary the whole design depends on: content goes to the audit log
// behind the redactor, or nowhere. A span that carried a prompt would route
// around the one chokepoint everything else relies on.
//
// Asserted structurally rather than by scanning an export, because the
// guarantee is that these shapes have no field able to carry content — there is
// no way to inject a prompt through this API, and a test that tried would be
// testing its own fixture. What this catches is the future edit that adds one.
func TestTheExportedShapesCannotCarryContent(t *testing.T) {
	banned := []string{"prompt", "completion", "argument", "message", "content", "text", "body"}
	for _, shape := range []any{Outcome{}, Invocation{}} {
		typ := reflect.TypeOf(shape)
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			// Counts only, so PromptTokens is fine and a Prompt would not be.
			// Content is a string; a number derived from it is not content.
			if f.Type.Kind() != reflect.String {
				continue
			}
			name := strings.ToLower(f.Name)
			for _, b := range banned {
				if strings.Contains(name, b) {
					t.Errorf("%s.%s is a string that can carry content, and this shape "+
						"leaves the process for a backend with no redaction step of its own",
						typ.Name(), f.Name)
				}
			}
		}
	}
}

// And the one field that names something a caller controls is a tool name,
// which is metadata. Arguments are the content, and there is nowhere to put
// them.
func TestARefusedCallExportsItsNameAndNotItsArguments(t *testing.T) {
	c := newCollector(t)
	tr := tracerTo(t, c, Config{})
	_, span := tr.Start(context.Background(), "claude-sonnet", "support", "")
	Tools(span, []string{"wire_transfer"}, []Invocation{
		{Name: "wire_transfer", ID: "c1", Refused: true, Reason: "tool_not_permitted"},
	})
	Finish(span, Outcome{AuditID: "a1", Recorded: true}, nil)
	tr.Shutdown(context.Background())

	body := string(mustBody(t, c))
	if !strings.Contains(body, "wire_transfer") {
		t.Error("the tool name should export: it is metadata and it is the finding")
	}
}

func mustBody(t *testing.T, c *collector) []byte {
	t.Helper()
	hits, body := c.received()
	if hits == 0 {
		t.Fatal("nothing reached the collector")
	}
	return body
}
