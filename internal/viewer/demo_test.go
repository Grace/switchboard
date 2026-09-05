package viewer

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/redact"
)

func ptr(f float64) *float64 { return &f }

// TestGenerateDemoPage is a dev affordance, not an assertion: set
// SWITCHBOARD_DEMO_OUT and it writes a page from a synthetic log so the layout
// can be looked at with real shapes in it.
func TestGenerateDemoPage(t *testing.T) {
	out := os.Getenv("SWITCHBOARD_DEMO_OUT")
	if out == "" {
		t.Skip("set SWITCHBOARD_DEMO_OUT to render a demo page")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	t.Setenv("SWITCHBOARD_AUDIT_KEY", "demo-key")

	red, err := redact.New([]string{"email", "credit_card", "phone_us"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := audit.Open(path, red, true)
	if err != nil {
		t.Fatal(err)
	}

	type line struct {
		backend, model string
	}
	lines := []line{
		{"bedrock", "claude-opus"}, {"bedrock", "claude-opus"}, {"bedrock", "claude-opus"},
		{"bedrock", "claude-sonnet"}, {"bedrock", "claude-sonnet"},
		{"local", "qwen3-8b"}, {"local", "llama-3.1-8b"},
	}
	teams := map[string][]string{
		"search":    {"dana@corp", "lee@corp", "amari@corp"},
		"billing":   {"kim@corp", "rowan@corp"},
		"fraud-ops": {"sasha@corp"},
		"support":   {"jo@corp", "wren@corp", "nas@corp", "tal@corp"},
	}
	teamNames := []string{"search", "search", "search", "billing", "billing", "fraud-ops", "support"}
	// Tools, offered to the teams that run agentic workflows. close_account is
	// offered and never called, which is the row worth seeing.
	agentTools := []string{"lookup_account", "transfer_funds", "email_customer", "close_account"}
	prompts := []string{
		"summarise this ticket for the customer",
		"classify the disputed charge on card 4111 1111 1111 1111",
		"draft a reply to grace@example.com about the refund",
		"why did this transaction score as high risk",
		"rewrite this paragraph for a compliance audience",
		"extract the merchant and amount from this statement line",
		"is this chargeback within the representment window",
	}

	rng := rand.New(rand.NewSource(7))
	base := time.Date(2026, 9, 4, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 900; i++ {
		ln := lines[rng.Intn(len(lines))]
		team := teamNames[rng.Intn(len(teamNames))]
		people := teams[team]
		subject := people[rng.Intn(len(people))]

		policy := "9f2a71c40db3"
		if i > 620 {
			policy = "c17e05ab9d44"
		}
		in := 300 + rng.Intn(2600)
		out := 60 + rng.Intn(700)
		if ln.backend == "local" {
			in, out = in/2, out/2
		}
		r := audit.Record{
			Time: base.Add(time.Duration(i) * 47 * time.Second),
			ID:   fmt.Sprintf("chatcmpl-%06d", i), Policy: policy,
			Team: team, Subject: subject, Model: ln.model, Backend: ln.backend,
			PromptTokens: in, CompletionTokens: out,
			Prompt: prompts[rng.Intn(len(prompts))], Completion: "…",
			StopReason: "end_turn", Streamed: rng.Intn(3) == 0,
			TraceID: fmt.Sprintf("%032x", rng.Uint64()),
			SpanID:  fmt.Sprintf("%016x", rng.Uint64()),
		}
		// Cached traffic on the hosted models: a large stable system prompt is
		// mostly cache reads after the first call.
		if ln.backend == "bedrock" && rng.Intn(4) != 0 {
			r.CacheReadTokens = 9000 + rng.Intn(3000)
			if rng.Intn(12) == 0 {
				r.CacheWriteTokens = 9000 + rng.Intn(3000)
				r.CacheReadTokens = 0
			}
			r.PromptTokens = 40 + rng.Intn(220)
		}

		// The agentic teams get tools. Most calls are a lookup; a few move money.
		if team == "fraud-ops" || team == "billing" {
			r.ToolsOffered = agentTools
			if rng.Intn(3) != 0 {
				r.ToolCalls = []audit.ToolCall{
					{Name: "lookup_account", ID: fmt.Sprintf("call-%d-a", i),
						Arguments: `{"account":"4111111111111111"}`},
				}
				if rng.Intn(9) == 0 {
					r.ToolCalls = append(r.ToolCalls, audit.ToolCall{
						Name: "transfer_funds", ID: fmt.Sprintf("call-%d-b", i),
						Arguments: `{"amount":250,"to":"grace@example.com"}`,
					})
				}
			}
		}

		if rng.Intn(45) == 0 {
			r.Error = "backend timed out after 30s"
			r.PromptTokens, r.CompletionTokens, r.StopReason = 0, 0, ""
			r.CacheReadTokens, r.CacheWriteTokens = 0, 0
			r.ToolCalls = nil
		}
		if err := l.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()

	prices := Prices{Currency: "USD", Model: map[string]Price{
		"claude-opus": {InPerMTok: 15, OutPerMTok: 75,
			CacheWrite: ptr(18.75), CacheReadPer: ptr(1.5)},
		"claude-sonnet": {InPerMTok: 3, OutPerMTok: 15,
			CacheWrite: ptr(3.75), CacheReadPer: ptr(0.3)},
		"qwen3-8b": {InPerMTok: 0.04, OutPerMTok: 0.04},
	}}
	n, err := WriteFile(out, path, []byte("demo-key"), prices)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s (%d bytes)", out, n)

	// Also a filtered slice, so the narrowed view can be looked at too.
	s, err := Summarise(path, []byte("demo-key"), Query{Team: "support"}, prices)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(out[:len(out)-5] + "-support.html")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := page.Execute(f, s); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", f.Name())

	// Keep the log itself where the CLI can be pointed at it.
	if keep := os.Getenv("SWITCHBOARD_DEMO_LOG"); keep != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keep, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", keep)
	}
}
