package gateway

// Live provider verification.
//
// These call the real OpenAI, Anthropic and Gemini APIs. They are skipped
// unless explicitly enabled, because they cost money and need credentials.
//
//	SWITCHBOARD_LIVE_OPENAI=1    OPENAI_API_KEY=...    go test -run Live ./internal/gateway/
//	SWITCHBOARD_LIVE_ANTHROPIC=1 ANTHROPIC_API_KEY=... go test -run Live ./internal/gateway/
//	SWITCHBOARD_LIVE_GEMINI=1    GEMINI_API_KEY=...    go test -run Live ./internal/gateway/
//
// They exist because the equivalent test against real Bedrock immediately found
// a defect that would have failed every genuine request: the response carried a
// field the wire struct did not model, and decoding was strict. A mock cannot
// find that class of bug, because a mock only returns the fields we wrote into
// it. These three adapters carry roughly thirty response-shape assumptions that
// have only ever been checked against mocks built from the same assumptions.
//
// The request goes through upstream() and the response through normalize(),
// which is the exact path a production request takes, so request construction,
// authentication, response parsing and finish-reason mapping are all exercised
// together rather than in isolation.

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type liveProvider struct {
	name, gate, keyEnv, url, model string
}

var liveProviders = []liveProvider{
	{"openai", "SWITCHBOARD_LIVE_OPENAI", "OPENAI_API_KEY",
		"https://api.openai.com", "gpt-4o-mini"},
	{"anthropic", "SWITCHBOARD_LIVE_ANTHROPIC", "ANTHROPIC_API_KEY",
		"https://api.anthropic.com", "claude-3-5-haiku-latest"},
	{"gemini", "SWITCHBOARD_LIVE_GEMINI", "GEMINI_API_KEY",
		"https://generativelanguage.googleapis.com", "gemini-2.0-flash"},
}

func (p liveProvider) skipUnlessEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv(p.gate) != "1" {
		t.Skipf("set %s=1 and %s to exercise the real %s API", p.gate, p.keyEnv, p.name)
	}
	if os.Getenv(p.keyEnv) == "" {
		t.Fatalf("%s is set but %s is empty", p.gate, p.keyEnv)
	}
}

func (p liveProvider) send(t *testing.T, c Chat) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	req, err := upstream(ctx, c,
		Route{Provider: p.name, Model: p.model},
		ProviderConfig{URL: p.url, KeyEnv: p.keyEnv}, nil)
	if err != nil {
		t.Fatalf("%s: could not build the request: %v", p.name, err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s: request failed: %v", p.name, err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

// A complete response, through the same normalize() a production request uses.
func TestLiveNonStreaming(t *testing.T) {
	for _, p := range liveProviders {
		t.Run(p.name, func(t *testing.T) {
			p.skipUnlessEnabled(t)
			res := p.send(t, Chat{
				MaxTokens: 16,
				Messages:  []Message{{Role: "user", Content: "Reply with the single word: ok"}},
			})
			body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
			if res.StatusCode != 200 {
				t.Fatalf("%s returned %d: %s", p.name, res.StatusCode, truncate(body))
			}
			n, _, err := normalize(p.name, body, false)
			if err != nil {
				// The Bedrock equivalent of this failure was a real defect, not
				// a test problem, so the body is printed to make it diagnosable.
				t.Fatalf("%s: a real response did not normalize: %v\nbody: %s",
					p.name, err, truncate(body))
			}
			if n.Text == "" {
				t.Errorf("%s: normalized to empty text", p.name)
			}
			if n.Finish == "" {
				t.Errorf("%s: no finish reason", p.name)
			}
			if n.Input == 0 && n.Output == 0 {
				// Not fatal: usage accounting differs per provider and may be
				// absent. Worth surfacing because billing would depend on it.
				t.Logf("%s: no token usage reported", p.name)
			}
			t.Logf("%s: text=%q finish=%s in=%d out=%d", p.name, n.Text, n.Finish, n.Input, n.Output)
		})
	}
}

// Streaming is where truncation handling and the finish-reason rules live, and
// where a hand-written mock proves least: real providers chunk differently,
// send keepalives, and terminate in their own ways.
func TestLiveStreaming(t *testing.T) {
	for _, p := range liveProviders {
		t.Run(p.name, func(t *testing.T) {
			p.skipUnlessEnabled(t)
			res := p.send(t, Chat{
				Stream:    true,
				MaxTokens: 32,
				Messages:  []Message{{Role: "user", Content: "Count: one two three"}},
			})
			if res.StatusCode != 200 {
				body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
				t.Fatalf("%s returned %d: %s", p.name, res.StatusCode, truncate(body))
			}
			if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "event-stream") {
				t.Errorf("%s: streaming content type is %q", p.name, ct)
			}

			var text strings.Builder
			var finish string
			frames, done := 0, false
			sc := bufio.NewScanner(res.Body)
			sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if !strings.HasPrefix(line, "data:") {
					continue
				}
				payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				if payload == "[DONE]" {
					done = true
					break
				}
				frames++
				n, complete, err := normalize(p.name, []byte(payload), true)
				if err != nil {
					t.Fatalf("%s: a real stream frame did not normalize: %v\nframe: %s",
						p.name, err, truncate([]byte(payload)))
				}
				text.WriteString(n.Text)
				if n.Finish != "" {
					finish = n.Finish
				}
				if complete {
					done = true
					break
				}
			}
			if err := sc.Err(); err != nil {
				t.Fatalf("%s: reading the stream failed: %v", p.name, err)
			}
			if frames == 0 {
				t.Fatalf("%s: no data frames", p.name)
			}
			if !done {
				// The gateway treats a stream ending without terminal marker as
				// truncation, so if a real provider does this the rule is wrong.
				t.Errorf("%s: stream ended without a terminal marker", p.name)
			}
			if finish == "" {
				t.Errorf("%s: stream carried no finish reason", p.name)
			}
			t.Logf("%s: %d frames, finish=%s, text=%q", p.name, frames, finish, text.String())
		})
	}
}

// The gateway rejects a response carrying a finish reason it does not model,
// so an unmapped value is a hard failure rather than a degraded one. This
// records what each provider actually sends when output is cut short.
func TestLiveTruncatedFinishReason(t *testing.T) {
	for _, p := range liveProviders {
		t.Run(p.name, func(t *testing.T) {
			p.skipUnlessEnabled(t)
			res := p.send(t, Chat{
				MaxTokens: 1, // forces the length/max_tokens path
				Messages:  []Message{{Role: "user", Content: "Write a long paragraph about the sea."}},
			})
			body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
			if res.StatusCode != 200 {
				t.Skipf("%s returned %d for a one-token request", p.name, res.StatusCode)
			}
			n, _, err := normalize(p.name, body, false)
			if err != nil {
				t.Fatalf("%s: truncated response did not normalize: %v\nbody: %s",
					p.name, err, truncate(body))
			}
			if n.Finish != "length" {
				t.Errorf("%s: expected finish=length when truncated, got %q", p.name, n.Finish)
			}
			t.Logf("%s: truncated finish=%s", p.name, n.Finish)
		})
	}
}

func truncate(b []byte) string {
	const max = 600
	if len(b) > max {
		return string(bytes.TrimSpace(b[:max])) + "…"
	}
	return string(bytes.TrimSpace(b))
}
