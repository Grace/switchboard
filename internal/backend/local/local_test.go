package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Grace/switchboard/internal/config"
	"github.com/Grace/switchboard/internal/switchboard"
	"github.com/Grace/switchboard/internal/wire"
)

// stub stands in for llama-server. The backend reaches a real HTTP server over
// a real connection and parses a real stream; only the model is absent.
//
// Injecting the instance directly is what makes this possible: ensure() returns
// a live instance without starting anything, so no process is spawned and no
// weights are loaded.
func stub(t *testing.T, h http.HandlerFunc) (*Backend, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	spec := config.Line{Name: "test-model", Backend: config.BackendLocal, Path: "/nonexistent.gguf"}
	b := New(Options{Logf: func(string, ...any) {}}, []config.Line{spec})
	b.live["test-model"] = &instance{
		spec: spec, base: srv.URL,
		started: time.Now(), lastUsed: time.Now(),
		done: make(chan struct{}),
	}
	return b, srv
}

func sse(frames ...string) string {
	var b strings.Builder
	for _, f := range frames {
		fmt.Fprintf(&b, "data: %s\n\n", f)
	}
	b.WriteString("data: [DONE]\n\n")
	return b.String()
}

func chunkFrame(text string) string {
	return fmt.Sprintf(`{"choices":[{"index":0,"delta":{"content":%q}}]}`, text)
}

func collect(t *testing.T, b *Backend, req *switchboard.ChatRequest) (*switchboard.Result, []string) {
	t.Helper()
	var got []string
	res, err := b.Chat(context.Background(), req, func(c switchboard.Chunk) error {
		got = append(got, c.Text)
		return nil
	})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	return res, got
}

// The central claim of this backend: tokens streamed by llama-server reach the
// caller in order, and the assembled result matches what was streamed.
func TestChatStreamsDeltasInOrder(t *testing.T) {
	b, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, sse(
			chunkFrame("Hello"),
			chunkFrame(", "),
			chunkFrame("world"),
			`{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":3}}`,
		))
	})

	res, got := collect(t, b, &switchboard.ChatRequest{
		Model:    "test-model",
		Messages: []switchboard.Message{{Role: switchboard.RoleUser, Content: "hi"}},
	})

	if want := []string{"Hello", ", ", "world"}; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("chunks = %v, want %v", got, want)
	}
	if res.Text != "Hello, world" {
		t.Errorf("text = %q", res.Text)
	}
	if res.StopReason != "stop" {
		t.Errorf("stop reason = %q", res.StopReason)
	}
	if res.Usage.InputTokens != 11 || res.Usage.OutputTokens != 3 {
		t.Errorf("usage = %+v", res.Usage)
	}
}

// What actually goes on the wire — llama-server needs stream and the usage
// option, or the final frame never carries token counts.
func TestChatSendsTheRightRequest(t *testing.T) {
	var got wire.ChatRequest
	var path, accept string
	b, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {
		path, accept = r.URL.Path, r.Header.Get("Accept")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		fmt.Fprint(w, sse(chunkFrame("ok")))
	})

	maxTokens := 128
	collect(t, b, &switchboard.ChatRequest{
		Model:     "test-model",
		Messages:  []switchboard.Message{{Role: switchboard.RoleUser, Content: "hi"}},
		MaxTokens: maxTokens,
		Stop:      []string{"END"},
	})

	if path != "/v1/chat/completions" {
		t.Errorf("path = %q", path)
	}
	if accept != "text/event-stream" {
		t.Errorf("Accept = %q", accept)
	}
	if !got.Stream {
		t.Error("stream must be true; the backend only reads SSE")
	}
	if got.StreamOptions == nil || !got.StreamOptions.IncludeUsage {
		t.Error("include_usage must be set or the final frame carries no token counts")
	}
	if got.Model != "test-model" || got.MaxTokens != maxTokens {
		t.Errorf("request = %+v", got)
	}
	if len(got.Messages) != 1 || got.Messages[0].Content != "hi" {
		t.Errorf("messages = %+v", got.Messages)
	}
}

// A non-200 has to say what happened. "llama-server failed" with no status and
// no body is the error message that wastes an afternoon.
func TestChatReportsServerErrorsWithDetail(t *testing.T) {
	b, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"context window exceeded"}`)
	})
	_, err := b.Chat(context.Background(), &switchboard.ChatRequest{Model: "test-model"}, func(switchboard.Chunk) error { return nil })
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"500", "context window exceeded"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}

func TestUnknownModelIsTyped(t *testing.T) {
	b, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {})
	_, err := b.Chat(context.Background(), &switchboard.ChatRequest{Model: "nope"}, func(switchboard.Chunk) error { return nil })
	var unknown *switchboard.UnknownModelError
	if !errors.As(err, &unknown) {
		t.Fatalf("want UnknownModelError, got %T: %v", err, err)
	}
}

// A malformed frame is an upstream bug. Losing the tokens already streamed
// because of it would be a worse one.
func TestMalformedFrameDoesNotLoseTheStream(t *testing.T) {
	b, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, sse(
			chunkFrame("one"),
			`{"choices":[{"delta":{"content":`, // truncated JSON
			chunkFrame("two"),
		))
	})
	res, got := collect(t, b, &switchboard.ChatRequest{Model: "test-model"})
	if res.Text != "onetwo" {
		t.Errorf("text = %q, want the surviving tokens", res.Text)
	}
	if len(got) != 2 {
		t.Errorf("chunks = %v", got)
	}
}

// Everything after [DONE] is not ours to read.
func TestStopsAtDone(t *testing.T) {
	b, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "data: "+chunkFrame("kept")+"\n\ndata: [DONE]\n\ndata: "+chunkFrame("ignored")+"\n\n")
	})
	res, _ := collect(t, b, &switchboard.ChatRequest{Model: "test-model"})
	if res.Text != "kept" {
		t.Errorf("text = %q, want only what preceded [DONE]", res.Text)
	}
}

// If the caller's emit fails — a client that hung up mid-stream — stop rather
// than generating into a closed pipe.
func TestEmitErrorAborts(t *testing.T) {
	b, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, sse(chunkFrame("a"), chunkFrame("b"), chunkFrame("c")))
	})
	calls := 0
	_, err := b.Chat(context.Background(), &switchboard.ChatRequest{Model: "test-model"},
		func(switchboard.Chunk) error {
			calls++
			return fmt.Errorf("client gone")
		})
	if err == nil {
		t.Fatal("emit failure should surface")
	}
	if calls != 1 {
		t.Errorf("emit called %d times; should stop at the first failure", calls)
	}
}

func TestModelsListsTheRoster(t *testing.T) {
	b, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {})
	models, err := b.Models(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 1 || models[0].Name != "test-model" {
		t.Fatalf("models = %+v", models)
	}
	if !models[0].Live {
		t.Error("an injected live instance should report Live")
	}
	if models[0].Backend != config.BackendLocal {
		t.Errorf("backend = %q", models[0].Backend)
	}
}

func TestNameIsStable(t *testing.T) {
	b, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {})
	if b.Name() != config.BackendLocal {
		t.Errorf("Name() = %q", b.Name())
	}
}

// --- idle reaping --------------------------------------------------------

func liveBackend(t *testing.T, idle time.Duration) (*Backend, *instance) {
	t.Helper()
	spec := config.Line{Name: "test-model", Backend: config.BackendLocal, Path: "/nonexistent.gguf"}
	b := New(Options{IdleTimeout: idle, Logf: func(string, ...any) {}}, []config.Line{spec})
	inst := &instance{
		spec: spec, base: "http://127.0.0.1:1",
		started: time.Now(), lastUsed: time.Now().Add(-time.Hour),
		done: make(chan struct{}),
	}
	// No process to wait on; closing done makes halt return immediately.
	close(inst.done)
	b.live["test-model"] = inst
	return b, inst
}

func isLive(b *Backend, name string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.live[name]
	return ok
}

func TestSweepUnloadsIdleModels(t *testing.T) {
	b, _ := liveBackend(t, time.Minute)
	b.sweepIdle()
	if isLive(b, "test-model") {
		t.Error("a model idle for an hour should have been unloaded")
	}
}

// The property that matters: a long generation can run well past the idle
// timeout without touching the clock, and unloading its weights mid-stream
// would kill the request.
func TestSweepSparesModelsWithRequestsInFlight(t *testing.T) {
	b, inst := liveBackend(t, time.Minute)
	b.acquire(inst) // a request begins

	inst.lastUsed = time.Now().Add(-time.Hour) // and runs long
	b.sweepIdle()
	if !isLive(b, "test-model") {
		t.Fatal("a model with a request in flight must not be unloaded")
	}

	b.release(inst) // request finishes
	inst.lastUsed = time.Now().Add(-time.Hour)
	b.sweepIdle()
	if isLive(b, "test-model") {
		t.Error("once the request is done the model should be reapable")
	}
}

func TestSweepLeavesRecentlyUsedModels(t *testing.T) {
	b, inst := liveBackend(t, time.Minute)
	inst.lastUsed = time.Now()
	b.sweepIdle()
	if !isLive(b, "test-model") {
		t.Error("a model used a moment ago should stay loaded")
	}
}

// acquire and release move the clock as well as the counter, so a burst of
// short requests keeps a model alive.
func TestAcquireAndReleaseTouchTheClock(t *testing.T) {
	b, inst := liveBackend(t, time.Minute)
	before := inst.lastUsed

	b.acquire(inst)
	if !inst.lastUsed.After(before) || inst.inflight != 1 {
		t.Fatalf("acquire: inflight=%d lastUsed moved=%v", inst.inflight, inst.lastUsed.After(before))
	}
	mid := inst.lastUsed

	b.release(inst)
	if inst.inflight != 0 || inst.lastUsed.Before(mid) {
		t.Errorf("release: inflight=%d lastUsed=%v", inst.inflight, inst.lastUsed)
	}
}

// --- tool forwarding ---------------------------------------------------
//
// The server refuses tool requests for any backend that does not implement
// server.ToolCaller, so these cover both halves of the contract: that the
// definitions reach llama-server, and that the calls it streams back come out
// assembled.

func TestToolsAreSupported(t *testing.T) {
	b := New(Options{}, nil)
	if !b.ToolsSupported() {
		t.Error("ToolsSupported() = false; the server will refuse tool requests")
	}
}

func TestChatForwardsToolDefinitions(t *testing.T) {
	var got wire.ChatRequest
	b, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		io.WriteString(w, sse(chunkFrame("ok")))
	})

	_, _ = collect(t, b, &switchboard.ChatRequest{
		Model:    "test-model",
		Messages: []switchboard.Message{{Role: switchboard.RoleUser, Content: "weather?"}},
		Tools: []switchboard.Tool{{
			Name:        "get_weather",
			Description: "Get the weather",
			Schema:      json.RawMessage(`{"type":"object"}`),
		}},
	})

	if len(got.Tools) != 1 {
		t.Fatalf("forwarded %d tools, want 1", len(got.Tools))
	}
	if got.Tools[0].Type != "function" {
		t.Errorf("Type = %q, want function", got.Tools[0].Type)
	}
	if got.Tools[0].Function.Name != "get_weather" {
		t.Errorf("Name = %q, want get_weather", got.Tools[0].Function.Name)
	}
	if string(got.Tools[0].Function.Parameters) != `{"type":"object"}` {
		t.Errorf("Parameters = %s; the schema must reach the model unaltered",
			got.Tools[0].Function.Parameters)
	}
}

func TestChatForwardsToolChoice(t *testing.T) {
	cases := []struct {
		name   string
		choice *switchboard.ToolChoice
		want   string
	}{
		{"unset", nil, ""},
		{"auto", &switchboard.ToolChoice{Mode: switchboard.ToolChoiceAuto}, `"auto"`},
		{"none", &switchboard.ToolChoice{Mode: switchboard.ToolChoiceNone}, `"none"`},
		// Neutral "any" is OpenAI's "required".
		{"any", &switchboard.ToolChoice{Mode: switchboard.ToolChoiceAny}, `"required"`},
		{"named", &switchboard.ToolChoice{Mode: switchboard.ToolChoiceTool, Name: "f"},
			`{"function":{"name":"f"},"type":"function"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got wire.ChatRequest
			b, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {
				json.NewDecoder(r.Body).Decode(&got)
				io.WriteString(w, sse(chunkFrame("ok")))
			})
			_, _ = collect(t, b, &switchboard.ChatRequest{
				Model:      "test-model",
				Messages:   []switchboard.Message{{Role: switchboard.RoleUser, Content: "hi"}},
				ToolChoice: tc.choice,
			})
			if string(got.ToolChoice) != tc.want {
				t.Errorf("tool_choice = %s, want %s", got.ToolChoice, tc.want)
			}
		})
	}
}

// A tool result is a RoleTool turn naming the call it answers; llama-server
// cannot match it to the assistant turn without both halves.
func TestChatForwardsToolResults(t *testing.T) {
	var got wire.ChatRequest
	b, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		io.WriteString(w, sse(chunkFrame("done")))
	})

	_, _ = collect(t, b, &switchboard.ChatRequest{
		Model: "test-model",
		Messages: []switchboard.Message{
			{Role: switchboard.RoleUser, Content: "weather?"},
			{Role: switchboard.RoleAssistant, ToolCalls: []switchboard.ToolCall{
				{ID: "call_1", Name: "get_weather", Arguments: `{"city":"Boston"}`},
			}},
			{Role: switchboard.RoleTool, ToolCallID: "call_1", Content: "18C"},
		},
	})

	if n := len(got.Messages); n != 3 {
		t.Fatalf("forwarded %d messages, want 3", n)
	}
	asst := got.Messages[1]
	if len(asst.ToolCalls) != 1 || asst.ToolCalls[0].ID != "call_1" {
		t.Errorf("assistant tool_calls = %+v, want one call_1", asst.ToolCalls)
	}
	if asst.ToolCalls[0].Function.Arguments != `{"city":"Boston"}` {
		t.Errorf("arguments = %q, want the string the model produced",
			asst.ToolCalls[0].Function.Arguments)
	}
	if got.Messages[2].ToolCallID != "call_1" {
		t.Errorf("tool_call_id = %q, want call_1", got.Messages[2].ToolCallID)
	}
}

// The shape llama-server actually streams: the opening frame carries id, type
// and name, and every frame after it adds another fragment of the arguments.
func TestChatAssemblesStreamedToolCalls(t *testing.T) {
	frames := []string{
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\""}}]}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"city\":\"Boston\"}"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
	}
	b, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, sse(frames...))
	})

	var deltas []switchboard.ToolCallDelta
	res, err := b.Chat(context.Background(), &switchboard.ChatRequest{
		Model:    "test-model",
		Messages: []switchboard.Message{{Role: switchboard.RoleUser, Content: "weather?"}},
	}, func(c switchboard.Chunk) error {
		if c.ToolCall != nil {
			deltas = append(deltas, *c.ToolCall)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}

	if len(deltas) != 2 {
		t.Fatalf("emitted %d tool deltas, want 2", len(deltas))
	}
	if deltas[0].ID != "call_1" || deltas[0].Name != "get_weather" {
		t.Errorf("first delta = %+v, want it to open the call", deltas[0])
	}
	if deltas[1].ID != "" || deltas[1].Name != "" {
		t.Errorf("later delta repeats id/name: %+v", deltas[1])
	}

	if len(res.ToolCalls) != 1 {
		t.Fatalf("assembled %d calls, want 1", len(res.ToolCalls))
	}
	call := res.ToolCalls[0]
	if call.ID != "call_1" || call.Name != "get_weather" {
		t.Errorf("call = %+v", call)
	}
	if call.Arguments != `{"city":"Boston"}` {
		t.Errorf("Arguments = %q, want the fragments joined in order", call.Arguments)
	}
	if res.StopReason != "tool_calls" {
		t.Errorf("StopReason = %q, want tool_calls", res.StopReason)
	}
}

// A server streaming a single call may omit index entirely; dropping those
// deltas would lose the call silently.
func TestChatToleratesMissingToolCallIndex(t *testing.T) {
	frames := []string{
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"id":"c1","function":{"name":"f","arguments":"{}"}}]}}]}`,
	}
	b, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, sse(frames...))
	})
	res, _ := collect(t, b, &switchboard.ChatRequest{
		Model:    "test-model",
		Messages: []switchboard.Message{{Role: switchboard.RoleUser, Content: "hi"}},
	})
	if len(res.ToolCalls) != 1 || res.ToolCalls[0].ID != "c1" {
		t.Fatalf("ToolCalls = %+v, want one call at the implied index 0", res.ToolCalls)
	}
}
