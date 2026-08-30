package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grace/golem/internal/golem"
	"github.com/grace/golem/internal/wire"
)

// fakeBackend returns a canned response, split into chunks, and records what
// it was asked for.
type fakeBackend struct {
	chunks     []string
	toolDeltas []golem.ToolCallDelta
	// noTools makes the backend report that it cannot forward tools, without
	// removing the method — the server asks the capability, not the type.
	noTools bool
	err     error
	got     *golem.ChatRequest

	animated map[string]bool
	closed   bool
}

func (f *fakeBackend) Name() string { return "fake" }

func (f *fakeBackend) Models(ctx context.Context) ([]golem.Model, error) {
	return []golem.Model{{Name: "test-model", Backend: "fake", Live: true}}, nil
}

func (f *fakeBackend) ToolsSupported() bool { return !f.noTools }

func (f *fakeBackend) Close() error {
	f.closed = true
	return nil
}

func (f *fakeBackend) Chat(ctx context.Context, req *golem.ChatRequest, emit func(golem.Chunk) error) (*golem.Result, error) {
	f.got = req
	if f.err != nil {
		return nil, f.err
	}
	var text strings.Builder
	for _, c := range f.chunks {
		text.WriteString(c)
		if err := emit(golem.Chunk{Text: c}); err != nil {
			return nil, err
		}
	}

	var acc golem.ToolCallAccumulator
	for _, d := range f.toolDeltas {
		acc.Add(d)
		if err := emit(golem.Chunk{ToolCall: &d}); err != nil {
			return nil, err
		}
	}

	return &golem.Result{
		Text: text.String(),
		// Deliberately a plain stop even when there are tool calls, so that
		// what the tests observe is the server's own correction.
		StopReason: "end_turn",
		Usage:      golem.Usage{InputTokens: 7, OutputTokens: 11},
		ToolCalls:  acc.Calls(),
	}, nil
}

func (f *fakeBackend) Animate(ctx context.Context, model string) error {
	if f.animated == nil {
		f.animated = map[string]bool{}
	}
	f.animated[model] = true
	return nil
}

func (f *fakeBackend) Rest(model string) bool {
	was := f.animated[model]
	delete(f.animated, model)
	return was
}

func newTestServer(t *testing.T, backend golem.Backend) *httptest.Server {
	t.Helper()
	reg := golem.NewRegistry()
	reg.Register(backend, []string{"test-model"})
	reg.SetDefault("test-model")

	s := New(reg, log.New(io.Discard, "", 0))
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestChatCompletion(t *testing.T) {
	backend := &fakeBackend{chunks: []string{"clay ", "and ", "word"}}
	srv := newTestServer(t, backend)

	resp := post(t, srv.URL+"/v1/chat/completions",
		`{"model":"test-model","messages":[{"role":"user","content":"hello"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %s, want 200", resp.Status)
	}

	var got wire.ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Choices) != 1 {
		t.Fatalf("choices = %d, want 1", len(got.Choices))
	}
	if want := "clay and word"; got.Choices[0].Message.Content != want {
		t.Errorf("content = %q, want %q", got.Choices[0].Message.Content, want)
	}
	// end_turn is Bedrock's vocabulary; clients branch on OpenAI's.
	if got.Choices[0].FinishReason == nil || *got.Choices[0].FinishReason != "stop" {
		t.Errorf("finish_reason = %v, want stop", got.Choices[0].FinishReason)
	}
	if got.Usage == nil || got.Usage.TotalTokens != 18 {
		t.Errorf("usage = %+v, want 18 total", got.Usage)
	}
	if backend.got.Messages[0].Content != "hello" {
		t.Errorf("backend saw %+v", backend.got.Messages)
	}
}

func TestChatStreaming(t *testing.T) {
	srv := newTestServer(t, &fakeBackend{chunks: []string{"one", "two"}})

	resp := post(t, srv.URL+"/v1/chat/completions",
		`{"model":"test-model","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type = %q", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(body)
	if !strings.HasSuffix(strings.TrimSpace(raw), "data: [DONE]") {
		t.Errorf("stream does not end with [DONE]:\n%s", raw)
	}

	var text strings.Builder
	var sawRole, sawFinish bool
	for _, line := range strings.Split(raw, "\n") {
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok || payload == "[DONE]" {
			continue
		}
		var frame wire.ChatResponse
		if err := json.Unmarshal([]byte(payload), &frame); err != nil {
			t.Fatalf("bad frame %q: %v", payload, err)
		}
		for _, c := range frame.Choices {
			if c.Delta == nil {
				t.Fatalf("streaming frame without delta: %q", payload)
			}
			if c.Delta.Role != "" {
				sawRole = true
			}
			text.WriteString(c.Delta.Content)
			if c.FinishReason != nil {
				sawFinish = true
			}
		}
	}
	if !sawRole {
		t.Error("no opening frame carrying the assistant role")
	}
	if !sawFinish {
		t.Error("no frame carrying finish_reason")
	}
	if got := text.String(); got != "onetwo" {
		t.Errorf("streamed text = %q, want %q", got, "onetwo")
	}
}

func TestUnknownModel(t *testing.T) {
	srv := newTestServer(t, &fakeBackend{})

	resp := post(t, srv.URL+"/v1/chat/completions",
		`{"model":"nope","messages":[{"role":"user","content":"hi"}]}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %s, want 404", resp.Status)
	}

	var got wire.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.Error.Message, "nope") {
		t.Errorf("error message = %q, want it to name the model", got.Error.Message)
	}
}

func TestEmptyMessages(t *testing.T) {
	srv := newTestServer(t, &fakeBackend{})
	resp := post(t, srv.URL+"/v1/chat/completions", `{"model":"test-model","messages":[]}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %s, want 400", resp.Status)
	}
}

func TestModelsList(t *testing.T) {
	srv := newTestServer(t, &fakeBackend{})

	resp, err := http.Get(srv.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got wire.ModelList
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Data) != 1 || got.Data[0].ID != "test-model" {
		t.Fatalf("models = %+v", got.Data)
	}
	if got.Data[0].OwnedBy != "fake" {
		t.Errorf("owned_by = %q, want the backend name", got.Data[0].OwnedBy)
	}
}

func TestAnimateAndRest(t *testing.T) {
	backend := &fakeBackend{}
	srv := newTestServer(t, backend)

	if resp := post(t, srv.URL+"/v1/animate", `{"model":"test-model"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("animate: status = %s", resp.Status)
	}
	if !backend.animated["test-model"] {
		t.Error("animate did not reach the backend")
	}

	resp := post(t, srv.URL+"/v1/rest", `{"model":"test-model"}`)
	var state struct{ State string }
	json.NewDecoder(resp.Body).Decode(&state)
	if state.State != "resting" {
		t.Errorf("state = %q, want resting", state.State)
	}
	if backend.animated["test-model"] {
		t.Error("rest did not unload the model")
	}
}

// weatherTool is the tools array most of the tool tests send.
const weatherTool = `"tools":[{"type":"function","function":{` +
	`"name":"get_weather","description":"look up the weather",` +
	`"parameters":{"type":"object","properties":{"city":{"type":"string"}}}}}]`

func TestChatToolCalls(t *testing.T) {
	backend := &fakeBackend{toolDeltas: []golem.ToolCallDelta{
		{Index: 0, ID: "call_1", Name: "get_weather"},
		{Index: 0, Arguments: `{"city":`},
		{Index: 0, Arguments: `"Berlin"}`},
	}}
	srv := newTestServer(t, backend)

	resp := post(t, srv.URL+"/v1/chat/completions",
		`{"model":"test-model","messages":[{"role":"user","content":"weather?"}],`+weatherTool+`}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %s, want 200", resp.Status)
	}

	var got wire.ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	calls := got.Choices[0].Message.ToolCalls
	if len(calls) != 1 {
		t.Fatalf("tool_calls = %+v, want 1", calls)
	}
	if calls[0].ID != "call_1" || calls[0].Function.Name != "get_weather" {
		t.Errorf("call = %+v", calls[0])
	}
	if want := `{"city":"Berlin"}`; calls[0].Function.Arguments != want {
		t.Errorf("arguments = %q, want %q", calls[0].Function.Arguments, want)
	}
	if calls[0].Index != nil {
		t.Error("a complete response should not carry a delta index")
	}
	// The backend reported end_turn; the tool calls have to win.
	if got.Choices[0].FinishReason == nil || *got.Choices[0].FinishReason != "tool_calls" {
		t.Errorf("finish_reason = %v, want tool_calls", got.Choices[0].FinishReason)
	}

	if len(backend.got.Tools) != 1 || backend.got.Tools[0].Name != "get_weather" {
		t.Fatalf("backend saw tools %+v", backend.got.Tools)
	}
	if !strings.Contains(string(backend.got.Tools[0].Schema), `"city"`) {
		t.Errorf("schema did not survive the trip: %s", backend.got.Tools[0].Schema)
	}
}

func TestChatToolCallsStreaming(t *testing.T) {
	srv := newTestServer(t, &fakeBackend{toolDeltas: []golem.ToolCallDelta{
		{Index: 0, ID: "call_a", Name: "get_weather"},
		{Index: 0, Arguments: `{"city":"Oslo"}`},
		{Index: 1, ID: "call_b", Name: "get_time"},
		{Index: 1, Arguments: `{"tz":"CET"}`},
	}})

	resp := post(t, srv.URL+"/v1/chat/completions",
		`{"model":"test-model","stream":true,"messages":[{"role":"user","content":"hi"}],`+weatherTool+`}`)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	// Reassemble the way a client would: index correlates the fragments.
	var acc golem.ToolCallAccumulator
	var finish string
	for _, line := range strings.Split(string(body), "\n") {
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok || payload == "[DONE]" {
			continue
		}
		var frame wire.ChatResponse
		if err := json.Unmarshal([]byte(payload), &frame); err != nil {
			t.Fatalf("bad frame %q: %v", payload, err)
		}
		for _, c := range frame.Choices {
			if c.FinishReason != nil {
				finish = *c.FinishReason
			}
			for _, tc := range c.Delta.ToolCalls {
				if tc.Index == nil {
					t.Fatalf("streamed tool call without an index: %q", payload)
				}
				acc.Add(golem.ToolCallDelta{
					Index:     *tc.Index,
					ID:        tc.ID,
					Name:      tc.Function.Name,
					Arguments: tc.Function.Arguments,
				})
			}
		}
	}

	calls := acc.Calls()
	if len(calls) != 2 {
		t.Fatalf("reassembled %d calls, want 2: %+v", len(calls), calls)
	}
	if calls[0].ID != "call_a" || calls[0].Arguments != `{"city":"Oslo"}` {
		t.Errorf("first call = %+v", calls[0])
	}
	if calls[1].Name != "get_time" || calls[1].Arguments != `{"tz":"CET"}` {
		t.Errorf("second call = %+v", calls[1])
	}
	if finish != "tool_calls" {
		t.Errorf("finish_reason = %q, want tool_calls", finish)
	}
}

func TestToolsRejectedByBackendThatCannotForwardThem(t *testing.T) {
	srv := newTestServer(t, &fakeBackend{noTools: true})

	resp := post(t, srv.URL+"/v1/chat/completions",
		`{"model":"test-model","messages":[{"role":"user","content":"hi"}],`+weatherTool+`}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %s, want 400 — silently dropping tools is the bug", resp.Status)
	}

	var got wire.ErrorResponse
	json.NewDecoder(resp.Body).Decode(&got)
	if !strings.Contains(got.Error.Message, "tool") {
		t.Errorf("error message = %q, want it to mention tools", got.Error.Message)
	}
}

func TestToolResultReachesBackend(t *testing.T) {
	backend := &fakeBackend{chunks: []string{"18C"}}
	srv := newTestServer(t, backend)

	resp := post(t, srv.URL+"/v1/chat/completions", `{"model":"test-model","messages":[
		{"role":"user","content":"weather?"},
		{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function",
			"function":{"name":"get_weather","arguments":"{\"city\":\"Berlin\"}"}}]},
		{"role":"tool","tool_call_id":"call_1","content":"18C"}
	]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %s, want 200", resp.Status)
	}

	msgs := backend.got.Messages
	if len(msgs) != 3 {
		t.Fatalf("backend saw %d messages, want 3", len(msgs))
	}
	if len(msgs[1].ToolCalls) != 1 || msgs[1].ToolCalls[0].Name != "get_weather" {
		t.Errorf("assistant turn lost its call: %+v", msgs[1])
	}
	if msgs[1].ToolCalls[0].Arguments != `{"city":"Berlin"}` {
		t.Errorf("arguments = %q", msgs[1].ToolCalls[0].Arguments)
	}
	if msgs[2].Role != golem.RoleTool || msgs[2].ToolCallID != "call_1" {
		t.Errorf("tool turn = %+v, want role tool answering call_1", msgs[2])
	}
}

func TestToolValidation(t *testing.T) {
	srv := newTestServer(t, &fakeBackend{})
	cases := map[string]string{
		"missing name": `"tools":[{"type":"function","function":{"description":"nameless"}}]`,
		"wrong type":   `"tools":[{"type":"retrieval","function":{"name":"x"}}]`,
		"bad choice":   weatherTool + `,"tool_choice":"sometimes"`,
		"unnamed tool": weatherTool + `,"tool_choice":{"type":"function","function":{}}`,
	}
	for name, fragment := range cases {
		t.Run(name, func(t *testing.T) {
			resp := post(t, srv.URL+"/v1/chat/completions",
				`{"model":"test-model","messages":[{"role":"user","content":"hi"}],`+fragment+`}`)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %s, want 400", resp.Status)
			}
		})
	}
}

func TestParseToolChoice(t *testing.T) {
	cases := map[string]golem.ToolChoice{
		`"auto"`:     {Mode: golem.ToolChoiceAuto},
		`"none"`:     {Mode: golem.ToolChoiceNone},
		`"required"`: {Mode: golem.ToolChoiceAny},
		`{"type":"function","function":{"name":"get_weather"}}`: {
			Mode: golem.ToolChoiceTool, Name: "get_weather",
		},
	}
	for in, want := range cases {
		got, err := parseToolChoice([]byte(in))
		if err != nil {
			t.Errorf("parseToolChoice(%s): %v", in, err)
			continue
		}
		if *got != want {
			t.Errorf("parseToolChoice(%s) = %+v, want %+v", in, *got, want)
		}
	}
}

func TestFinishReason(t *testing.T) {
	cases := map[string]string{
		"":              "stop",
		"end_turn":      "stop",
		"max_tokens":    "length",
		"length":        "length",
		"tool_use":      "tool_calls",
		"guardrail":     "guardrail",
		"STOP_SEQUENCE": "stop",
	}
	for in, want := range cases {
		if got := finishReason(in); got != want {
			t.Errorf("finishReason(%q) = %q, want %q", in, got, want)
		}
	}
}
