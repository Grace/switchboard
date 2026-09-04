package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/config"
	"github.com/Grace/switchboard/internal/oidc"
	"github.com/Grace/switchboard/internal/redact"
	"github.com/Grace/switchboard/internal/switchboard"
	"github.com/Grace/switchboard/internal/wire"
)

// fakeBackend returns a canned response, split into chunks, and records what
// it was asked for.
type fakeBackend struct {
	chunks     []string
	toolDeltas []switchboard.ToolCallDelta
	// noTools makes the backend report that it cannot forward tools, without
	// removing the method — the server asks the capability, not the type.
	noTools bool
	err     error
	got     *switchboard.ChatRequest
	// onChat observes the request context, so a test can assert on what the
	// server resolved before the backend was reached.
	onChat func(context.Context)

	connected map[string]bool
	closed    bool
}

func (f *fakeBackend) Name() string { return "fake" }

func (f *fakeBackend) Models(ctx context.Context) ([]switchboard.Model, error) {
	return []switchboard.Model{{Name: "test-model", Backend: "fake", Live: true}}, nil
}

func (f *fakeBackend) ToolsSupported() bool { return !f.noTools }

func (f *fakeBackend) Close() error {
	f.closed = true
	return nil
}

func (f *fakeBackend) Chat(ctx context.Context, req *switchboard.ChatRequest, emit func(switchboard.Chunk) error) (*switchboard.Result, error) {
	f.got = req
	if f.onChat != nil {
		f.onChat(ctx)
	}
	if f.err != nil {
		return nil, f.err
	}
	var text strings.Builder
	for _, c := range f.chunks {
		text.WriteString(c)
		if err := emit(switchboard.Chunk{Text: c}); err != nil {
			return nil, err
		}
	}

	var acc switchboard.ToolCallAccumulator
	for _, d := range f.toolDeltas {
		acc.Add(d)
		if err := emit(switchboard.Chunk{ToolCall: &d}); err != nil {
			return nil, err
		}
	}

	return &switchboard.Result{
		Text: text.String(),
		// Deliberately a plain stop even when there are tool calls, so that
		// what the tests observe is the server's own correction.
		StopReason: "end_turn",
		Usage:      switchboard.Usage{InputTokens: 7, OutputTokens: 11},
		ToolCalls:  acc.Calls(),
	}, nil
}

func (f *fakeBackend) Connect(ctx context.Context, model string) error {
	if f.connected == nil {
		f.connected = map[string]bool{}
	}
	f.connected[model] = true
	return nil
}

func (f *fakeBackend) Disconnect(model string) bool {
	was := f.connected[model]
	delete(f.connected, model)
	return was
}

func newTestServer(t *testing.T, backend switchboard.Backend) *httptest.Server {
	t.Helper()
	reg := switchboard.NewRegistry()
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
	backend := &fakeBackend{chunks: []string{"patch ", "me ", "through"}}
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
	if want := "patch me through"; got.Choices[0].Message.Content != want {
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

func TestConnectAndDisconnect(t *testing.T) {
	backend := &fakeBackend{}
	srv := newTestServer(t, backend)

	if resp := post(t, srv.URL+"/v1/connect", `{"model":"test-model"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("connect: status = %s", resp.Status)
	}
	if !backend.connected["test-model"] {
		t.Error("connect did not reach the backend")
	}

	resp := post(t, srv.URL+"/v1/disconnect", `{"model":"test-model"}`)
	var state struct{ State string }
	json.NewDecoder(resp.Body).Decode(&state)
	if state.State != "disconnected" {
		t.Errorf("state = %q, want disconnected", state.State)
	}
	if backend.connected["test-model"] {
		t.Error("disconnect did not unload the model")
	}
}

// weatherTool is the tools array most of the tool tests send.
const weatherTool = `"tools":[{"type":"function","function":{` +
	`"name":"get_weather","description":"look up the weather",` +
	`"parameters":{"type":"object","properties":{"city":{"type":"string"}}}}}]`

func TestChatToolCalls(t *testing.T) {
	backend := &fakeBackend{toolDeltas: []switchboard.ToolCallDelta{
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
	srv := newTestServer(t, &fakeBackend{toolDeltas: []switchboard.ToolCallDelta{
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
	var acc switchboard.ToolCallAccumulator
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
				acc.Add(switchboard.ToolCallDelta{
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
	if msgs[2].Role != switchboard.RoleTool || msgs[2].ToolCallID != "call_1" {
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
	cases := map[string]switchboard.ToolChoice{
		`"auto"`:     {Mode: switchboard.ToolChoiceAuto},
		`"none"`:     {Mode: switchboard.ToolChoiceNone},
		`"required"`: {Mode: switchboard.ToolChoiceAny},
		`{"type":"function","function":{"name":"get_weather"}}`: {
			Mode: switchboard.ToolChoiceTool, Name: "get_weather",
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

// --- attribution ---------------------------------------------------------

func newAttributedServer(t *testing.T, backend switchboard.Backend, require bool) *httptest.Server {
	t.Helper()
	reg := switchboard.NewRegistry()
	reg.Register(backend, []string{"test-model"})
	reg.SetDefault("test-model")

	s := New(reg, log.New(io.Discard, "", 0)).
		WithAttribution([]config.Team{
			{Name: "search", Keys: []string{"key-search-0123456789"}},
			{Name: "billing", Keys: []string{"key-billing-0123456789"}},
		}, require)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func postAs(t *testing.T, url, key, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

const chatBody = `{"messages":[{"role":"user","content":"hi"}]}`

// The whole point: the backend learns who called, because nothing downstream
// of the gateway can work it out afterwards.
func TestCallerReachesTheBackend(t *testing.T) {
	var seen string
	backend := &fakeBackend{onChat: func(ctx context.Context) {
		if c, ok := switchboard.CallerFrom(ctx); ok {
			seen = c.Team
		}
	}}
	srv := newAttributedServer(t, backend, false)

	if resp := postAs(t, srv.URL+"/v1/chat/completions", "key-billing-0123456789", chatBody); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if seen != "billing" {
		t.Errorf("backend saw team %q, want billing", seen)
	}
}

func TestUnattributedIsServedWhenNotRequired(t *testing.T) {
	var attributed bool
	backend := &fakeBackend{onChat: func(ctx context.Context) {
		_, attributed = switchboard.CallerFrom(ctx)
	}}
	srv := newAttributedServer(t, backend, false)

	if resp := postAs(t, srv.URL+"/v1/chat/completions", "", chatBody); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if attributed {
		t.Error("a request with no key must not arrive attributed")
	}
}

// Fail closed: unattributed spend is spend nobody is accountable for.
func TestUnattributedIsRefusedWhenRequired(t *testing.T) {
	srv := newAttributedServer(t, &fakeBackend{}, true)
	for _, key := range []string{"", "not-a-real-key-000000"} {
		resp := postAs(t, srv.URL+"/v1/chat/completions", key, chatBody)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("key %q: status = %d, want 401", key, resp.StatusCode)
		}
	}
}

func TestBearerParsing(t *testing.T) {
	for header, want := range map[string]string{
		"Bearer abc":  "abc",
		"bearer abc":  "abc",
		"Bearer  abc": "abc",
		"":            "",
		"abc":         "",
		"Basic abc":   "",
		"Bearer":      "",
	} {
		got, ok := bearer(header)
		if got != want || ok != (want != "") {
			t.Errorf("bearer(%q) = %q,%v; want %q", header, got, ok, want)
		}
	}
}

// --- audit ---------------------------------------------------------------

// End to end: a request carrying a team and an email address should produce an
// audit record that names the team, counts the redaction, and does not contain
// the address.
func TestAuditRecordsRedactedCompletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	red, err := redact.New([]string{"email"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	lg, err := audit.Open(path, red, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lg.Close() })

	reg := switchboard.NewRegistry()
	reg.Register(&fakeBackend{chunks: []string{"reply to ops@example.com"}}, []string{"test-model"})
	reg.SetDefault("test-model")
	s := New(reg, log.New(io.Discard, "", 0)).
		WithAttribution([]config.Team{{Name: "search", Keys: []string{"key-search-0123456789"}}}, false).
		WithAudit(lg)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)

	body := `{"messages":[{"role":"user","content":"mail grace@example.com"}]}`
	if resp := postAs(t, srv.URL+"/v1/chat/completions", "key-search-0123456789", body); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "grace@example.com") || strings.Contains(string(raw), "ops@example.com") {
		t.Fatalf("raw address reached the audit log: %s", raw)
	}

	var rec audit.Record
	if err := json.Unmarshal(bytes.TrimSpace(raw), &rec); err != nil {
		t.Fatalf("decode %q: %v", raw, err)
	}
	if rec.Team != "search" {
		t.Errorf("team = %q, want search", rec.Team)
	}
	// One in the prompt, one in the completion.
	if rec.Redactions["email"] != 2 {
		t.Errorf("redactions = %v, want 2 emails", rec.Redactions)
	}
	if !strings.Contains(rec.Prompt, "[redacted:email]") {
		t.Errorf("prompt = %q", rec.Prompt)
	}
	if rec.Model != "test-model" {
		t.Errorf("model = %q", rec.Model)
	}
}

// A backend failure is still a record: "nothing was sent" and "we do not know"
// are different answers during an incident review.
func TestAuditRecordsBackendErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	lg, err := audit.Open(path, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	reg := switchboard.NewRegistry()
	reg.Register(&fakeBackend{err: errors.New("upstream exploded")}, []string{"test-model"})
	reg.SetDefault("test-model")
	s := New(reg, log.New(io.Discard, "", 0)).WithAudit(lg)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)

	post(t, srv.URL+"/v1/chat/completions", `{"messages":[{"role":"user","content":"hi"}]}`)
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(path)
	var rec audit.Record
	if err := json.Unmarshal(bytes.TrimSpace(raw), &rec); err != nil {
		t.Fatalf("decode %q: %v", raw, err)
	}
	if !strings.Contains(rec.Error, "upstream exploded") {
		t.Errorf("error not recorded: %+v", rec)
	}
}

func TestNoAuditLogIsFine(t *testing.T) {
	srv := newTestServer(t, &fakeBackend{chunks: []string{"ok"}})
	if resp := post(t, srv.URL+"/v1/chat/completions", `{"messages":[{"role":"user","content":"hi"}]}`); resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d without an audit log", resp.StatusCode)
	}
}

// --- oidc ----------------------------------------------------------------

// End to end through the server: a token from a trusted issuer resolves a
// caller with both a team and a subject, and the subject reaches the audit log.
// That is the point of SSO here — per-user attribution, not just per-team.
func TestOIDCTokenResolvesCallerAndSubject(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	iss := oidcIssuer(t, k, "k1")

	v, err := oidc.New(oidc.Config{
		Issuer: iss.URL, Audience: "switchboard", TeamClaim: "groups", Client: iss.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	var seen switchboard.Caller
	backend := &fakeBackend{onChat: func(ctx context.Context) {
		seen, _ = switchboard.CallerFrom(ctx)
	}}
	reg := switchboard.NewRegistry()
	reg.Register(backend, []string{"test-model"})
	reg.SetDefault("test-model")

	s := New(reg, log.New(io.Discard, "", 0)).
		WithAttribution([]config.Team{{Name: "platform"}}, true).
		WithOIDC(v)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)

	tok := mintToken(t, k, "k1", iss.URL, "platform")
	if resp := postAs(t, srv.URL+"/v1/chat/completions", tok, chatBody); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if seen.Team != "platform" {
		t.Errorf("team = %q", seen.Team)
	}
	if seen.Subject != "user-42" {
		t.Errorf("subject = %q; SSO exists to identify the person", seen.Subject)
	}
}

// The identity provider decides who someone is. It does not decide which teams
// exist here — otherwise any group name it emits becomes a billable team and a
// session tag on the AWS bill.
func TestOIDCTeamMustBeOnTheRoster(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	iss := oidcIssuer(t, k, "k1")
	v, _ := oidc.New(oidc.Config{
		Issuer: iss.URL, Audience: "switchboard", TeamClaim: "groups", Client: iss.Client(),
	})

	reg := switchboard.NewRegistry()
	reg.Register(&fakeBackend{}, []string{"test-model"})
	reg.SetDefault("test-model")
	s := New(reg, log.New(io.Discard, "", 0)).
		WithAttribution([]config.Team{{Name: "platform"}}, true).
		WithOIDC(v)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)

	tok := mintToken(t, k, "k1", iss.URL, "not-a-real-team")
	if resp := postAs(t, srv.URL+"/v1/chat/completions", tok, chatBody); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for a team not on the roster", resp.StatusCode)
	}
}

// A deployment using static keys must not start depending on an identity
// provider being reachable.
func TestStaticKeysStillWorkAlongsideOIDC(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	iss := oidcIssuer(t, k, "k1")
	v, _ := oidc.New(oidc.Config{
		Issuer: iss.URL, Audience: "switchboard", TeamClaim: "groups", Client: iss.Client(),
	})
	iss.Close() // the provider is down

	reg := switchboard.NewRegistry()
	reg.Register(&fakeBackend{}, []string{"test-model"})
	reg.SetDefault("test-model")
	s := New(reg, log.New(io.Discard, "", 0)).
		WithAttribution([]config.Team{{Name: "search", Keys: []string{"key-search-0123456789"}}}, true).
		WithOIDC(v)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)

	if resp := postAs(t, srv.URL+"/v1/chat/completions", "key-search-0123456789", chatBody); resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d; a static key must not need the identity provider", resp.StatusCode)
	}
}
