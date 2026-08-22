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
	chunks []string
	err    error
	got    *golem.ChatRequest

	animated map[string]bool
}

func (f *fakeBackend) Name() string { return "fake" }

func (f *fakeBackend) Models(ctx context.Context) ([]golem.Model, error) {
	return []golem.Model{{Name: "test-model", Backend: "fake", Live: true}}, nil
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
	return &golem.Result{
		Text:       text.String(),
		StopReason: "end_turn",
		Usage:      golem.Usage{InputTokens: 7, OutputTokens: 11},
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

func TestFinishReason(t *testing.T) {
	cases := map[string]string{
		"":            "stop",
		"end_turn":    "stop",
		"max_tokens":  "length",
		"length":      "length",
		"tool_use":    "tool_calls",
		"guardrail":   "guardrail",
		"STOP_SEQUENCE": "stop",
	}
	for in, want := range cases {
		if got := finishReason(in); got != want {
			t.Errorf("finishReason(%q) = %q, want %q", in, got, want)
		}
	}
}
