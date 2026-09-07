package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStreams(t *testing.T) {
	cases := map[string]string{
		"openai":    "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"},\"finish_reason\":null}]}\r\n\r\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n",
		"anthropic": "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\ndata: {\"type\":\"message_stop\"}\n\n",
		"gemini":    "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hello\"}]}}]}\n\ndata: {\"candidates\":[{\"finishReason\":\"STOP\"}]}\n\n",
	}
	for provider, stream := range cases {
		t.Run(provider, func(t *testing.T) {
			s := testServer(t, nil)
			w := httptest.NewRecorder()
			res := &http.Response{Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(stream))}
			if e := s.stream(w, res, Route{provider, "test"}, "id", 1); e != nil {
				t.Fatal(e)
			}
			if !strings.Contains(w.Body.String(), "hello") || strings.Count(w.Body.String(), "[DONE]") != 1 {
				t.Fatal(w.Body.String())
			}
		})
	}
}
func TestStreamTruncation(t *testing.T) {
	s := testServer(t, nil)
	w := httptest.NewRecorder()
	res := &http.Response{Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n"))}
	if s.stream(w, res, Route{"openai", "test"}, "id", 1) == nil || strings.Contains(w.Body.String(), "[DONE]") || !strings.Contains(w.Body.String(), "stream_error") {
		t.Fatal(w.Body.String())
	}
}
func TestSSEMultilineAndBound(t *testing.T) {
	var value string
	if e := readSSE(strings.NewReader(": ping\n\ndata: {\ndata: \"a\":1}\n\n"), func(b []byte) error { value = string(b); return nil }); e != nil || value != "{\n\"a\":1}" {
		t.Fatal(value, e)
	}
	if readSSE(strings.NewReader("data: "+strings.Repeat("x", 1<<20)+"\n\n"), func([]byte) error { return nil }) == nil {
		t.Fatal("oversized event accepted")
	}
}
func TestUnexpectedTools(t *testing.T) {
	for provider, b := range map[string]string{"openai": `{"choices":[{"message":{"tool_calls":[{}]},"finish_reason":"tool_calls"}]}`, "anthropic": `{"content":[{"type":"tool_use"}],"stop_reason":"tool_use"}`, "gemini": `{"candidates":[{"content":{"parts":[{"functionCall":{}}]},"finishReason":"STOP"}]}`} {
		if _, _, e := normalize(provider, []byte(b), false); e == nil {
			t.Fatal("tool accepted", provider)
		}
	}
}
