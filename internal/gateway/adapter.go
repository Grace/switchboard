package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type Chat struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Stream      bool      `json:"stream"`
	MaxTokens   int       `json:"max_tokens"`
	Temperature *float64  `json:"temperature,omitempty"`
}

func ParseChat(b []byte) (Chat, error) {
	var c Chat
	if e := strictJSON(b, &c); e != nil {
		return c, errors.New("only model, messages, stream, max_tokens, temperature are supported; tools and multimodal content are not supported")
	}
	if c.Model != "preferred" || len(c.Messages) < 1 || len(c.Messages) > 128 {
		return c, errors.New("model must be preferred; 1-128 messages required")
	}
	if c.MaxTokens == 0 {
		c.MaxTokens = 1024
	}
	if c.MaxTokens < 1 || c.MaxTokens > 16384 || (c.Temperature != nil && (*c.Temperature < 0 || *c.Temperature > 1)) {
		return c, errors.New("invalid generation limits")
	}
	for i, m := range c.Messages {
		if m.Content == "" || (m.Role != "user" && m.Role != "assistant" && m.Role != "system") || (m.Role == "system" && i != 0) {
			return c, errors.New("text messages only; system allowed only first")
		}
	}
	if c.Messages[len(c.Messages)-1].Role != "user" {
		return c, errors.New("last message must be user")
	}
	return c, nil
}
func upstream(ctx context.Context, c Chat, r Route, p ProviderConfig, signer *BedrockSigner) (*http.Request, error) {
	var body any
	path := ""
	system := ""
	msgs := []Message{}
	for _, m := range c.Messages {
		if m.Role == "system" {
			system = m.Content
		} else {
			msgs = append(msgs, m)
		}
	}
	switch r.Provider {
	case "openai":
		c.Model = r.Model
		body = c
		path = "/v1/chat/completions"
	case "anthropic":
		b := map[string]any{"model": r.Model, "messages": msgs, "max_tokens": c.MaxTokens, "stream": c.Stream}
		if system != "" {
			b["system"] = system
		}
		if c.Temperature != nil {
			b["temperature"] = *c.Temperature
		}
		body = b
		path = "/v1/messages"
	case "gemini":
		contents := []any{}
		for _, m := range msgs {
			role := m.Role
			if role == "assistant" {
				role = "model"
			}
			contents = append(contents, map[string]any{"role": role, "parts": []any{map[string]any{"text": m.Content}}})
		}
		gen := map[string]any{"maxOutputTokens": c.MaxTokens, "candidateCount": 1}
		if c.Temperature != nil {
			gen["temperature"] = *c.Temperature
		}
		b := map[string]any{"contents": contents, "generationConfig": gen}
		if system != "" {
			b["systemInstruction"] = map[string]any{"parts": []any{map[string]any{"text": system}}}
		}
		body = b
		path = "/v1beta/models/" + r.Model + ":generateContent"
		if c.Stream {
			path = "/v1beta/models/" + r.Model + ":streamGenerateContent?alt=sse"
		}
	case "bedrock":
		// Streaming is AWS event-stream framing rather than SSE and the
		// incremental decode path is not built yet. Refusing here is honest:
		// the alternative is accepting the request and mishandling the frames.
		if c.Stream {
			return nil, errStreamUnsupported
		}
		body = bedrockBody(c, system, msgs)
		path = "/model/" + url.PathEscape(r.Model) + "/converse"
	default:
		return nil, errors.New("unknown adapter")
	}
	raw := jsonBytes(body)
	req, e := http.NewRequestWithContext(ctx, "POST", trimURL(p.URL)+path, bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	switch r.Provider {
	case "openai":
		req.Header.Set("Authorization", "Bearer "+os.Getenv(p.KeyEnv))
	case "anthropic":
		req.Header.Set("x-api-key", os.Getenv(p.KeyEnv))
		req.Header.Set("anthropic-version", "2023-06-01")
	case "gemini":
		req.Header.Set("x-goog-api-key", os.Getenv(p.KeyEnv))
	case "bedrock":
		// No key: the task's IAM role authenticates, so nothing long-lived is
		// stored or pasted by a customer.
		if signer == nil {
			return nil, errors.New("bedrock configured but no signer available")
		}
		if e := signer.sign(ctx, req, raw); e != nil {
			return nil, e
		}
	}
	return req, nil
}

type normalized struct {
	Text          string
	Finish        string
	Input, Output int
}

func finish(s string) (string, error) {
	switch s {
	case "stop", "end_turn", "stop_sequence", "STOP":
		return "stop", nil
	case "length", "max_tokens", "MAX_TOKENS":
		return "length", nil
	case "content_filter", "SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII":
		return "content_filter", nil
	}
	return "", errors.New("unsupported finish reason")
}

type wire struct {
	Type    string          `json:"type"`
	Error   json.RawMessage `json:"error"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Content   *string         `json:"content"`
			ToolCalls json.RawMessage `json:"tool_calls"`
			Refusal   *string         `json:"refusal"`
		} `json:"message"`
		Delta struct {
			Content   *string         `json:"content"`
			ToolCalls json.RawMessage `json:"tool_calls"`
			Refusal   *string         `json:"refusal"`
		} `json:"delta"`
		Finish *string `json:"finish_reason"`
	} `json:"choices"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Delta      struct {
		Type string `json:"type"`
		Text string `json:"text"`
		Stop string `json:"stop_reason"`
	} `json:"delta"`
	ContentBlock struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content_block"`
	Usage struct {
		Input      int `json:"input_tokens"`
		Output     int `json:"output_tokens"`
		Prompt     int `json:"prompt_tokens"`
		Completion int `json:"completion_tokens"`
	} `json:"usage"`
	Candidates []struct {
		Index   int `json:"index"`
		Content struct {
			Parts []struct {
				Text     string          `json:"text"`
				Thought  bool            `json:"thought"`
				Function json.RawMessage `json:"functionCall"`
				Inline   json.RawMessage `json:"inlineData"`
			} `json:"parts"`
		} `json:"content"`
		Finish string `json:"finishReason"`
	} `json:"candidates"`
	PromptFeedback struct {
		Block string `json:"blockReason"`
	} `json:"promptFeedback"`
	UsageMetadata struct {
		Input  int `json:"promptTokenCount"`
		Output int `json:"candidatesTokenCount"`
	} `json:"usageMetadata"`
}

func normalize(provider string, b []byte, stream bool) (normalized, bool, error) {
	if provider == "bedrock" {
		// Only the complete-response shape reaches here: the streaming path is
		// refused in upstream() until event-stream decoding is wired.
		n, e := normalizeBedrock(b)
		return n, true, e
	}
	var w wire
	var n normalized
	if json.Unmarshal(b, &w) != nil {
		return n, false, errors.New("invalid provider JSON")
	}
	if len(w.Error) > 0 && string(w.Error) != "null" {
		return n, false, errors.New("provider stream error")
	}
	done := false
	switch provider {
	case "openai":
		n.Input = w.Usage.Prompt
		n.Output = w.Usage.Completion
		if len(w.Choices) > 1 {
			return n, false, errors.New("multiple choices unsupported")
		}
		for _, c := range w.Choices {
			if c.Index != 0 {
				return n, false, errors.New("invalid choice")
			}
			text := c.Message.Content
			tools := c.Message.ToolCalls
			refusal := c.Message.Refusal
			if stream {
				text = c.Delta.Content
				tools = c.Delta.ToolCalls
				refusal = c.Delta.Refusal
			}
			if len(tools) > 0 && string(tools) != "null" && string(tools) != "[]" {
				return n, false, errors.New("unexpected tool call")
			}
			if text != nil {
				n.Text = *text
			}
			if refusal != nil {
				n.Text += *refusal
			}
			if c.Finish != nil {
				f, e := finish(*c.Finish)
				if e != nil {
					return n, false, e
				}
				n.Finish = f
				done = true
			}
		}
	case "anthropic":
		n.Input = w.Usage.Input
		n.Output = w.Usage.Output
		if stream {
			switch w.Type {
			case "content_block_start":
				if w.ContentBlock.Type != "text" {
					return n, false, errors.New("unsupported content block")
				}
				n.Text = w.ContentBlock.Text
			case "content_block_delta":
				if w.Delta.Type != "text_delta" {
					return n, false, errors.New("unsupported content delta")
				}
				n.Text = w.Delta.Text
			case "message_delta":
				if w.Delta.Stop != "" {
					f, e := finish(w.Delta.Stop)
					if e != nil {
						return n, false, e
					}
					n.Finish = f
				}
			case "message_stop":
				done = true
			case "message_start", "content_block_stop", "ping":
			default:
				return n, false, errors.New("unknown stream event")
			}
		} else {
			for _, c := range w.Content {
				if c.Type != "text" {
					return n, false, errors.New("unsupported content block")
				}
				n.Text += c.Text
			}
			f, e := finish(w.StopReason)
			if e != nil {
				return n, false, e
			}
			n.Finish = f
			done = true
		}
	case "gemini":
		n.Input = w.UsageMetadata.Input
		n.Output = w.UsageMetadata.Output
		if w.PromptFeedback.Block != "" {
			n.Finish = "content_filter"
			return n, true, nil
		}
		if len(w.Candidates) > 1 {
			return n, false, errors.New("multiple candidates unsupported")
		}
		for _, c := range w.Candidates {
			if c.Index != 0 {
				return n, false, errors.New("invalid candidate")
			}
			for _, p := range c.Content.Parts {
				if len(p.Function) > 0 || len(p.Inline) > 0 {
					return n, false, errors.New("unsupported Gemini content")
				}
				if !p.Thought {
					n.Text += p.Text
				}
			}
			if c.Finish != "" {
				f, e := finish(c.Finish)
				if e != nil {
					return n, false, e
				}
				n.Finish = f
				done = true
			}
		}
	}
	if !stream && !done {
		return n, false, errors.New("incomplete provider response")
	}
	return n, done, nil
}
func completion(id string, r Route, n normalized, created int64) any {
	return map[string]any{"id": "chatcmpl-" + id, "object": "chat.completion", "created": created, "model": r.Model, "choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": n.Text}, "finish_reason": n.Finish}}, "usage": map[string]int{"prompt_tokens": n.Input, "completion_tokens": n.Output, "total_tokens": n.Input + n.Output}}
}
func chunk(id string, r Route, n normalized, created int64) any {
	delta := map[string]any{}
	if n.Text != "" {
		delta["content"] = n.Text
	}
	var f any
	if n.Finish != "" {
		f = n.Finish
	}
	return map[string]any{"id": "chatcmpl-" + id, "object": "chat.completion.chunk", "created": created, "model": r.Model, "choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": f}}}
}

// SSE event assembly supports CRLF, comments and multi-line data. Bound both lines
// and assembled events so a malicious upstream cannot grow memory without limit.
func readSSE(r io.Reader, fn func([]byte) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var data []byte
	dispatch := func() error {
		if len(data) == 0 {
			return nil
		}
		e := fn(bytes.TrimSuffix(data, []byte("\n")))
		data = nil
		return e
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if e := dispatch(); e != nil {
				return e
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			v := strings.TrimPrefix(line, "data:")
			v = strings.TrimPrefix(v, " ")
			data = append(data, v...)
			data = append(data, '\n')
			if len(data) > 1<<20 {
				return errors.New("oversized SSE event")
			}
		}
	}
	if e := scanner.Err(); e != nil {
		return e
	}
	return dispatch()
}

var streamComplete = errors.New("complete")

func writeSSE(w http.ResponseWriter, v any) error {
	_, e := fmt.Fprintf(w, "data: %s\n\n", jsonBytes(v))
	if e == nil {
		e = http.NewResponseController(w).Flush()
	}
	return e
}
