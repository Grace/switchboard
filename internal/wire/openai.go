// Package wire holds the OpenAI-compatible JSON shapes.
//
// They appear on both sides of switchboard: the server speaks this dialect so that
// existing clients (Zed, Continue, the openai SDKs, curl) work unmodified, and
// the local backend speaks it upstream to llama-server.
package wire

import "encoding/json"

// Message is one chat turn on the wire.
//
// Content stays a plain string: OpenAI allows null there for a turn that is
// only a tool call, and null decodes into the zero value without complaint.
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// Tool is one entry of the request's tools array.
type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

// ToolFunction is a tool definition — what the model is told it may call.
type ToolFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// ToolCall is one entry of an assistant message's tool_calls array.
//
// Index is set on streaming deltas and absent on a complete response, which is
// why it is a pointer: index 0 is meaningful and must still be written.
type ToolCall struct {
	Index    *int             `json:"index,omitempty"`
	ID       string           `json:"id,omitempty"`
	Type     string           `json:"type,omitempty"`
	Function ToolCallFunction `json:"function"`
}

// ToolCallFunction is the name and arguments of an actual call. Arguments is
// a JSON string, and arrives in fragments when streaming.
type ToolCallFunction struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

// StreamOptions mirrors OpenAI's stream_options.
type StreamOptions struct {
	IncludeUsage bool `json:"include_usage,omitempty"`
}

// ChatRequest is POST /v1/chat/completions.
type ChatRequest struct {
	Model         string         `json:"model"`
	Messages      []Message      `json:"messages"`
	MaxTokens     int            `json:"max_tokens,omitempty"`
	Temperature   *float64       `json:"temperature,omitempty"`
	TopP          *float64       `json:"top_p,omitempty"`
	Stop          []string       `json:"stop,omitempty"`
	Stream        bool           `json:"stream,omitempty"`
	StreamOptions *StreamOptions `json:"stream_options,omitempty"`
	Tools         []Tool         `json:"tools,omitempty"`
	// ToolChoice is polymorphic — a bare string or a function object — so it
	// stays raw here and is decoded where it can be reported to the caller.
	ToolChoice json.RawMessage `json:"tool_choice,omitempty"`
}

// Usage is token accounting in OpenAI's naming.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Choice carries Message for a complete response and Delta for a stream.
type Choice struct {
	Index        int      `json:"index"`
	Message      *Message `json:"message,omitempty"`
	Delta        *Message `json:"delta,omitempty"`
	FinishReason *string  `json:"finish_reason"`
}

// ChatResponse is both the non-streaming body and, with Delta choices, one SSE
// frame of a streaming one.
type ChatResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   *Usage   `json:"usage,omitempty"`
}

// Model is one entry of GET /v1/models.
type Model struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

// ModelList is the body of GET /v1/models.
type ModelList struct {
	Object string  `json:"object"`
	Data   []Model `json:"data"`
}

// Error is the nested error object.
type Error struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code,omitempty"`
}

// ErrorResponse is what switchboard returns on any non-2xx.
type ErrorResponse struct {
	Error Error `json:"error"`
}
