// Package golem defines the core types every backend speaks.
//
// The vocabulary is deliberate: weights sitting on disk are clay, a shem is the
// written word that animates one of them, and a backend is what does the
// animating — whether that is llama.cpp on this laptop or Bedrock in us-east-1.
package golem

import (
	"context"
	"errors"
	"fmt"
)

// Role identifies who produced a message.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	// RoleTool carries the result of a call the model asked for. The turn
	// names the call it answers in ToolCallID.
	RoleTool Role = "tool"
)

// Message is one turn of a conversation.
//
// ToolCalls and ToolCallID are the two halves of a tool exchange: an assistant
// turn asks, and a RoleTool turn answers in Content, naming the call it
// answers. They sit beside Content rather than inside a content-block union
// because that is the shape both ends of golem already speak.
type Message struct {
	Role       Role       `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// ChatRequest is a backend-neutral completion request. Zero values mean "let
// the backend decide"; backends must not invent defaults for unset fields.
type ChatRequest struct {
	Model       string
	Messages    []Message
	MaxTokens   int
	Temperature *float64
	TopP        *float64
	Stop        []string
	// Tools are the functions the model may call. A backend that cannot
	// forward them must not silently ignore them; see server.ToolCaller.
	Tools []Tool
	// ToolChoice constrains tool use. Nil means auto when Tools is non-empty.
	ToolChoice *ToolChoice
}

// System splits any leading system messages out of the conversation, since
// most APIs model them as a separate field rather than a turn.
func (r *ChatRequest) System() (string, []Message) {
	var system string
	rest := make([]Message, 0, len(r.Messages))
	for _, m := range r.Messages {
		if m.Role == RoleSystem && len(rest) == 0 {
			if system != "" {
				system += "\n\n"
			}
			system += m.Content
			continue
		}
		rest = append(rest, m)
	}
	return system, rest
}

// Chunk is one increment of a streaming response: either a piece of assistant
// text or a piece of a tool call, never both.
type Chunk struct {
	Text     string
	ToolCall *ToolCallDelta
}

// Usage reports token accounting when a backend provides it.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// Result is the completed response, returned alongside the streamed chunks.
// A backend that emitted tool-call deltas must also report them assembled
// here, so the non-streaming path and the finish reason do not have to
// reconstruct them.
type Result struct {
	Text       string
	StopReason string
	Usage      Usage
	ToolCalls  []ToolCall
}

// Model is one routable model as this process sees it.
type Model struct {
	Name    string `json:"name"`
	Backend string `json:"backend"`
	Detail  string `json:"detail,omitempty"`
	Live    bool   `json:"live"`
}

// Backend is the one interface a new compute target has to satisfy. Adding
// SageMaker, MLX, or a raw cgo llama.cpp binding means implementing this and
// nothing else.
type Backend interface {
	// Name is the stable identifier used in config, e.g. "local".
	Name() string

	// Models lists what this backend can route to.
	Models(ctx context.Context) ([]Model, error)

	// Chat streams a completion. emit is called for each chunk in order; if it
	// returns an error, Chat abandons the stream and returns that error.
	Chat(ctx context.Context, req *ChatRequest, emit func(Chunk) error) (*Result, error)

	// Close releases anything the backend is holding: child processes,
	// connections, loaded weights.
	Close() error
}

// ErrUnknownModel is returned when nothing in the registry answers to a name.
var ErrUnknownModel = errors.New("unknown model")

// UnknownModelError names the model that could not be resolved.
type UnknownModelError struct{ Model string }

func (e *UnknownModelError) Error() string {
	return fmt.Sprintf("unknown model %q", e.Model)
}

func (e *UnknownModelError) Unwrap() error { return ErrUnknownModel }
