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
)

// Message is one turn of a conversation.
type Message struct {
	Role    Role   `json:"role"`
	Content string `json:"content"`
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

// Chunk is one increment of a streaming response.
type Chunk struct {
	Text string
}

// Usage reports token accounting when a backend provides it.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// Result is the completed response, returned alongside the streamed chunks.
type Result struct {
	Text       string
	StopReason string
	Usage      Usage
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
