// Package switchboard defines the core types every backend speaks.
//
// The vocabulary is deliberate: a line is one routable model as configured, a
// backend is what actually serves it — llama.cpp on this laptop or Bedrock in
// us-east-1 — and the registry is what connects a caller to the right one.
package switchboard

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
// because that is the shape both ends of switchboard already speak.
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
	// CacheWriteTokens and CacheReadTokens are the parts of the input that were
	// written to, or served from, a provider-side prompt cache.
	//
	// They are counted separately because they are billed separately — a cache
	// read is a fraction of the base input rate and a cache write is a premium
	// on it. A gateway that folded them into InputTokens would produce a cost
	// figure wrong by an order of magnitude for anyone with a large stable
	// system prompt, and would produce it silently.
	//
	// They are disjoint from InputTokens, matching how providers report them:
	// a request whose prompt was entirely a cache hit reports almost no input
	// tokens and a large cache read. Adding all three is the total consumed.
	CacheWriteTokens int `json:"cache_write_tokens,omitempty"`
	CacheReadTokens  int `json:"cache_read_tokens,omitempty"`
}

// PromptTokens is everything that went in, however it was billed.
func (u Usage) PromptTokens() int {
	return u.InputTokens + u.CacheWriteTokens + u.CacheReadTokens
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

	// ModelID is the provider-side identifier this gateway sent, as distinct
	// from the name the caller asked for. Recording it makes the routing
	// decision visible in the log itself rather than only in whatever
	// configuration happened to be on disk at the time.
	ModelID string
	// ProviderModel is the identifier the provider reported as having served
	// the request, where it reports one at all.
	//
	// These are two different claims and are kept apart deliberately. ModelID
	// is what we did; ProviderModel is what the other side says it did. An
	// alias resolving to a dated snapshot, or a provider updating a pinned
	// name server-side, changes the second and leaves the first untouched —
	// and that is the only shape of change a comparison of requested names is
	// blind to by construction. Collapsing the two would report an attestation
	// as an observation.
	ProviderModel string
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
