package golem

import "encoding/json"

// Tool is one function a model may call.
//
// Schema is JSON Schema describing the arguments object, passed through
// untouched: every backend wants it in a slightly different container and none
// of them want it interpreted on the way.
type Tool struct {
	Name        string
	Description string
	Schema      json.RawMessage
}

// ToolCall is a model's request to invoke one tool.
//
// Arguments stays a string rather than a decoded map. It is what the model
// actually produced, callers hand it straight back as a tool result, and
// round-tripping it through a decoded form would quietly reorder keys and
// reformat numbers.
type ToolCall struct {
	ID        string
	Name      string
	Arguments string
}

// ToolChoiceMode constrains which tool, if any, the model may call.
type ToolChoiceMode string

const (
	// ToolChoiceAuto lets the model decide. This is what a request carrying
	// tools and no explicit choice means.
	ToolChoiceAuto ToolChoiceMode = "auto"
	// ToolChoiceNone forbids tool calls on this turn.
	ToolChoiceNone ToolChoiceMode = "none"
	// ToolChoiceAny requires a tool call, the model's pick of which.
	ToolChoiceAny ToolChoiceMode = "any"
	// ToolChoiceTool requires the tool named by ToolChoice.Name.
	ToolChoiceTool ToolChoiceMode = "tool"
)

// ToolChoice is how a caller constrains tool use.
type ToolChoice struct {
	Mode ToolChoiceMode
	// Name is the required tool, set only when Mode is ToolChoiceTool.
	Name string
}

// ToolCallDelta is one increment of a streamed tool call.
//
// Both dialects golem speaks announce a call before they can describe it: the
// first delta at an index carries ID and Name, and every delta after it adds
// another fragment of the arguments JSON. Index is what correlates the
// fragments when a model opens several calls at once.
type ToolCallDelta struct {
	Index     int
	ID        string
	Name      string
	Arguments string
}

// ToolCallAccumulator reassembles streamed deltas into whole tool calls.
//
// Every backend produces deltas and both response paths need the finished
// calls, so the assembly lives here rather than once per backend. The zero
// value is ready to use.
type ToolCallAccumulator struct {
	order []int
	calls map[int]*ToolCall
}

// Add folds one delta into the call at its index.
func (a *ToolCallAccumulator) Add(d ToolCallDelta) {
	if a.calls == nil {
		a.calls = make(map[int]*ToolCall)
	}
	call, seen := a.calls[d.Index]
	if !seen {
		call = &ToolCall{}
		a.calls[d.Index] = call
		a.order = append(a.order, d.Index)
	}
	// Later frames repeat neither id nor name, so only overwrite on a value.
	if d.ID != "" {
		call.ID = d.ID
	}
	if d.Name != "" {
		call.Name = d.Name
	}
	call.Arguments += d.Arguments
}

// Len reports how many distinct calls have been opened.
func (a *ToolCallAccumulator) Len() int { return len(a.order) }

// Calls returns the assembled calls in the order the model opened them, or nil
// if there were none.
func (a *ToolCallAccumulator) Calls() []ToolCall {
	if len(a.order) == 0 {
		return nil
	}
	out := make([]ToolCall, 0, len(a.order))
	for _, i := range a.order {
		out = append(out, *a.calls[i])
	}
	return out
}
