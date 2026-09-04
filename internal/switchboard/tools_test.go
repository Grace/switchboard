package switchboard

import "testing"

func TestToolCallAccumulator(t *testing.T) {
	// Two calls opened at once, their fragments interleaved — which is what a
	// model doing parallel tool calls actually streams.
	var acc ToolCallAccumulator
	for _, d := range []ToolCallDelta{
		{Index: 0, ID: "call_a", Name: "get_weather"},
		{Index: 1, ID: "call_b", Name: "get_time"},
		{Index: 0, Arguments: `{"city":`},
		{Index: 1, Arguments: `{"tz":"CET"}`},
		{Index: 0, Arguments: `"Oslo"}`},
	} {
		acc.Add(d)
	}

	if acc.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", acc.Len())
	}
	calls := acc.Calls()
	// Order is the order calls were opened, not the order they finished.
	if calls[0].ID != "call_a" || calls[1].ID != "call_b" {
		t.Fatalf("calls out of order: %+v", calls)
	}
	if want := `{"city":"Oslo"}`; calls[0].Arguments != want {
		t.Errorf("calls[0].Arguments = %q, want %q", calls[0].Arguments, want)
	}
	if want := `{"tz":"CET"}`; calls[1].Arguments != want {
		t.Errorf("calls[1].Arguments = %q, want %q", calls[1].Arguments, want)
	}
	if calls[0].Name != "get_weather" || calls[1].Name != "get_time" {
		t.Errorf("names lost: %+v", calls)
	}
}

func TestToolCallAccumulatorEmpty(t *testing.T) {
	var acc ToolCallAccumulator
	if acc.Len() != 0 {
		t.Errorf("Len() = %d, want 0", acc.Len())
	}
	// nil, not an empty slice: callers test len(result.ToolCalls) and the
	// field is omitempty on the way out.
	if calls := acc.Calls(); calls != nil {
		t.Errorf("Calls() = %+v, want nil", calls)
	}
}

func TestToolCallAccumulatorKeepsFirstIdentity(t *testing.T) {
	// Only the opening frame carries id and name; later frames must not blank
	// them out with their own empty fields.
	var acc ToolCallAccumulator
	acc.Add(ToolCallDelta{Index: 0, ID: "call_a", Name: "get_weather"})
	acc.Add(ToolCallDelta{Index: 0, Arguments: "{}"})

	got := acc.Calls()[0]
	if got.ID != "call_a" || got.Name != "get_weather" {
		t.Errorf("call = %+v, want id and name preserved", got)
	}
}

func TestSystemSplit(t *testing.T) {
	req := &ChatRequest{Messages: []Message{
		{Role: RoleSystem, Content: "be brief"},
		{Role: RoleSystem, Content: "be kind"},
		{Role: RoleUser, Content: "hello"},
		{Role: RoleSystem, Content: "too late"},
	}}

	system, rest := req.System()
	if want := "be brief\n\nbe kind"; system != want {
		t.Errorf("system = %q, want %q", system, want)
	}
	// A system turn after the conversation starts is a real turn, not a
	// preamble, and stays where the caller put it.
	if len(rest) != 2 || rest[0].Content != "hello" || rest[1].Content != "too late" {
		t.Errorf("rest = %+v", rest)
	}
}
