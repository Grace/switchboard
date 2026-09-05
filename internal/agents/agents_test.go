package agents

import (
	"testing"
	"time"

	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/config"
)

func at(day int) time.Time {
	return time.Date(2026, 9, day, 12, 0, 0, 0, time.UTC)
}

func rec(team string, day int, offered []string, called ...audit.ToolCall) audit.Record {
	return audit.Record{
		Time: at(day), Team: team, Subject: team + "@example.com",
		Model: "claude", ToolsOffered: offered, ToolCalls: called,
	}
}

func byID(t *testing.T, inv Inventory, id string) Agent {
	t.Helper()
	for _, a := range inv.Agents {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("no agent %q in inventory of %d", id, len(inv.Agents))
	return Agent{}
}

// The premise of the whole package: the same program is one row however many
// people run it, and the order it lists its tools in is a property of how the
// request was assembled rather than of the program.
func TestSameToolsetIsOneAgentRegardlessOfCallerOrOrder(t *testing.T) {
	b := New(nil, config.Pricing{})
	b.Add(rec("support", 1, []string{"search", "read", "email"}))
	b.Add(rec("billing", 2, []string{"email", "search", "read"}))
	b.Add(rec("support", 3, []string{"read", "email", "search"}))
	inv := b.Build()

	if len(inv.Agents) != 1 {
		t.Fatalf("want 1 agent, got %d", len(inv.Agents))
	}
	a := inv.Agents[0]
	if a.Requests != 3 {
		t.Errorf("want 3 requests, got %d", a.Requests)
	}
	if len(a.Teams) != 2 {
		t.Errorf("want both teams recorded, got %v", a.Teams)
	}
	if a.Subjects != 2 {
		t.Errorf("want 2 distinct subjects, got %d", a.Subjects)
	}
	if !a.First.Equal(at(1)) || !a.Last.Equal(at(3)) {
		t.Errorf("window is %s → %s", a.First, a.Last)
	}
}

// A different toolset is a different program. This is also how a modified agent
// shows up, which is the point rather than a limitation.
func TestDifferentToolsetIsADifferentAgent(t *testing.T) {
	b := New(nil, config.Pricing{})
	b.Add(rec("support", 1, []string{"search", "read"}))
	b.Add(rec("support", 2, []string{"search", "read", "transfer_funds"}))
	inv := b.Build()
	if len(inv.Agents) != 2 {
		t.Fatalf("want 2 agents, got %d", len(inv.Agents))
	}
}

// Offered-minus-called is the least-privilege finding, and it is the reason to
// build this at all: it is measured rather than asserted.
func TestUnusedAuthorityIsReported(t *testing.T) {
	b := New(nil, config.Pricing{})
	offered := []string{"search", "read", "delete_account"}
	b.Add(rec("support", 1, offered, audit.ToolCall{Name: "search"}))
	b.Add(rec("support", 2, offered, audit.ToolCall{Name: "search"}, audit.ToolCall{Name: "read"}))
	inv := b.Build()

	a := inv.Agents[0]
	if len(a.Unused) != 1 || a.Unused[0] != "delete_account" {
		t.Fatalf("want delete_account unused, got %v", a.Unused)
	}
	if a.Called["search"] != 2 || a.Called["read"] != 1 {
		t.Errorf("call tally wrong: %v", a.Called)
	}
}

// A refused call is the agent asking. Reporting it as unused authority would
// recommend removing a grant the program is actively trying to use — the
// opposite of the finding, and a recommendation that would hide an attack.
func TestRefusedCallIsNotUnusedAuthority(t *testing.T) {
	b := New(nil, config.Pricing{})
	offered := []string{"search", "send_email"}
	b.Add(rec("support", 1, offered,
		audit.ToolCall{Name: "search"},
		audit.ToolCall{Name: "send_email", Refused: true, Reason: "tool_not_permitted"}))
	a := b.Build().Agents[0]

	for _, u := range a.Unused {
		if u == "send_email" {
			t.Fatal("a tool the agent tried to call was reported as unused authority")
		}
	}
	if a.Refused["send_email"] != 1 {
		t.Errorf("refusal not counted: %v", a.Refused)
	}
}

// The diff against the configuration is the shadow-AI finding: a program
// offering something nobody declared changed without anyone saying so.
func TestUndeclaredToolsAreFound(t *testing.T) {
	b := New([]string{"search", "read"}, config.Pricing{})
	b.Add(rec("support", 1, []string{"search", "wire_transfer"}))
	inv := b.Build()

	a := inv.Agents[0]
	if len(a.Undeclared) != 1 || a.Undeclared[0] != "wire_transfer" {
		t.Fatalf("want wire_transfer undeclared, got %v", a.Undeclared)
	}
	// And the other direction: authorised, never asked for.
	if len(inv.Unseen) != 1 || inv.Unseen[0] != "read" {
		t.Fatalf("want read unseen, got %v", inv.Unseen)
	}
}

// An empty declaration list is not evidence that everything is authorised.
// Reporting every tool as undeclared because the config said nothing would
// invent findings for every deployment that has not configured tools yet.
func TestNoDeclarationMeansNoUndeclaredFinding(t *testing.T) {
	b := New(nil, config.Pricing{})
	b.Add(rec("support", 1, []string{"anything", "at_all"}))
	if u := b.Build().Agents[0].Undeclared; len(u) != 0 {
		t.Fatalf("silence in the config produced findings: %v", u)
	}
}

// Requests with no tools cannot be attributed to a program, and the inventory
// has to say so rather than presenting them as one agent.
func TestUntooledTrafficIsCountedNotIdentified(t *testing.T) {
	b := New(nil, config.Pricing{})
	b.Add(rec("a", 1, nil))
	b.Add(rec("b", 2, nil))
	b.Add(rec("support", 3, []string{"search"}))
	inv := b.Build()

	if len(inv.Agents) != 2 {
		t.Fatalf("want 2 rows, got %d", len(inv.Agents))
	}
	// The anonymous row sorts last even though it has more requests, because it
	// is context rather than a finding.
	last := inv.Agents[len(inv.Agents)-1]
	if !last.Anonymous {
		t.Fatal("the untooled row should sort last")
	}
	if last.Requests != 2 || last.ID != "" {
		t.Errorf("untooled row is %+v", last)
	}
}

// A total that silently omits the requests it could not price is the kind of
// number that gets repeated in a meeting.
func TestPartialPricingIsFlagged(t *testing.T) {
	prices := config.Pricing{Models: map[string]config.ModelPrice{
		"claude": {InputPerMTok: 3, OutputPerMTok: 15},
	}}
	b := New(nil, prices)
	r := rec("support", 1, []string{"search"})
	r.PromptTokens, r.CompletionTokens = 1000, 500
	b.Add(r)
	if a := b.Build().Agents[0]; !a.CostKnown || a.Cost <= 0 {
		t.Fatalf("priced request should be known: %+v", a)
	}

	b2 := New(nil, prices)
	r2 := rec("support", 1, []string{"search"})
	r2.Model = "some-unpriced-model"
	r2.PromptTokens = 1000
	b2.Add(r2)
	if b2.Build().Agents[0].CostKnown {
		t.Fatal("an unpriced request must mark the total partial")
	}
}

// The fingerprint has to be stable across runs, or an inventory cannot be
// compared with last month's.
func TestFingerprintIsStable(t *testing.T) {
	id1, _ := fingerprint([]string{"b", "a"})
	id2, _ := fingerprint([]string{"a", "b"})
	if id1 != id2 || id1 == "" {
		t.Fatalf("fingerprint unstable: %q vs %q", id1, id2)
	}
	if other, _ := fingerprint([]string{"a", "b", "c"}); other == id1 {
		t.Fatal("different toolsets collided")
	}
}
