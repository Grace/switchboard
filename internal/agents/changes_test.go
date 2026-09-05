package agents

import (
	"strings"
	"testing"
	"time"

	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/config"
)

func find(t *testing.T, log Changelog, kind EventKind) Event {
	t.Helper()
	for _, e := range log.Events {
		if e.Kind == kind {
			return e
		}
	}
	t.Fatalf("no %s event in %d events", kind, len(log.Events))
	return Event{}
}

func has(log Changelog, kind EventKind) bool {
	for _, e := range log.Events {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

// The headline artifact: a dated sentence saying an agent gained a capability.
// This is what an examiner asking "did it operate throughout the period" needs
// and what no snapshot inventory can produce.
func TestToolsetChangeIsDatedAndDescribed(t *testing.T) {
	b := New([]string{"search", "read"}, config.Pricing{})
	for d := 1; d <= 5; d++ {
		b.Add(rec("support", d, []string{"search", "read"}))
	}
	for d := 20; d <= 24; d++ {
		b.Add(rec("support", d, []string{"search", "read", "wire_transfer"}))
	}
	log := b.Build().Changes(0)

	e := find(t, log, Changed)
	if !e.Time.Equal(at(20)) {
		t.Errorf("change should be dated to first sight of the new toolset, got %s", e.Time)
	}
	if len(e.Gained) != 1 || e.Gained[0] != "wire_transfer" {
		t.Errorf("gained = %v", e.Gained)
	}
	if len(e.Lost) != 0 {
		t.Errorf("nothing was lost, got %v", e.Lost)
	}
	if !e.Shadow {
		t.Error("gaining an undeclared tool must be marked shadow")
	}
	// The claim is a conclusion from overlap, not something the log recorded.
	// A reader who takes it for an observation will defend it to an auditor who
	// can disprove it.
	if !e.Inferred {
		t.Error("succession must be labelled inferred")
	}
}

// A program that became something else did not stop. Reporting both would put
// a retirement in an audit response for an agent that is still running.
func TestSuccessorIsNotAlsoRetired(t *testing.T) {
	b := New(nil, config.Pricing{})
	b.Add(rec("support", 1, []string{"a", "b", "c"}))
	for d := 20; d <= 24; d++ {
		b.Add(rec("support", d, []string{"a", "b", "c", "d"}))
	}
	log := b.Build().Changes(0)
	if has(log, Retired) {
		t.Fatal("the predecessor of a change was also reported retired")
	}
}

// Below the overlap threshold the claim stops being an inference and becomes a
// guess. Two honest rows beat one invented history.
func TestUnrelatedToolsetsAreNotLinked(t *testing.T) {
	b := New(nil, config.Pricing{})
	b.Add(rec("support", 1, []string{"a", "b", "c", "d"}))
	for d := 20; d <= 24; d++ {
		b.Add(rec("support", d, []string{"w", "x", "y", "z"}))
	}
	log := b.Build().Changes(0)
	if has(log, Changed) {
		t.Fatal("two disjoint toolsets were reported as one program changing")
	}
	n := 0
	for _, e := range log.Events {
		if e.Kind == Appeared {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("want 2 independent appearances, got %d", n)
	}
}

// Retirement is measured against the end of the window, not against now, so
// re-running a closed period next year gives the same answer.
func TestRetirementIsMeasuredAgainstTheWindow(t *testing.T) {
	b := New(nil, config.Pricing{})
	b.Add(rec("research", 1, []string{"w", "x"}))
	for d := 25; d <= 28; d++ {
		b.Add(rec("support", d, []string{"totally", "different", "tools"}))
	}
	log := b.Build().Changes(0)

	e := find(t, log, Retired)
	if !e.Time.Equal(at(1)) {
		t.Errorf("retirement should be dated to the last call, got %s", e.Time)
	}

	// Widen the quiet threshold past the gap and it is no longer a retirement.
	quiet := b.Build().Changes(60 * 24 * time.Hour)
	if has(quiet, Retired) {
		t.Error("an agent silent for less than the threshold was reported retired")
	}
}

// The shadow-skill inference: tools carried by exactly the same agents arrived
// together and are one thing somebody installed.
func TestShadowSkillsGroupByWhatArrivedTogether(t *testing.T) {
	b := New([]string{"search"}, config.Pricing{})
	// One agent carries a payments pair.
	for d := 1; d <= 3; d++ {
		b.Add(rec("support", d, []string{"search", "wire_transfer", "check_balance"}))
	}
	// A different agent carries an unrelated scraping pair.
	for d := 1; d <= 3; d++ {
		b.Add(rec("research", d, []string{"search", "crawl", "extract"}))
	}
	log := b.Build().Changes(0)

	if len(log.Shadow) != 2 {
		t.Fatalf("want 2 distinct shadow skills, got %d: %+v", len(log.Shadow), log.Shadow)
	}
	for _, s := range log.Shadow {
		if len(s.Tools) != 2 {
			t.Errorf("shadow skill %s should hold its pair, got %v", s.ID, s.Tools)
		}
		if strings.Contains(strings.Join(s.Tools, ","), "search") {
			t.Errorf("a declared tool leaked into a shadow skill: %v", s.Tools)
		}
	}
}

// A shadow skill being *used* is a different finding from one merely present,
// and it is the one that needs an answer this week.
func TestShadowSkillCountsRefusals(t *testing.T) {
	b := New([]string{"search"}, config.Pricing{})
	for d := 1; d <= 4; d++ {
		b.Add(rec("support", d, []string{"search", "wire_transfer"},
			audit.ToolCall{Name: "wire_transfer", Refused: true, Reason: "tool_not_permitted"}))
	}
	log := b.Build().Changes(0)
	if len(log.Shadow) != 1 {
		t.Fatalf("want 1 shadow skill, got %d", len(log.Shadow))
	}
	if log.Shadow[0].Refused != 4 {
		t.Errorf("want 4 refusals counted, got %d", log.Shadow[0].Refused)
	}
}

// Nothing declared means no shadow skills, for the same reason it means no
// undeclared tools: silence in the config is not evidence of anything.
func TestNoDeclarationMeansNoShadowSkills(t *testing.T) {
	b := New(nil, config.Pricing{})
	b.Add(rec("support", 1, []string{"anything", "at_all"}))
	if s := b.Build().Changes(0).Shadow; len(s) != 0 {
		t.Fatalf("silence produced shadow skills: %+v", s)
	}
}

// A policy fingerprint moving means entries either side were judged under
// different rules, which is the other half of "was this allowed at the time".
func TestPolicyChangeIsAnEvent(t *testing.T) {
	b := New(nil, config.Pricing{})
	for d := 1; d <= 3; d++ {
		r := rec("support", d, []string{"search"})
		r.Policy = "fingerprint-one"
		b.Add(r)
	}
	for d := 4; d <= 6; d++ {
		r := rec("support", d, []string{"search"})
		r.Policy = "fingerprint-two"
		b.Add(r)
	}
	log := b.Build().Changes(0)

	e := find(t, log, PolicyChanged)
	if !e.Time.Equal(at(4)) {
		t.Errorf("policy change should be dated to the first entry under the new one, got %s", e.Time)
	}
	// One fingerprint throughout is not a change.
	b2 := New(nil, config.Pricing{})
	r := rec("support", 1, []string{"search"})
	r.Policy = "only-one"
	b2.Add(r)
	if has(b2.Build().Changes(0), PolicyChanged) {
		t.Error("a single unchanged policy was reported as a change")
	}
}

// The untooled row is every program that used no tools. Saying it appeared or
// changed would be a claim about a thing that does not exist.
func TestUntooledTrafficProducesNoEvents(t *testing.T) {
	b := New(nil, config.Pricing{})
	for d := 1; d <= 5; d++ {
		b.Add(rec("research", d, nil))
	}
	if log := b.Build().Changes(0); len(log.Events) != 0 {
		t.Fatalf("untooled traffic produced events: %+v", log.Events)
	}
}
