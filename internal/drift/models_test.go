package drift

import (
	"testing"
	"time"

	"github.com/Grace/switchboard/internal/audit"
)

func rec(model, backend, team string, day int) audit.Record {
	return audit.Record{
		Time:    time.Date(2026, 9, day, 12, 0, 0, 0, time.UTC),
		Model:   model,
		Backend: backend,
		Team:    team,
	}
}

// The finding this whole command exists for: a model answered production
// traffic and is on nobody's approved list.
func TestUnapprovedModelIsFound(t *testing.T) {
	b := New([]string{"claude", "haiku"})
	for d := 1; d <= 5; d++ {
		b.Add(rec("claude", "bedrock", "support", d))
	}
	for d := 18; d <= 20; d++ {
		b.Add(rec("gpt-4o-mini", "bedrock", "research", d))
	}
	res := b.Build()

	if len(res.Unapproved) != 1 || res.Unapproved[0] != "gpt-4o-mini" {
		t.Fatalf("unapproved = %v", res.Unapproved)
	}
	// And the other direction: approved, never called.
	if len(res.Unused) != 1 || res.Unused[0] != "haiku" {
		t.Fatalf("unused = %v", res.Unused)
	}
	// The window on the finding is what makes it actionable — an auditor's
	// next question is always when it started.
	for _, m := range res.Seen {
		if m.Name != "gpt-4o-mini" {
			continue
		}
		if m.First.Day() != 18 || m.Last.Day() != 20 {
			t.Errorf("window on the finding is %s → %s", m.First, m.Last)
		}
		if m.Requests != 3 {
			t.Errorf("requests = %d", m.Requests)
		}
	}
}

// An empty roster is not evidence that the models answering traffic were
// reviewed. Reporting them approved invents assurance; reporting them
// unapproved invents a finding for every deployment that has not listed models.
func TestNoRosterProducesNoFindings(t *testing.T) {
	b := New(nil)
	b.Add(rec("whatever", "bedrock", "support", 1))
	res := b.Build()

	if res.RosterKnown {
		t.Error("an empty roster must not read as a known roster")
	}
	if len(res.Unapproved) != 0 {
		t.Errorf("silence produced findings: %v", res.Unapproved)
	}
	if res.Seen[0].Approved {
		t.Error("a model was reported approved with nothing to approve it")
	}
}

// A clean deployment has to be able to come out clean, or the command is just
// an alarm nobody can silence.
func TestMatchingRosterIsClean(t *testing.T) {
	b := New([]string{"claude"})
	for d := 1; d <= 3; d++ {
		b.Add(rec("claude", "bedrock", "support", d))
	}
	res := b.Build()
	if len(res.Unapproved) != 0 || len(res.Unused) != 0 {
		t.Fatalf("clean deployment reported findings: %v / %v", res.Unapproved, res.Unused)
	}
	if !res.Seen[0].Approved {
		t.Error("a rostered model was not marked approved")
	}
}

// The fingerprint count is the only signal this data carries that a name may
// have changed meaning, so it has to be counted correctly.
func TestPolicyFingerprintsAreCounted(t *testing.T) {
	b := New([]string{"claude"})
	r1 := rec("claude", "bedrock", "support", 1)
	r1.Policy = "one"
	r2 := rec("claude", "bedrock", "support", 2)
	r2.Policy = "one"
	r3 := rec("claude", "bedrock", "support", 3)
	r3.Policy = "two"
	b.Add(r1)
	b.Add(r2)
	b.Add(r3)

	if got := b.Build().Policies; got != 2 {
		t.Fatalf("want 2 distinct fingerprints, got %d", got)
	}
}

// One model reached through two backends is one row, because the roster names
// models and the finding is about the name.
func TestBackendsAndTeamsAccumulate(t *testing.T) {
	b := New([]string{"claude"})
	b.Add(rec("claude", "bedrock", "support", 1))
	b.Add(rec("claude", "local", "research", 2))
	m := b.Build().Seen[0]

	if len(m.Backends) != 2 {
		t.Errorf("backends = %v", m.Backends)
	}
	if len(m.Teams) != 2 {
		t.Errorf("teams = %v", m.Teams)
	}
	if m.Requests != 2 {
		t.Errorf("requests = %d", m.Requests)
	}
}

// A record with no model names nothing, and inventing an empty row for it would
// put a blank line in a report somebody has to explain.
func TestRecordsWithoutAModelAreCountedNotListed(t *testing.T) {
	b := New([]string{"claude"})
	b.Add(audit.Record{Time: time.Now()})
	res := b.Build()
	if len(res.Seen) != 0 {
		t.Fatalf("a model-less record produced a row: %+v", res.Seen)
	}
	if res.Entries != 1 {
		t.Errorf("it should still count as an entry, got %d", res.Entries)
	}
}
