package databricks

import (
	"strings"
	"testing"
	"time"

	"github.com/Grace/switchboard/internal/assess"
)

func window(t *testing.T) (time.Time, time.Time) {
	t.Helper()
	from, _ := time.Parse(time.RFC3339, "2026-09-01T00:00:00Z")
	to, _ := time.Parse(time.RFC3339, "2026-10-01T00:00:00Z")
	return from, to
}

func readOps(t *testing.T, body string) *Operation {
	t.Helper()
	from, to := window(t)
	op, err := ReadAudit(strings.NewReader(body), from, to)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

// The finding the whole file exists for: a control that is on today tells you
// nothing about whether it was on in March.
func TestAGapMakesTheControlUnmetForThePeriod(t *testing.T) {
	op := readOps(t, `[
	  {"event_time":"2026-09-05T10:00:00Z","actor":"a@x.com","action_name":"updateServingEndpoint",
	   "request_params":{"inference_table_config":"{\"enabled\":false}"}},
	  {"event_time":"2026-09-26T09:00:00Z","actor":"b@x.com","action_name":"updateServingEndpoint",
	   "request_params":{"inference_table_config":"{\"enabled\":true}"}}
	]`)
	if len(op.Gaps) != 1 {
		t.Fatalf("want one gap, got %+v", op.Gaps)
	}

	// A config export taken today would say logging is on.
	d := assess.Deployment{Source: "databricks"}
	d.Audit.Enabled = assess.Yes
	d = op.Apply(d)

	if d.Audit.Enabled != assess.No {
		t.Errorf("a period containing a logging gap is not evidenced; got %v", d.Audit.Enabled)
	}
	joined := strings.Join(d.Caveats, " ")
	if !strings.Contains(joined, "2026-09-05") || !strings.Contains(joined, "20 days") {
		t.Errorf("the caveat should say when and how long: %q", joined)
	}
}

// Off and never switched back on is the worse case and should read that way.
func TestAnOpenGapSaysItNeverCameBack(t *testing.T) {
	op := readOps(t, `[
	  {"event_time":"2026-09-20T08:00:00Z","actor":"a@x.com","action_name":"updateServingEndpoint",
	   "request_params":{"rate_limits":"null"}}
	]`)
	if len(op.Gaps) != 1 || !op.Gaps[0].Open() {
		t.Fatalf("want one open gap, got %+v", op.Gaps)
	}
	d := op.Apply(assess.Deployment{Source: "databricks"})
	if d.Runtime.Limits != assess.No {
		t.Error("an open gap must mark the control unmet")
	}
	if !strings.Contains(strings.Join(d.Caveats, " "), "still off at the end") {
		t.Errorf("caveats = %q", d.Caveats)
	}
}

// No rows is ambiguous, and saying so is the point: "nothing changed" and "the
// query never reached the table" look identical, and only one is evidence.
func TestNoRowsIsNotEvidenceOfNoChanges(t *testing.T) {
	d := readOps(t, `[]`).Apply(assess.Deployment{Source: "databricks"})
	joined := strings.Join(d.Caveats, " ")
	if !strings.Contains(joined, "look identical") {
		t.Errorf("an empty result must be reported as ambiguous: %q", joined)
	}
	// And it must not silently downgrade anything.
	if d.Audit.Enabled != assess.Unknown {
		t.Errorf("an empty audit query must not change a control: %v", d.Audit.Enabled)
	}
}

func TestCleanPeriodSaysSo(t *testing.T) {
	d := readOps(t, `[
	  {"event_time":"2026-09-04T12:00:00Z","actor":"a@x.com","action_name":"updateServingEndpoint",
	   "request_params":{"guardrails":"{\"enabled\":true}"}}
	]`).Apply(assess.Deployment{Source: "databricks"})
	if !strings.Contains(strings.Join(d.Caveats, " "), "none of which switched a governance control off") {
		t.Errorf("caveats = %q", d.Caveats)
	}
}

// Compute resizes and other non-governance events must not be reported as
// control changes, or the finding that matters is buried.
func TestNonGovernanceChangesAreNotGaps(t *testing.T) {
	op := readOps(t, `[
	  {"event_time":"2026-09-06T12:00:00Z","actor":"a@x.com","action_name":"updateServingEndpoint",
	   "request_params":{"workload_size":"Medium","scale_to_zero_enabled":"false"}}
	]`)
	if len(op.Gaps) != 0 {
		t.Errorf("a compute change is not a governance gap: %+v", op.Gaps)
	}
	if len(op.Changes) != 1 {
		t.Errorf("it is still an event worth counting: %+v", op.Changes)
	}
}

func TestMalformedTimestampIsAnError(t *testing.T) {
	from, to := window(t)
	_, err := ReadAudit(strings.NewReader(
		`[{"event_time":"yesterday","actor":"a","action_name":"x","request_params":{}}]`), from, to)
	if err == nil || !strings.Contains(err.Error(), "event_time") {
		t.Fatalf("want a parse error naming the column, got %v", err)
	}
}
