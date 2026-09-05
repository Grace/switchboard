package redteam

import (
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

func TestReadsTheCurrentPromptfooShape(t *testing.T) {
	res, err := Read(strings.NewReader(`{
	  "evalId": "eval-abc",
	  "results": {
	    "version": 3,
	    "timestamp": "2026-08-14T09:12:00.000Z",
	    "stats": {"successes": 44, "failures": 3, "errors": 0}
	  }
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.Tool != "promptfoo" || res.Version != "3" {
		t.Errorf("tool/version = %q/%q", res.Tool, res.Version)
	}
	if res.Passed != 44 || res.Failed != 3 || res.Total() != 47 {
		t.Errorf("stats = %+v", res)
	}
	if res.Ran.Format("2006-01-02") != "2026-08-14" {
		t.Errorf("ran = %s", res.Ran)
	}
	if res.Clean() {
		t.Error("a run with failures is not clean")
	}
}

// The shape moved between versions; a report from an older one is still
// somebody's real security evidence.
func TestReadsTheOlderTopLevelShape(t *testing.T) {
	res, err := Read(strings.NewReader(
		`{"version":"0.9.1","timestamp":"2026-08-14","stats":{"successes":10,"failures":0,"errors":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed != 10 || res.Errors != 1 || res.Version != "0.9.1" {
		t.Errorf("res = %+v", res)
	}
	if res.Clean() {
		t.Error("an errored run is not clean")
	}
}

// The one thing this must never do: report a deployment as tested on the
// strength of a file that might be anything.
func TestRefusesToGuessAtAnUnrecognisedReport(t *testing.T) {
	for _, in := range []string{
		`{"cluster_id":"abc"}`,
		`{"results":{"version":3}}`,
		`{}`,
		`[]`,
	} {
		if res, err := Read(strings.NewReader(in)); err == nil {
			t.Errorf("%s parsed as %+v; it should have been refused", in, res)
		}
	}
	// And the refusal has to say what it looked for, and name the tools it
	// cannot read, or the user has no next step.
	_, err := Read(strings.NewReader(`{"entry_type":"eval","probe":"dan"}`))
	if err == nil {
		t.Fatal("a garak-shaped report should not parse as promptfoo")
	}
	for _, want := range []string{"results.stats", "garak"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

func TestNotJSONIsARefusalNotAnEmptyResult(t *testing.T) {
	if _, err := Read(strings.NewReader("hello")); err == nil {
		t.Fatal("plain text should not parse")
	}
}

// A reviewer's first question about a security test is when it ran, so the
// sentence always says — and says loudly when the answer is "a long time ago".
func TestTheDescriptionAlwaysStatesTheAge(t *testing.T) {
	fresh := Result{Tool: "promptfoo", Version: "3", Ran: now.AddDate(0, 0, -22), Passed: 44, Failed: 3}
	got := fresh.Describe(now)
	for _, want := range []string{"promptfoo 3", "2026-08-14", "22 days ago", "44 of 47", "3 failed"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in: %s", want, got)
		}
	}

	stale := Result{Tool: "promptfoo", Ran: now.AddDate(-2, 0, 0), Passed: 47}
	got = stale.Describe(now)
	if !strings.Contains(got, "record of testing rather than current assurance") {
		t.Errorf("a two-year-old run should not read as current: %s", got)
	}

	// The clause is unpunctuated: the caller wraps it in a sentence, and a
	// trailing stop here shows up as ".." in the report.
	if strings.HasSuffix(fresh.Describe(now), ".") {
		t.Errorf("Describe should not end in a full stop: %s", fresh.Describe(now))
	}

	// A report with no assertions evidences that the tool ran and nothing more,
	// and has to say which of those it is.
	empty := Result{Tool: "promptfoo", Ran: now}
	got = empty.Describe(now)
	if !strings.Contains(got, "no assertions") {
		t.Errorf("an empty run should say so: %s", got)
	}

	// An undated report must not silently read as recent.
	undated := Result{Tool: "promptfoo", Passed: 5}
	if !strings.Contains(undated.Describe(now), "unrecorded time") {
		t.Errorf("an undated run should say so: %s", undated.Describe(now))
	}
}
