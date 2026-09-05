package assess

import (
	"strings"
	"testing"
	"time"
)

func find(t *testing.T, rep ControlReport, objective string) Control {
	t.Helper()
	for _, c := range rep.Controls {
		if strings.Contains(c.Objective, objective) {
			return c
		}
	}
	t.Fatalf("no control matching %q", objective)
	return Control{}
}

// The point of the whole package: a source that cannot answer a question must
// say so, rather than inventing a finding or inventing assurance.
func TestUnknownIsNotAFinding(t *testing.T) {
	// Everything Unknown — a foreign config the adapter could barely read.
	d := Deployment{Source: "litellm", Origin: "config.yaml"}
	d.Audit.Enabled = Unknown
	rep := Assess(d)

	if rep.Unmet() {
		t.Error("an unreadable config must not report failures it cannot evidence")
	}
	counts := rep.Counts()
	if counts[StatusUnknown] == 0 {
		t.Fatal("want unknown rows")
	}
	for _, c := range rep.Controls {
		if c.Status == StatusUnknown && !strings.Contains(c.Evidence, "litellm") {
			t.Errorf("unknown evidence should name the source: %q", c.Evidence)
		}
	}
}

func TestUnknownDiffersFromAbsent(t *testing.T) {
	silent := Deployment{Source: "litellm"}
	silent.Auth.DenyUnauthenticated = Unknown
	explicit := Deployment{Source: "litellm"}
	explicit.Auth.DenyUnauthenticated = No

	if got := find(t, Assess(silent), "Unauthenticated access").Status; got != StatusUnknown {
		t.Errorf("silent config, want unknown, got %q", got)
	}
	if got := find(t, Assess(explicit), "Unauthenticated access").Status; got != StatusUnmet {
		t.Errorf("explicitly off, want unmet, got %q", got)
	}
}

// A deployment that records nothing should not collect credit for a
// data-protection control it is only passing by having no data.
func TestNoRecordIsNotProtection(t *testing.T) {
	d := Deployment{Source: "switchboard"}
	d.Audit.Enabled = No
	row := find(t, Assess(d), "Sensitive data")
	if row.Status != StatusNotAddressed {
		t.Errorf("want not-addressed, got %q — %s", row.Status, row.Evidence)
	}
}

// Redaction an application can skip is a convention; at a chokepoint it is a
// control. The report has to be able to tell them apart, because most gateways
// are the former.
func TestChokepointRedactionOutranksOptIn(t *testing.T) {
	base := Deployment{Source: "x"}
	base.Audit.Enabled = Yes
	base.Data.RedactionRules = 3
	base.Data.ContentLogged = Yes

	optIn := base
	optIn.Data.RedactionUnbypassable = No
	if ev := find(t, Assess(optIn), "Sensitive data").Evidence; !strings.Contains(ev, "convention") {
		t.Errorf("opt-in redaction should be named as such: %q", ev)
	}

	choke := base
	choke.Data.RedactionUnbypassable = Yes
	if ev := find(t, Assess(choke), "Sensitive data").Evidence; !strings.Contains(ev, "chokepoint") {
		t.Errorf("chokepoint redaction should be named as such: %q", ev)
	}
}

// The remedy for missing FIPS depends on the toolchain, so it comes from the
// adapter rather than being guessed at here.
func TestFIPSRemedyComesFromTheAdapter(t *testing.T) {
	d := Deployment{Source: "switchboard", Profile: ProfileFedRAMP}
	d.Runtime.FIPS = No
	d.Runtime.FIPSHint = "Build with GOFIPS140=v1.0.0."
	if ev := find(t, Assess(d), "FIPS").Evidence; !strings.Contains(ev, "GOFIPS140") {
		t.Errorf("want the adapter's hint, got %q", ev)
	}

	d.Runtime.FIPSHint = ""
	if ev := find(t, Assess(d), "FIPS").Evidence; strings.Contains(ev, "GOFIPS140") {
		t.Errorf("no hint supplied, should not invent one: %q", ev)
	}
}

func TestRetentionFloorFollowsProfile(t *testing.T) {
	d := Deployment{Source: "x", Profile: ProfileFINRA}
	d.Audit.Enabled = Yes
	d.Audit.Archived = Yes
	d.Audit.Retention = 3 * 365 * 24 * time.Hour
	if got := find(t, Assess(d), "Log retention").Status; got != StatusUnmet {
		t.Errorf("3 years against a 6 year floor, want unmet, got %q", got)
	}
	d.Profile = ProfileEUAIAct
	if got := find(t, Assess(d), "Log retention").Status; got != StatusMet {
		t.Errorf("3 years clears six months, want met, got %q", got)
	}
}

// A deployment that cannot offer tools has no action to authorise. Scoring that
// as unmet would put a finding in front of a reviewer that nobody can act on,
// which is the same failure as inventing one from an Unknown.
func TestNoToolsIsNotAGap(t *testing.T) {
	d := Deployment{Source: "litellm"}
	d.Agency.ToolsOffered = No
	rep := Assess(d)
	c := find(t, rep, "authorised before they take effect")
	if c.Status != StatusNotAddressed {
		t.Fatalf("no tools should be not-addressed, got %s", c.Status)
	}
	if rep.Unmet() {
		t.Fatal("a deployment with no tools must not fail -strict on the agency rows")
	}
	// One line about a deployment with no tools is a fact; a second is padding.
	for _, c := range rep.Controls {
		if strings.Contains(c.Objective, "Tool calls and refusals are recorded") {
			t.Fatal("the recording row should be omitted when nothing can call a tool")
		}
	}
}

// Passing tool calls through unchecked is a real gap, and it is the one the
// whole enforcement path exists to close. It has to fail -strict.
func TestUnenforcedToolsIsUnmet(t *testing.T) {
	d := Deployment{Source: "switchboard"}
	d.Agency.ToolsOffered = Yes
	d.Agency.Authorised = No
	d.Agency.CallsRecorded = Yes
	c := find(t, Assess(d), "authorised before they take effect")
	if c.Status != StatusUnmet {
		t.Fatalf("unenforced tools should be unmet, got %s", c.Status)
	}
}

// The met row must carry its own limit. A reviewer reads the row and stops, so
// a claim that an action was prevented has to say where it is only a signal —
// otherwise the report overstates exactly where it can least afford to.
func TestEnforcementRowStatesTheStreamingLimit(t *testing.T) {
	d := Deployment{Source: "switchboard"}
	d.Agency.ToolsOffered = Yes
	d.Agency.Authorised = Yes
	d.Agency.AuthorisedDetail = "4 tools declared."
	c := find(t, Assess(d), "authorised before they take effect")
	if c.Status != StatusMet {
		t.Fatalf("want met, got %s", c.Status)
	}
	if !strings.Contains(c.Evidence, "4 tools declared.") {
		t.Error("evidence dropped the adapter's detail")
	}
	if !strings.Contains(c.Evidence, "streaming") {
		t.Errorf("evidence claims prevention without stating the streaming limit: %q", c.Evidence)
	}
}

// A source that says nothing about tools gets Unknown, not No — the same rule
// every other row here follows.
func TestSilentSourceGetsUnknownAgency(t *testing.T) {
	rep := Assess(Deployment{Source: "databricks"})
	for _, obj := range []string{"authorised before they take effect", "Tool calls and refusals are recorded"} {
		if c := find(t, rep, obj); c.Status != StatusUnknown {
			t.Errorf("%s: want unknown, got %s", obj, c.Status)
		}
	}
}
