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
