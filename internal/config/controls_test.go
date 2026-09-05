package config

import (
	"strings"
	"testing"
	"time"
)

// find returns the assessed row for an objective, so a test can name the
// control it cares about instead of indexing into a slice that will move.
func find(t *testing.T, rep ControlReport, objective string) Control {
	t.Helper()
	for _, c := range rep.Controls {
		if strings.Contains(c.Objective, objective) {
			return c
		}
	}
	t.Fatalf("no control matching %q in report", objective)
	return Control{}
}

func TestControlsReportsAnEmptyConfigHonestly(t *testing.T) {
	rep := (&Config{Listen: "127.0.0.1:11435"}).Controls()

	if !rep.Unmet() {
		t.Error("a config with nothing turned on should have unmet controls")
	}
	if rep.Counts()[StatusMet] != 0 {
		t.Errorf("nothing should be met, got %d", rep.Counts()[StatusMet])
	}
	if len(rep.Yours) != 0 {
		t.Error("no profile means no regime obligations to list")
	}
	// Every row carries its reason. A status with no evidence is the claim this
	// command exists to avoid making.
	for _, c := range rep.Controls {
		if strings.TrimSpace(c.Evidence) == "" {
			t.Errorf("control %q has no evidence", c.Objective)
		}
		if strings.TrimSpace(c.Refs) == "" {
			t.Errorf("control %q cites no framework", c.Objective)
		}
	}
}

func TestControlsProfileTightensPersonIdentity(t *testing.T) {
	c := compliant()
	c.OIDC = OIDC{}
	c.Teams = []Team{{Name: "platform", Keys: []string{"k"}}}

	if got := find(t, c.Controls(), "identify a person").Status; got != StatusPartial {
		t.Errorf("without a profile a shared key is partial, got %q", got)
	}

	c.Profile = ProfileHIPAA
	row := find(t, c.Controls(), "identify a person")
	if row.Status != StatusUnmet {
		t.Errorf("hipaa should make a shared key unmet, got %q", row.Status)
	}
	if !strings.Contains(row.Refs, "164.312(d)") {
		t.Errorf("row should cite the regime's authority, got %q", row.Refs)
	}
}

func TestControlsRetentionRowFollowsTheProfileFloor(t *testing.T) {
	c := compliant()
	c.Audit.Retention = Duration(3 * 365 * 24 * time.Hour)

	c.Profile = ProfileEUAIAct
	if got := find(t, c.Controls(), "Log retention").Status; got != StatusMet {
		t.Errorf("3 years clears the Art. 26 floor, got %q", got)
	}

	c.Profile = ProfileFINRA
	row := find(t, c.Controls(), "Log retention")
	if row.Status != StatusUnmet {
		t.Errorf("3 years misses the 6 year floor, got %q", row.Status)
	}
	if !strings.Contains(row.Evidence, "6 years") {
		t.Errorf("evidence should name the floor, got %q", row.Evidence)
	}
}

func TestControlsRetentionWithoutAnArchiveIsNotMet(t *testing.T) {
	// Keeping everything on one host is a promise the disk cannot keep, and
	// reporting it as met would be the flattering answer.
	c := compliant()
	c.Audit.Retention = 0
	c.Audit.ArchiveCommand = ""
	row := find(t, c.Controls(), "Log retention")
	if row.Status != StatusPartial {
		t.Errorf("keep-everything with no archive is partial, got %q", row.Status)
	}
}

func TestControlsMetadataOnlyBeatsRedactedContent(t *testing.T) {
	// Not writing content at all is a stronger position than redacting it, and
	// the report should say so rather than rewarding the bigger feature.
	c := compliant()
	c.Redaction = Redaction{Rules: []string{"us_ssn"}}

	c.Audit.LogContent = false
	if got := find(t, c.Controls(), "Sensitive data").Status; got != StatusMet {
		t.Errorf("metadata-only should be met, got %q", got)
	}

	c.Audit.LogContent = true
	row := find(t, c.Controls(), "Sensitive data")
	if row.Status != StatusPartial {
		t.Errorf("redacted content is partial, got %q", row.Status)
	}
	if !strings.Contains(row.Evidence, "prose") {
		t.Errorf("evidence should name the pattern-matching limit, got %q", row.Evidence)
	}
}

func TestControlsTamperEvidenceNeverClaimsMore(t *testing.T) {
	// This row must never read as met: tail truncation stays undetectable from
	// the file alone however the gateway is configured.
	c := compliant()
	row := find(t, c.Controls(), "protected from modification")
	if row.Status != StatusPartial {
		t.Fatalf("tamper evidence is always partial, got %q", row.Status)
	}
	if !strings.Contains(row.Evidence, "truncation") {
		t.Errorf("evidence must name the truncation gap, got %q", row.Evidence)
	}
}

func TestControlsListsRegimeObligationsItCannotCheck(t *testing.T) {
	for _, p := range []Profile{ProfileHIPAA, ProfileFINRA, ProfileEUAIAct} {
		c := compliant()
		c.Profile = p
		rep := c.Controls()
		if len(rep.Yours) == 0 {
			t.Errorf("profile %q should name obligations outside the config file", p)
		}
		if rep.Regime == "" {
			t.Errorf("profile %q should name its regime", p)
		}
	}
}

func TestControlsFullyConfiguredHasNoUnmet(t *testing.T) {
	// The point of the command is that a good config can actually pass it.
	c := compliant()
	c.Profile = ProfileHIPAA
	c.Attribution = Attribution{Enabled: true, RoleARN: "arn:aws:iam::1:role/r", RequireCaller: true}
	c.Redaction = Redaction{Rules: []string{"us_ssn", "email", "phone_us"}}
	c.TLS = TLS{CertFile: "/tmp/c.pem", KeyFile: "/tmp/k.pem"}
	c.Limits = Limits{Enabled: true}
	c.Audit.VerifyInterval = Duration(time.Hour)
	c.Vault = Vault{Enabled: true, Path: "/tmp/v", PublicKey: "/tmp/pub.pem"}

	rep := c.Controls()
	for _, ctl := range rep.Controls {
		if ctl.Status == StatusUnmet {
			t.Errorf("unmet with a full config: %s — %s", ctl.Objective, ctl.Evidence)
		}
	}
	if rep.Unmet() {
		t.Error("Unmet() should be false")
	}
}
