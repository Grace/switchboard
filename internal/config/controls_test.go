package config

import (
	"crypto/fips140"
	"github.com/Grace/switchboard/internal/assess"
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
	// Nothing the config controls should be met. FIPS is excluded because it is
	// a property of the process, not of the file — it is met under
	// GODEBUG=fips140=on however empty the config is.
	for _, c := range rep.Controls {
		if c.Status == StatusMet && !strings.Contains(c.Objective, "FIPS") {
			t.Errorf("empty config should not meet %q: %s", c.Objective, c.Evidence)
		}
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
		if len(c.Refs) == 0 {
			t.Errorf("control %q cites no framework", c.Objective)
		}
	}
}

func TestControlsProfileTightensPersonIdentity(t *testing.T) {
	c := compliant(t)
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
	if !strings.Contains(assess.Render(row.Refs, ""), "164.312(d)") {
		t.Errorf("row should cite the regime's authority, got %v", row.Refs)
	}
}

func TestControlsRetentionRowFollowsTheProfileFloor(t *testing.T) {
	c := compliant(t)
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
	c := compliant(t)
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
	c := compliant(t)
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
	c := compliant(t)
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
		c := compliant(t)
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
	c := compliant(t)
	c.Profile = ProfileHIPAA
	c.Attribution = Attribution{Enabled: true, RoleARN: "arn:aws:iam::1:role/r", RequireCaller: true}
	c.Redaction = Redaction{Rules: []string{"us_ssn", "email", "phone_us"}}
	c.TLS = TLS{CertFile: "/tmp/c.pem", KeyFile: "/tmp/k.pem"}
	c.Limits = Limits{Enabled: true}
	c.Audit.VerifyInterval = Duration(time.Hour)
	c.Vault = Vault{Enabled: true, Path: "/tmp/v", PublicKey: "/tmp/pub.pem"}
	// A deployment that forwards tools and bounds none of them has a real gap,
	// so a config is not fully configured until it has declared them. Adding
	// this here rather than exempting the row is the point: the row is supposed
	// to make somebody do this.
	c.Tools = Tools{
		Enabled: true,
		Declare: map[string]ToolDecl{"lookup": {Bundle: "support"}},
		Grants:  map[string]ToolGrant{"clinic": {Tools: []string{"lookup"}}},
	}

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

func TestControlsFIPSRow(t *testing.T) {
	c := compliant(t)

	// No regime asking for it: reported, not counted against you.
	row := find(t, c.Controls(), "FIPS-validated")
	if fips140.Enabled() {
		if row.Status != StatusMet {
			t.Errorf("FIPS mode is on, want met, got %q", row.Status)
		}
	} else if row.Status != StatusNotAddressed {
		t.Errorf("no regime asks for FIPS, want not-addressed, got %q", row.Status)
	}

	// A regime that does ask turns the same fact into a finding.
	c.Profile = ProfileFedRAMP
	row = find(t, c.Controls(), "FIPS-validated")
	want := StatusUnmet
	if fips140.Enabled() {
		want = StatusMet
	}
	if row.Status != want {
		t.Errorf("under fedramp want %q, got %q", want, row.Status)
	}
	if !fips140.Enabled() && !strings.Contains(row.Evidence, "GOFIPS140") {
		t.Errorf("evidence should name the remedy, got %q", row.Evidence)
	}
}

func TestControlsGovernmentTLSIsUnconditional(t *testing.T) {
	c := compliant(t)
	c.TLS = TLS{}

	c.Profile = ProfileHIPAA
	if got := find(t, c.Controls(), "Encryption in transit").Status; got != StatusPartial {
		t.Errorf("hipaa tolerates a loopback plaintext bind, got %q", got)
	}

	c.Profile = Profile800171
	if got := find(t, c.Controls(), "Encryption in transit").Status; got != StatusUnmet {
		t.Errorf("800-171 does not, want unmet, got %q", got)
	}
}

func TestControlsSaysWhenARetentionFloorIsNotStatutory(t *testing.T) {
	// The federal regimes leave the period organization-defined. Presenting
	// switchboard's default as a regulatory number would be exactly the kind of
	// overclaim this report exists to avoid.
	c := compliant(t)
	c.Profile = ProfileFedRAMP
	if ev := find(t, c.Controls(), "Log retention").Evidence; !strings.Contains(ev, "rather than a statutory number") {
		t.Errorf("federal retention should be marked as a default, got %q", ev)
	}

	c.Profile = ProfileHIPAA
	if ev := find(t, c.Controls(), "Log retention").Evidence; strings.Contains(ev, "rather than a statutory number") {
		t.Errorf("HIPAA's floor is statutory and should not carry the caveat, got %q", ev)
	}
}

func TestControlsSkipsProviderRowWithNoProvider(t *testing.T) {
	// A finding nobody can act on teaches people to skim the report.
	c := compliant(t)
	if got := find(t, c.Controls(), "Least privilege").Status; got != StatusNotAddressed {
		t.Errorf("local-only deployment, want not-addressed, got %q", got)
	}

	c.Models = []Line{{Name: "claude", Backend: BackendBedrock, ModelID: "anthropic.x"}}
	if got := find(t, c.Controls(), "Least privilege").Status; got != StatusPartial {
		t.Errorf("bedrock configured without attribution, want partial, got %q", got)
	}
}

// The evidence line has to describe this deployment, not tool use in general.
// A generic sentence in an evidence column is the failure mode this whole
// command exists to avoid: it reads as a finding and asserts nothing.
func TestToolEvidenceDescribesThisDeployment(t *testing.T) {
	c := Default()
	c.Audit.Enabled = true
	c.Audit.Path = "/tmp/audit.jsonl"
	c.Tools = Tools{
		Enabled: true,
		Declare: map[string]ToolDecl{
			"search_tickets": {Bundle: "support", Scopes: []string{"tickets"}},
			"read_account":   {Bundle: "support", Scopes: []string{"accounts"}},
			"send_email":     {Bundle: "comms", Scopes: []string{"tickets"}, Egress: true},
		},
		Grants: map[string]ToolGrant{
			"support": {Tools: []string{"search_tickets", "read_account"}, Scopes: []string{"tickets"}},
		},
	}
	if err := c.Tools.validate(); err != nil {
		t.Fatalf("fixture does not validate: %v", err)
	}

	rep := c.Controls()
	var ev string
	for _, ctl := range rep.Controls {
		if strings.Contains(ctl.Objective, "authorised before they take effect") {
			if ctl.Status != StatusMet {
				t.Fatalf("enforcement is on; want met, got %s", ctl.Status)
			}
			ev = ctl.Evidence
		}
	}
	if ev == "" {
		t.Fatal("no tool authorisation row in the report")
	}
	for _, want := range []string{
		"3 tools declared",
		"2 bundles",
		"1 of those tools can send data outside",
		"1 team holds an explicit grant",
		"may call nothing",
	} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence missing %q:\n%s", want, ev)
		}
	}
}

// Off, the row is a real gap rather than a silence. switchboard forwards tools
// whether or not it bounds them, so "we have not configured this" and "there is
// nothing to configure" are different answers.
func TestToolsOffIsUnmetNotUnknown(t *testing.T) {
	c := Default()
	rep := c.Controls()
	for _, ctl := range rep.Controls {
		if strings.Contains(ctl.Objective, "authorised before they take effect") {
			if ctl.Status != StatusUnmet {
				t.Fatalf("want unmet with tools disabled, got %s", ctl.Status)
			}
			return
		}
	}
	t.Fatal("no tool authorisation row in the report")
}
