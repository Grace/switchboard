package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

// compliant is a config that satisfies every profile, so each test can spoil
// exactly one thing and attribute the failure to that thing.
func compliant() *Config {
	return &Config{
		Listen: "127.0.0.1:11435",
		OIDC:   OIDC{Enabled: true, Issuer: "https://idp.example", Audience: "switchboard"},
		Teams:  []Team{{Name: "platform"}},
		Audit: Audit{
			Enabled:        true,
			Path:           "/tmp/audit.jsonl",
			Required:       true,
			MaxBytes:       1 << 20,
			Retention:      Duration(7 * 365 * 24 * time.Hour),
			ArchiveCommand: "cp $SEGMENT /archive/",
		},
	}
}

func TestProfileUnknownIsRejected(t *testing.T) {
	c := compliant()
	c.Profile = "sox"
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "not one of") {
		t.Fatalf("want unknown-profile error, got %v", err)
	}
}

func TestProfileNoneEnforcesNothing(t *testing.T) {
	c := compliant()
	c.Audit.Retention = Duration(time.Hour) // far below every floor
	c.Audit.Required = false
	c.OIDC.Enabled = false
	if err := c.Validate(); err != nil {
		t.Fatalf("no profile should assert nothing, got %v", err)
	}
}

func TestProfileAccepted(t *testing.T) {
	for _, p := range ProfileNames() {
		c := compliant()
		c.Profile = Profile(p)
		if err := c.Validate(); err != nil {
			t.Errorf("profile %q rejected a compliant config: %v", p, err)
		}
	}
}

func TestProfileRetentionFloor(t *testing.T) {
	// Three years clears the EU AI Act's six months and misses the six-year
	// floors, which is the whole reason the profiles are distinguishable.
	c := compliant()
	c.Audit.Retention = Duration(3 * 365 * 24 * time.Hour)

	c.Profile = ProfileEUAIAct
	if err := c.Validate(); err != nil {
		t.Errorf("3 years should clear the Art. 26 floor: %v", err)
	}
	for _, p := range []Profile{ProfileHIPAA, ProfileFINRA} {
		c.Profile = p
		err := c.Validate()
		if err == nil {
			t.Errorf("profile %q accepted 3 years against a 6 year floor", p)
			continue
		}
		if !strings.Contains(err.Error(), "6 years") {
			t.Errorf("profile %q error should name the floor in years, got %v", p, err)
		}
	}
}

func TestProfileZeroRetentionSatisfiesAnyFloor(t *testing.T) {
	// Zero means keep everything. Reading it as "shorter than the floor" would
	// reject the most conservative setting there is.
	c := compliant()
	c.Profile = ProfileHIPAA
	c.Audit.Retention = 0
	if err := c.Validate(); err != nil {
		t.Fatalf("keep-everything should satisfy a retention floor, got %v", err)
	}
}

func TestProfileZeroRetentionStillNeedsAnArchive(t *testing.T) {
	c := compliant()
	c.Profile = ProfileHIPAA
	c.Audit.Retention = 0
	c.Audit.ArchiveCommand = ""
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "archive_command") {
		t.Fatalf("want an archive requirement, got %v", err)
	}
}

func TestProfileRequiresAuditAndItsGuards(t *testing.T) {
	t.Run("audit off", func(t *testing.T) {
		c := compliant()
		c.Profile = ProfileFINRA
		c.Audit = Audit{}
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "audit.enabled") {
			t.Fatalf("want audit.enabled requirement, got %v", err)
		}
	})
	t.Run("audit not required", func(t *testing.T) {
		c := compliant()
		c.Profile = ProfileFINRA
		c.Audit.Required = false
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "audit.required") {
			t.Fatalf("want audit.required requirement, got %v", err)
		}
	})
}

func TestProfilePersonIdentity(t *testing.T) {
	// HIPAA §164.312(d) wants a person; the EU AI Act profile does not, and
	// asserting it there would be inventing an obligation.
	c := compliant()
	c.OIDC = OIDC{}

	c.Profile = ProfileHIPAA
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "oidc.enabled") {
		t.Fatalf("hipaa should require a person, got %v", err)
	}

	c.Profile = ProfileEUAIAct
	if err := c.Validate(); err != nil {
		t.Fatalf("eu-ai-act should not require oidc, got %v", err)
	}
}

func TestProfileRequiredRulesBindOnlyWhenContentIsLogged(t *testing.T) {
	c := compliant()
	c.Profile = ProfileHIPAA

	// Metadata-only: there is no content to redact, so demanding rules would
	// be theatre.
	if err := c.Validate(); err != nil {
		t.Fatalf("metadata-only auditing should not need redaction rules: %v", err)
	}

	c.Audit.LogContent = true
	c.Redaction = Redaction{Rules: []string{"us_ssn"}}
	err := c.Validate()
	if err == nil {
		t.Fatal("want missing-rules error once content is logged")
	}
	for _, want := range []string{"email", "phone_us"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name missing rule %q, got %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "us_ssn") {
		t.Errorf("error should not name a rule that is present: %v", err)
	}

	c.Redaction = Redaction{Rules: []string{"us_ssn", "email", "phone_us"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("all required rules present, got %v", err)
	}
}

func TestLoadForReportSkipsOnlyTheProfile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/c.json"

	// Declares a regime it cannot satisfy. Load must refuse; LoadForReport must
	// not, because that config is exactly the one worth a report.
	write(t, path, `{"profile":"hipaa","audit":{"enabled":true,"path":"/tmp/a.jsonl","required":true,"max_bytes":1048576,"retention":"720h","archive_command":"true"},"oidc":{"enabled":true,"issuer":"https://i","audience":"a"},"teams":[{"name":"platform"}]}`)
	if _, _, err := Load(path); err == nil {
		t.Fatal("Load should refuse a config its profile rejects")
	}
	cfg, found, err := LoadForReport(path)
	if err != nil || !found {
		t.Fatalf("LoadForReport: %v", err)
	}
	if cfg.Profile != ProfileHIPAA {
		t.Errorf("profile should survive the report load, got %q", cfg.Profile)
	}

	// Non-profile errors must still be errors: skipping the assertion is not
	// skipping validation.
	write(t, path, `{"models":[{"name":"x","backend":"nope"}]}`)
	if _, _, err := LoadForReport(path); err == nil {
		t.Fatal("LoadForReport should still reject an unknown backend")
	}
}

func TestProfileIsInThePolicyFingerprint(t *testing.T) {
	// Changing the regime changes what the gateway refuses, which makes it a
	// policy change and puts it on every audit entry.
	a := compliant()
	b := compliant()
	b.Profile = ProfileHIPAA
	if a.PolicyFingerprint() == b.PolicyFingerprint() {
		t.Fatal("declaring a profile should move the policy fingerprint")
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
