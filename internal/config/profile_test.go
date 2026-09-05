package config

import (
	"crypto/fips140"
	"os"
	"strings"
	"testing"
	"time"
)

// compliant is a config that satisfies every profile, so each test can spoil
// exactly one thing and attribute the failure to that thing.
//
// The one thing it cannot supply is FIPS mode, which is a property of the
// process rather than of the config: see requiresFIPS.
func compliant(t *testing.T) *Config {
	t.Helper()
	dir := t.TempDir()
	crt, key := dir+"/tls.crt", dir+"/tls.key"
	for _, f := range []string{crt, key} {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &Config{
		Listen:      "127.0.0.1:11435",
		TLS:         TLS{CertFile: crt, KeyFile: key},
		OIDC:        OIDC{Enabled: true, Issuer: "https://idp.example", Audience: "switchboard"},
		Teams:       []Team{{Name: "platform", Keys: []string{"a-key-long-enough-to-pass"}}},
		Attribution: Attribution{RequireCaller: true},
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
	c := compliant(t)
	c.Profile = "sox"
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "not one of") {
		t.Fatalf("want unknown-profile error, got %v", err)
	}
}

func TestProfileNoneEnforcesNothing(t *testing.T) {
	c := compliant(t)
	c.Audit.Retention = Duration(time.Hour) // far below every floor
	c.Audit.Required = false
	c.OIDC.Enabled = false
	if err := c.Validate(); err != nil {
		t.Fatalf("no profile should assert nothing, got %v", err)
	}
}

func TestProfileAccepted(t *testing.T) {
	for _, name := range ProfileNames() {
		p := Profile(name)
		if requiresFIPS(p) && !fips140.Enabled() {
			// Not a gap in coverage: TestProfileRequiresFIPS pins the other
			// branch, and CI runs this package a second time under
			// GODEBUG=fips140=on to reach this one.
			t.Logf("skipping %q: needs GODEBUG=fips140=on", p)
			continue
		}
		c := compliant(t)
		c.Profile = p
		if err := c.Validate(); err != nil {
			t.Errorf("profile %q rejected a compliant config: %v", p, err)
		}
	}
}

func requiresFIPS(p Profile) bool {
	r, ok := p.Regime()
	return ok && r.RequireFIPS
}

func TestProfileRequiresFIPS(t *testing.T) {
	c := compliant(t)
	c.Profile = ProfileFedRAMP
	err := c.Validate()
	if fips140.Enabled() {
		if err != nil {
			t.Fatalf("FIPS mode is on, so this should pass: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "FIPS 140-3") {
		t.Fatalf("want a FIPS requirement, got %v", err)
	}
	// The error has to say how to fix it: nobody guesses GOFIPS140.
	if !strings.Contains(err.Error(), "GODEBUG=fips140=on") {
		t.Errorf("error should name the remedy, got %v", err)
	}
}

func TestProfileRequiresTLSEvenOnLoopback(t *testing.T) {
	// Loopback plaintext is fine everywhere else in switchboard. Under these
	// regimes it is not, and that difference is the point of the assertion.
	c := compliant(t)
	c.TLS = TLS{}
	c.Profile = Profile800171
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "tls.cert_file") {
		t.Fatalf("want a TLS requirement, got %v", err)
	}

	c.Profile = ProfileHIPAA
	if err := c.Validate(); err != nil {
		t.Fatalf("hipaa does not assert TLS, so this should pass: %v", err)
	}
}

func TestProfileRetentionFloor(t *testing.T) {
	// Three years clears the EU AI Act's six months and misses the six-year
	// floors, which is the whole reason the profiles are distinguishable.
	c := compliant(t)
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
	c := compliant(t)
	c.Profile = ProfileHIPAA
	c.Audit.Retention = 0
	if err := c.Validate(); err != nil {
		t.Fatalf("keep-everything should satisfy a retention floor, got %v", err)
	}
}

func TestProfileZeroRetentionStillNeedsAnArchive(t *testing.T) {
	c := compliant(t)
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
		c := compliant(t)
		c.Profile = ProfileFINRA
		c.Audit = Audit{}
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "audit.enabled") {
			t.Fatalf("want audit.enabled requirement, got %v", err)
		}
	})
	t.Run("audit not required", func(t *testing.T) {
		c := compliant(t)
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
	c := compliant(t)
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
	c := compliant(t)
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
	a := compliant(t)
	b := compliant(t)
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

// Requiring a credential and assuming a role per caller are different
// decisions. A deployment serving only local models has nothing to attribute
// to a provider bill and every reason to demand a key; the validator used to
// refuse that combination outright.
func TestRequireCallerWorksWithoutAWS(t *testing.T) {
	c := &Config{
		Listen:      "127.0.0.1:11435",
		Teams:       []Team{{Name: "local", Keys: []string{"a-key-long-enough-to-pass"}}},
		Attribution: Attribution{RequireCaller: true}, // Enabled stays false: no AWS
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("require_caller without attribution should be valid: %v", err)
	}
	if c.Attribution.Enabled {
		t.Error("validate must not switch AWS role assumption on by itself")
	}
}

func TestRequireCallerNeedsSomethingToAuthenticateAgainst(t *testing.T) {
	c := &Config{Listen: "127.0.0.1:11435", Attribution: Attribution{RequireCaller: true}}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "nothing can authenticate") {
		t.Fatalf("want a no-credentials error, got %v", err)
	}

	// OIDC alone is enough — no static keys required.
	c.OIDC = OIDC{Enabled: true, Issuer: "https://idp", Audience: "sb"}
	c.Teams = []Team{{Name: "platform"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("oidc should satisfy it: %v", err)
	}
}

func TestRosterIsCheckedWithoutAttribution(t *testing.T) {
	// A short key used to be accepted in silence whenever attribution was off.
	c := &Config{
		Listen: "127.0.0.1:11435",
		Teams:  []Team{{Name: "local", Keys: []string{"tooshort"}}},
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "16 characters") {
		t.Fatalf("want a key-length error with attribution off, got %v", err)
	}
}

func TestSTSNamingRulesOnlyApplyToAWS(t *testing.T) {
	// "a" is too short for an STS session name. That constraint is meaningless
	// for a deployment that never calls AWS and should not be imposed on one.
	c := &Config{
		Listen: "127.0.0.1:11435",
		Teams:  []Team{{Name: "a", Keys: []string{"a-key-long-enough-to-pass"}}},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("local-only deployment should not face STS naming rules: %v", err)
	}

	c.Attribution = Attribution{Enabled: true, RoleARN: "arn:aws:iam::1:role/r"}
	if err := c.Validate(); err == nil {
		t.Error("with AWS on, the STS naming rule should apply")
	}
}

func TestProfileRequiresAuthenticatedCallers(t *testing.T) {
	c := compliant(t)
	c.Profile = ProfileHIPAA
	c.Attribution.RequireCaller = false
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "require_caller") {
		t.Fatalf("a record-keeping regime should refuse anonymous callers, got %v", err)
	}
}
