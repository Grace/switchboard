package config

import (
	"strings"
	"testing"
)

func base() *Config {
	return &Config{
		Listen: "127.0.0.1:11435",
		Models: []Line{{Name: "m", Backend: BackendBedrock, ModelID: "x"}},
	}
}

func TestAttributionOffIsFine(t *testing.T) {
	if err := base().Validate(); err != nil {
		t.Fatalf("attribution absent should validate: %v", err)
	}
}

// Fail closed only makes sense if there is something to close over.
func TestRequireCallerWithoutEnabledIsRefused(t *testing.T) {
	c := base()
	c.Attribution = Attribution{RequireCaller: true}
	if err := c.Validate(); err == nil {
		t.Fatal("require_caller without enabled must be refused")
	}
}

func TestEnabledNeedsRoleAndTeams(t *testing.T) {
	c := base()
	c.Attribution = Attribution{Enabled: true}
	if err := c.Validate(); err == nil {
		t.Fatal("enabled without role_arn must be refused")
	}

	c.Attribution.RoleARN = "arn:aws:iam::1:role/r"
	if err := c.Validate(); err == nil {
		t.Fatal("enabled with no teams must be refused: nothing to attribute to")
	}
}

func TestDefaultsAreFilledIn(t *testing.T) {
	c := base()
	c.Attribution = Attribution{Enabled: true, RoleARN: "arn:aws:iam::1:role/r"}
	c.Teams = []Team{{Name: "search", Keys: []string{"0123456789abcdef"}}}
	if err := c.Validate(); err != nil {
		t.Fatalf("should validate: %v", err)
	}
	if c.Attribution.TagKey != "team" {
		t.Errorf("tag_key default = %q, want team", c.Attribution.TagKey)
	}
	if c.Attribution.SessionDuration == 0 {
		t.Error("session_duration should default rather than be zero")
	}
}

// A session name AWS rejects is a runtime failure switchboard cannot recover
// from, so it is a config error instead.
func TestTeamNameMustBeAValidSessionName(t *testing.T) {
	for _, name := range []string{"a", "has space", "emoji🙂", ""} {
		c := base()
		c.Attribution = Attribution{Enabled: true, RoleARN: "arn:aws:iam::1:role/r"}
		c.Teams = []Team{{Name: name, Keys: []string{"0123456789abcdef"}}}
		if err := c.Validate(); err == nil {
			t.Errorf("team name %q should be refused", name)
		}
	}
}

func TestKeysMustBeUniqueAndLongEnough(t *testing.T) {
	c := base()
	c.Attribution = Attribution{Enabled: true, RoleARN: "arn:aws:iam::1:role/r"}

	c.Teams = []Team{{Name: "search", Keys: []string{"short"}}}
	if err := c.Validate(); err == nil {
		t.Error("a five-character key should be refused")
	}

	shared := "0123456789abcdef"
	c.Teams = []Team{
		{Name: "search", Keys: []string{shared}},
		{Name: "billing", Keys: []string{shared}},
	}
	if err := c.Validate(); err == nil {
		t.Error("a key shared by two teams makes attribution ambiguous and must be refused")
	}

	c.Teams = []Team{{Name: "search", Keys: nil}}
	if err := c.Validate(); err == nil {
		t.Error("a team with no keys can never be authenticated as")
	}
}

func TestTeamForKey(t *testing.T) {
	teams := []Team{
		{Name: "search", Keys: []string{"key-search-0123456789"}},
		{Name: "billing", Keys: []string{"key-billing-0123456789", "key-billing-alt-01234"}},
	}
	for key, want := range map[string]string{
		"key-search-0123456789":  "search",
		"key-billing-0123456789": "billing",
		"key-billing-alt-01234":  "billing",
	} {
		if got, ok := TeamForKey(teams, key); !ok || got != want {
			t.Errorf("TeamForKey(%q) = %q,%v; want %q", key, got, ok, want)
		}
	}
	if _, ok := TeamForKey(teams, "nope"); ok {
		t.Error("unknown key must not resolve")
	}
	if _, ok := TeamForKey(teams, ""); ok {
		t.Error("empty key must not resolve")
	}
}

// --- redaction and audit -------------------------------------------------

// The rule worth protecting: content logging is the moment prompts stop being
// transient and acquire a retention policy. Doing that with no redaction
// configured is refused, not silently allowed.
func TestLogContentRequiresRedaction(t *testing.T) {
	c := base()
	c.Audit = Audit{Enabled: true, Path: "/tmp/a.jsonl", LogContent: true}
	err := c.Validate()
	if err == nil {
		t.Fatal("log_content with no redaction rules must be refused")
	}
	if !strings.Contains(err.Error(), "refusing") {
		t.Errorf("error should say what it refused: %v", err)
	}

	c.Redaction = Redaction{Rules: []string{"email"}}
	if err := c.Validate(); err != nil {
		t.Errorf("with rules it should validate: %v", err)
	}
}

func TestAuditNeedsPathAndCoherentFlags(t *testing.T) {
	c := base()
	c.Audit = Audit{Enabled: true}
	if err := c.Validate(); err == nil {
		t.Error("audit.enabled with no path must be refused")
	}

	c = base()
	c.Audit = Audit{LogContent: true}
	if err := c.Validate(); err == nil {
		t.Error("log_content without enabled must be refused")
	}
}

// A pattern that does not compile is a startup error in front of whoever wrote
// it, not a rule that silently never fires.
func TestBadRedactionRuleFailsAtLoad(t *testing.T) {
	c := base()
	c.Redaction = Redaction{Rules: []string{"no_such_rule"}}
	if err := c.Validate(); err == nil {
		t.Error("unknown built-in rule must be refused")
	}

	c = base()
	c.Redaction = Redaction{Custom: []CustomRule{{Name: "x", Pattern: "([oops"}}}
	if err := c.Validate(); err == nil {
		t.Error("uncompilable custom pattern must be refused")
	}
}

func TestRedactionBuildsWhatItDeclares(t *testing.T) {
	r := Redaction{Rules: []string{"email"}, Custom: []CustomRule{{Name: "acct", Pattern: `ACCT-\d+`}}}
	red, err := r.Build()
	if err != nil {
		t.Fatal(err)
	}
	out, counts := red.Apply("grace@example.com ACCT-99")
	if counts["email"] != 1 || counts["acct"] != 1 {
		t.Errorf("counts = %v (out %q)", counts, out)
	}
	if r.Empty() {
		t.Error("declared rules should not report empty")
	}
	if !(Redaction{}).Empty() {
		t.Error("no rules should report empty")
	}
}

// --- tls -----------------------------------------------------------------

// Binding a plaintext listener to a public address is a decision, not a
// default, and it should be named at config load rather than at incident.
func TestPlaintextOnAPublicBindIsRefused(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:11435", "10.0.0.5:11435", "[::]:11435"} {
		c := base()
		c.Listen = addr
		if err := c.Validate(); err == nil {
			t.Errorf("listen %q with no TLS must be refused", addr)
		}
	}
}

func TestLoopbackWithoutTLSIsFine(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:11435", "localhost:11435", "[::1]:11435", "127.0.0.5:8080"} {
		c := base()
		c.Listen = addr
		if err := c.Validate(); err != nil {
			t.Errorf("listen %q should be allowed behind a terminator: %v", addr, err)
		}
	}
}

func TestMutualTLSNeedsTLS(t *testing.T) {
	c := base()
	c.TLS = TLS{ClientCAFile: "/etc/ca.pem"}
	if err := c.Validate(); err == nil {
		t.Fatal("a client CA without a server certificate must be refused")
	}
}

func TestTLSFilesMustExist(t *testing.T) {
	c := base()
	c.Listen = "0.0.0.0:11435"
	c.TLS = TLS{CertFile: "/nonexistent/x.crt", KeyFile: "/nonexistent/x.key"}
	if err := c.Validate(); err == nil {
		t.Fatal("missing certificate files must be refused at load, not at bind")
	}
}

func TestTLSHalfConfiguredIsRefused(t *testing.T) {
	c := base()
	c.Listen = "0.0.0.0:11435"
	c.TLS = TLS{CertFile: "/tmp/only.crt"}
	if err := c.Validate(); err == nil {
		t.Fatal("a certificate without a key must be refused")
	}
}
