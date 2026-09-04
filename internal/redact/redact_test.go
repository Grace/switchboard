package redact

import (
	"strings"
	"testing"
)

func mustNew(t *testing.T, names []string, custom ...Rule) *Redactor {
	t.Helper()
	r, err := New(names, custom)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func TestBuiltinsRedact(t *testing.T) {
	r := mustNew(t, BuiltinNames())
	cases := map[string]string{
		"write to grace@example.com please":  "email",
		"ssn 123-45-6789 on file":            "us_ssn",
		"card 4111 1111 1111 1111 charged":   "credit_card",
		"call (704) 555-0142 tomorrow":       "phone_us",
		"key AKIAIOSFODNN7EXAMPLE leaked":    "aws_access_key_id",
		"Authorization: Bearer abcdef123456": "bearer_token",
	}
	for in, rule := range cases {
		out, counts := r.Apply(in)
		if counts[rule] == 0 {
			t.Errorf("%q: rule %q did not fire (got %q, counts %v)", in, rule, out, counts)
		}
		if !strings.Contains(out, "[redacted:") {
			t.Errorf("%q: no placeholder in %q", in, out)
		}
	}
}

func TestPrivateKeyBlockGoesWhole(t *testing.T) {
	r := mustNew(t, []string{"private_key"})
	in := "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\nlines\n-----END RSA PRIVATE KEY-----\nafter"
	out, counts := r.Apply(in)
	if counts["private_key"] != 1 {
		t.Fatalf("counts = %v", counts)
	}
	if strings.Contains(out, "MIIEow") {
		t.Errorf("key body survived: %q", out)
	}
	if !strings.HasPrefix(out, "before") || !strings.HasSuffix(out, "after") {
		t.Errorf("surrounding text should be intact: %q", out)
	}
}

// The point of the checks: an order id is not a card number, and a redactor
// that eats every long number destroys the correlation ids you need during an
// incident.
func TestCreditCardNeedsLuhnAndIssuerPrefix(t *testing.T) {
	r := mustNew(t, []string{"credit_card"})

	kept := map[string]string{
		"order 1234567890123 shipped":        "fails Luhn",
		"ts 1757001234567890 recorded":       "passes Luhn but no issuer prefix",
		"tracking 9400111899223197428490 ok": "fails both",
	}
	for in, why := range kept {
		out, counts := r.Apply(in)
		if counts["credit_card"] != 0 {
			t.Errorf("%s: %q should survive, got %q", why, in, out)
		}
	}

	for _, card := range []string{
		"4111 1111 1111 1111", // Visa
		"5500 0000 0000 0004", // Mastercard
		"3782 822463 10005",   // Amex
		"6011000990139424",    // Discover
		"2223003122003222",    // Mastercard 2-series
	} {
		if _, counts := r.Apply("card " + card); counts["credit_card"] != 1 {
			t.Errorf("%s should be redacted, counts = %v", card, counts)
		}
	}
}

// A separator is allowed between digits but never after the last one —
// otherwise the match swallows the following space and quietly rewrites text
// that was never sensitive.
func TestRedactionLeavesSurroundingTextAlone(t *testing.T) {
	r := mustNew(t, []string{"credit_card"})
	out, _ := r.Apply("ref 4111 1111 1111 1111 end")
	if out != "ref [redacted:credit_card] end" {
		t.Errorf("got %q, want the trailing space intact", out)
	}
}

// Counts are what you keep when you keep nothing else.
func TestCountsWithoutContent(t *testing.T) {
	r := mustNew(t, []string{"email"})
	_, counts := r.Apply("a@x.com and b@y.com and c@z.com")
	if counts["email"] != 3 {
		t.Errorf("counts = %v, want 3 emails", counts)
	}
}

func TestPlaceholderPreservesStructure(t *testing.T) {
	r := mustNew(t, []string{"email"})
	out, _ := r.Apply("from grace@example.com to ops@example.com")
	if out != "from [redacted:email] to [redacted:email]" {
		t.Errorf("got %q", out)
	}
}

func TestCustomRules(t *testing.T) {
	r := mustNew(t, nil, Rule{Name: "account", Pattern: `ACCT-[0-9]{6}`})
	out, counts := r.Apply("see ACCT-123456 for detail")
	if counts["account"] != 1 || strings.Contains(out, "123456") {
		t.Errorf("out=%q counts=%v", out, counts)
	}
}

// Bad configuration must fail at load, where someone can see it, rather than
// becoming a rule that silently never fires.
func TestBadConfigIsRefusedAtCompile(t *testing.T) {
	if _, err := New([]string{"no_such_rule"}, nil); err == nil {
		t.Error("unknown built-in must be refused")
	}
	if _, err := New([]string{"email", "email"}, nil); err == nil {
		t.Error("duplicate rule must be refused")
	}
	if _, err := New(nil, []Rule{{Name: "bad", Pattern: "([unclosed"}}); err == nil {
		t.Error("uncompilable pattern must be refused")
	}
	if _, err := New(nil, []Rule{{Name: "empty", Pattern: `x*`}}); err == nil {
		t.Error("a pattern matching the empty string must be refused")
	}
	if _, err := New(nil, []Rule{{Pattern: "x"}}); err == nil {
		t.Error("unnamed custom rule must be refused")
	}
}

func TestNilAndEmptyAreSafe(t *testing.T) {
	var r *Redactor
	if out, counts := r.Apply("grace@example.com"); out != "grace@example.com" || counts != nil {
		t.Error("nil redactor should pass content through unchanged")
	}
	r2 := mustNew(t, nil)
	if out, _ := r2.Apply(""); out != "" {
		t.Error("empty input")
	}
}

func TestRulesAreReported(t *testing.T) {
	r := mustNew(t, []string{"email", "us_ssn"})
	if got := strings.Join(r.Rules(), ","); got != "email,us_ssn" {
		t.Errorf("Rules() = %q", got)
	}
}
