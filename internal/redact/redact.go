// Package redact removes sensitive content before it is written down.
//
// The distinction that matters here is between containment and disclosure. A
// sandbox, a VPC, a private subnet — those control what a process may reach.
// None of them help with content the gateway itself writes to a log, a trace,
// or a telemetry exporter, because that path is open on purpose.
//
// Application-side masking is the usual advice, and it is a hope rather than a
// control: it is correct only if every team configured their SDK correctly, and
// nobody can prove that to an auditor. A gateway is the one place in the path
// that cannot be bypassed, which makes it the only place redaction is a control
// rather than a convention.
package redact

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Rule is one class of thing worth removing.
type Rule struct {
	// Name appears in the replacement and in the audit counts.
	Name string
	// Pattern is an RE2 expression.
	Pattern string

	re *regexp.Regexp
	// confirm rejects a syntactic match that fails a semantic check, which is
	// how the card rule avoids redacting every long number.
	confirm func(string) bool
}

// Built-in rules. Each is opt-in by name: a redactor that removes everything it
// can imagine would make logs useless, and the point is to keep them readable.
func builtins() map[string]Rule {
	return map[string]Rule{
		"email": {
			Name:    "email",
			Pattern: `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
		},
		"us_ssn": {
			Name:    "us_ssn",
			Pattern: `\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`,
		},
		"credit_card": {
			Name:    "credit_card",
			Pattern: `\b[0-9](?:[ \-]?[0-9]){12,18}\b`,
			confirm: isCard,
		},
		"phone_us": {
			Name:    "phone_us",
			Pattern: `\b(?:\+1[ .\-]?)?\(?[0-9]{3}\)?[ .\-]?[0-9]{3}[ .\-]?[0-9]{4}\b`,
		},
		"aws_access_key_id": {
			Name:    "aws_access_key_id",
			Pattern: `\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b`,
		},
		"bearer_token": {
			Name:    "bearer_token",
			Pattern: `(?i)bearer\s+[A-Za-z0-9\-._~+/]{8,}=*`,
		},
		"private_key": {
			Name:    "private_key",
			Pattern: `(?s)-----BEGIN[A-Z ]*PRIVATE KEY-----.*?-----END[A-Z ]*PRIVATE KEY-----`,
		},
	}
}

// BuiltinNames lists the rules available by name, sorted.
func BuiltinNames() []string {
	b := builtins()
	out := make([]string, 0, len(b))
	for name := range b {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Redactor applies a fixed set of rules.
type Redactor struct {
	rules []Rule
}

// New compiles a redactor from built-in rule names and custom patterns.
//
// Compilation happens here, at config load, rather than at first request. A
// pattern that does not compile is a configuration error someone can see and
// fix, not a redaction that silently never fires.
func New(builtinNames []string, custom []Rule) (*Redactor, error) {
	avail := builtins()
	var rules []Rule
	seen := map[string]bool{}

	for _, name := range builtinNames {
		r, ok := avail[name]
		if !ok {
			return nil, fmt.Errorf("unknown built-in redaction rule %q (have %s)",
				name, strings.Join(BuiltinNames(), ", "))
		}
		if seen[name] {
			return nil, fmt.Errorf("redaction rule %q listed twice", name)
		}
		seen[name] = true
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("built-in rule %q: %w", name, err)
		}
		r.re = re
		rules = append(rules, r)
	}

	for _, c := range custom {
		if c.Name == "" {
			return nil, fmt.Errorf("custom redaction rule needs a name")
		}
		if seen[c.Name] {
			return nil, fmt.Errorf("redaction rule %q listed twice", c.Name)
		}
		seen[c.Name] = true
		if c.Pattern == "" {
			return nil, fmt.Errorf("custom rule %q needs a pattern", c.Name)
		}
		re, err := regexp.Compile(c.Pattern)
		if err != nil {
			return nil, fmt.Errorf("custom rule %q: %w", c.Name, err)
		}
		// An expression that matches empty would replace between every rune.
		if re.MatchString("") {
			return nil, fmt.Errorf("custom rule %q matches the empty string", c.Name)
		}
		c.re = re
		rules = append(rules, c)
	}

	return &Redactor{rules: rules}, nil
}

// Apply returns the redacted text and a count of what was removed, by rule.
//
// The counts are the useful part when content is not being stored at all: you
// can record that three email addresses passed through without recording any of
// them.
func (r *Redactor) Apply(s string) (string, map[string]int) {
	if r == nil || len(r.rules) == 0 || s == "" {
		return s, nil
	}
	counts := map[string]int{}
	for _, rule := range r.rules {
		placeholder := "[redacted:" + rule.Name + "]"
		s = rule.re.ReplaceAllStringFunc(s, func(m string) string {
			if rule.confirm != nil && !rule.confirm(m) {
				return m
			}
			counts[rule.Name]++
			return placeholder
		})
	}
	if len(counts) == 0 {
		return s, nil
	}
	return s, counts
}

// Rules reports the rule names in the order they are applied.
func (r *Redactor) Rules() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.rules))
	for _, x := range r.rules {
		out = append(out, x.Name)
	}
	return out
}

// isCard confirms that a run of digits is plausibly a card number rather than
// an order id, a tracking number, or a timestamp.
//
// Luhn alone is not enough: it is a typo checksum, so one in ten arbitrary
// numbers passes it — a 16-digit nanosecond timestamp has a real chance. Real
// cards also begin with an assigned issuer prefix, and checking both costs
// nothing in recall, because every genuine card satisfies both by
// construction.
func isCard(s string) bool {
	digits := onlyDigits(s)
	return len(digits) >= 13 && len(digits) <= 19 && hasIssuerPrefix(digits) && luhn(s)
}

func onlyDigits(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// Assigned issuer identification ranges, per ISO/IEC 7812.
func hasIssuerPrefix(d string) bool {
	two := d[:2]
	switch {
	case d[0] == '4': // Visa
		return true
	case two >= "51" && two <= "55", two == "35": // Mastercard, JCB
		return true
	case two == "34" || two == "37": // American Express
		return true
	case two == "30" || two == "36" || two == "38" || two == "39": // Diners
		return true
	case strings.HasPrefix(d, "6011") || two == "65": // Discover
		return true
	case len(d) >= 4: // Mastercard 2-series, 2221-2720
		if four := d[:4]; four >= "2221" && four <= "2720" {
			return true
		}
	}
	return false
}

// luhn confirms that a run of digits is plausibly a card number rather than an
// order id, a timestamp, or a phone number written without separators.
func luhn(s string) bool {
	var digits []int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}
