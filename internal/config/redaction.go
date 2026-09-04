package config

import (
	"fmt"

	"github.com/Grace/switchboard/internal/redact"
)

// Redaction declares what to strip before anything is written down.
type Redaction struct {
	// Rules names built-in rules to apply. `switchboard redact -list` prints
	// what is available.
	Rules []string `json:"rules,omitempty"`
	// Custom adds site-specific patterns — account number formats, internal
	// identifiers, anything the built-ins cannot know about.
	Custom []CustomRule `json:"custom,omitempty"`
}

// CustomRule is one site-specific pattern.
type CustomRule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

// Audit configures the record of what was sent where.
type Audit struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path,omitempty"`
	// LogContent stores redacted prompts and completions alongside the
	// metadata. It requires redaction rules: see Validate.
	LogContent bool `json:"log_content,omitempty"`
}

// Empty reports whether any redaction is configured at all.
func (r Redaction) Empty() bool { return len(r.Rules) == 0 && len(r.Custom) == 0 }

// Build compiles the declared rules.
func (r Redaction) Build() (*redact.Redactor, error) {
	if r.Empty() {
		return nil, nil
	}
	custom := make([]redact.Rule, 0, len(r.Custom))
	for _, c := range r.Custom {
		custom = append(custom, redact.Rule{Name: c.Name, Pattern: c.Pattern})
	}
	return redact.New(r.Rules, custom)
}

func (c *Config) validateIO() error {
	// Compile now so a bad pattern is a startup error in front of whoever wrote
	// it, rather than a rule that silently never matches.
	if _, err := c.Redaction.Build(); err != nil {
		return fmt.Errorf("redaction: %w", err)
	}

	if !c.Audit.Enabled {
		if c.Audit.LogContent {
			return fmt.Errorf("audit.log_content is set but audit.enabled is false")
		}
		return nil
	}
	if c.Audit.Path == "" {
		return fmt.Errorf("audit.enabled requires audit.path")
	}
	// The rule worth being loud about: content logging is the moment prompts
	// stop being transient and acquire a retention policy. Doing that with no
	// redaction configured is almost always an accident.
	if err := c.Limits.validate(c.Teams); err != nil {
		return err
	}
	if c.Vault.Enabled {
		if err := c.Vault.validate(c.Redaction, c.Audit); err != nil {
			return err
		}
	}
	if c.Audit.LogContent && c.Redaction.Empty() {
		return fmt.Errorf(
			"audit.log_content is set but no redaction rules are configured: " +
				"refusing to write raw prompts and completions to disk. Add " +
				"redaction.rules, or leave log_content off and keep metadata only")
	}
	return nil
}
