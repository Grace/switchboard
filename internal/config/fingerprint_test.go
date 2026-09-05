package config

import (
	"testing"
	"time"
)

func policyBase() *Config {
	return &Config{
		Listen:       "127.0.0.1:11435",
		DefaultModel: "m",
		Models:       []Line{{Name: "m", Backend: BackendBedrock, ModelID: "x"}},
		Teams:        []Team{{Name: "search", Keys: []string{"key-search-0123456789"}}},
	}
}

func TestSameConfigSameFingerprint(t *testing.T) {
	a, b := policyBase(), policyBase()
	if a.PolicyFingerprint() != b.PolicyFingerprint() {
		t.Error("identical configuration must fingerprint identically")
	}
	if len(a.PolicyFingerprint()) != 12 {
		t.Errorf("fingerprint = %q, want 12 hex characters", a.PolicyFingerprint())
	}
}

// Anything that changes what the gateway allows, redacts, attributes or refuses
// must move the fingerprint.
func TestPolicyChangesMoveTheFingerprint(t *testing.T) {
	base := policyBase().PolicyFingerprint()

	cases := map[string]func(*Config){
		"a new team":              func(c *Config) { c.Teams = append(c.Teams, Team{Name: "billing"}) },
		"a team's limits":         func(c *Config) { c.Teams[0].Limits = TeamLimits{Concurrent: 4} },
		"attribution turned on":   func(c *Config) { c.Attribution.Enabled = true },
		"fail-closed attribution": func(c *Config) { c.Attribution.RequireCaller = true },
		"a redaction rule":        func(c *Config) { c.Redaction.Rules = []string{"email"} },
		"a custom pattern":        func(c *Config) { c.Redaction.Custom = []CustomRule{{Name: "a", Pattern: "b"}} },
		"content logging":         func(c *Config) { c.Audit.LogContent = true },
		"audit becoming required": func(c *Config) { c.Audit.Required = true },
		"retention":               func(c *Config) { c.Audit.Retention = Duration(time.Hour) },
		"sealing turned on":       func(c *Config) { c.Vault.Enabled = true },
		"a spend limit":           func(c *Config) { c.Limits.Default.TokensPerWindow = 100 },
		"mutual TLS":              func(c *Config) { c.TLS.ClientCAFile = "/ca.pem" },
		"a new model":             func(c *Config) { c.Models = append(c.Models, Line{Name: "n"}) },
		"the default model":       func(c *Config) { c.DefaultModel = "other" },
		"an identity provider":    func(c *Config) { c.OIDC.Enabled = true },
	}
	for name, mutate := range cases {
		c := policyBase()
		mutate(c)
		if c.PolicyFingerprint() == base {
			t.Errorf("%s should change the fingerprint", name)
		}
	}
}

// A fingerprint that moves for things that are not policy trains people to
// ignore it.
func TestNonPolicyChangesLeaveItAlone(t *testing.T) {
	base := policyBase().PolicyFingerprint()

	cases := map[string]func(*Config){
		"the listen address": func(c *Config) { c.Listen = "127.0.0.1:9999" },
		"the audit path":     func(c *Config) { c.Audit.Path = "/somewhere/else.jsonl" },
		"the vault path":     func(c *Config) { c.Vault.Path = "/elsewhere.jsonl" },
		"the AWS region":     func(c *Config) { c.Bedrock.Region = "eu-west-1" },
		"an idle timeout":    func(c *Config) { c.Local.IdleTimeout = Duration(time.Minute) },
	}
	for name, mutate := range cases {
		c := policyBase()
		mutate(c)
		if c.PolicyFingerprint() != base {
			t.Errorf("%s is not a policy change and should not move the fingerprint", name)
		}
	}
}

// A rotated key is not a policy change, and a fingerprint is not a place to put
// a digest of a secret. Adding or removing one is a change; altering its value
// is not.
func TestKeyRotationIsNotAPolicyChangeButKeyCountIs(t *testing.T) {
	base := policyBase()
	rotated := policyBase()
	rotated.Teams[0].Keys = []string{"key-search-9999999999"}
	if base.PolicyFingerprint() != rotated.PolicyFingerprint() {
		t.Error("rotating a key should not read as a policy change")
	}

	added := policyBase()
	added.Teams[0].Keys = append(added.Teams[0].Keys, "key-search-second-0123")
	if added.PolicyFingerprint() == base.PolicyFingerprint() {
		t.Error("adding a second credential to a team is a policy change")
	}
}

func TestFingerprintIsStableAcrossRuns(t *testing.T) {
	c := policyBase()
	first := c.PolicyFingerprint()
	for i := 0; i < 50; i++ {
		if c.PolicyFingerprint() != first {
			t.Fatal("fingerprint is not deterministic")
		}
	}
}
