package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestConfigValidation(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	s := testServer(t, map[string]ProviderConfig{"openai": {URL: "https://api.openai.com", KeyEnv: "PROVIDER_KEY"}})
	c := s.C
	c.TrustedKeys = map[string]string{"test": base64.StdEncoding.EncodeToString(pub)}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.Listen = "0.0.0.0:8080" }, func(c *Config) { c.ControlURL = "http://evil.example" }, func(c *Config) { c.ControlURL = "https://user:pass@evil.example" }, func(c *Config) { c.Concurrency = 0 }, func(c *Config) { c.TimeoutSeconds = 300 }, func(c *Config) { c.TrustedKeys = map[string]string{} }, func(c *Config) { c.LocalTokenEnv = "MISSING_ENV" }} {
		bad := c
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid config accepted")
		}
	}
}
func TestTraceContext(t *testing.T) {
	trace, parent := traceIDs("00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
	if trace != "0123456789abcdef0123456789abcdef" || parent != "0123456789abcdef" {
		t.Fatal("valid context lost")
	}
	trace, parent = traceIDs("00-00000000000000000000000000000000-0000000000000000-01")
	if len(trace) != 32 || parent != "" {
		t.Fatal("invalid context trusted")
	}
}

// The default state is that no counter leaves the task. That is invisible unless
// something says so, so this is the one thing standing between an operator and
// silently having no telemetry at all.
func TestUncollectedMetricsWarning(t *testing.T) {
	if w := (Config{}).UncollectedMetricsWarning(); w == "" {
		t.Error("no warning when nothing is collecting metrics")
	} else {
		for _, want := range []string{"otlp_metrics_url", "collector.yaml", "DEPLOYMENT.md"} {
			if !strings.Contains(w, want) {
				t.Errorf("warning does not mention %q: %s", want, w)
			}
		}
	}
	if w := (Config{OTLPMetricsURL: "https://collector.example.com/v1/metrics"}).UncollectedMetricsWarning(); w != "" {
		t.Errorf("warned despite a configured endpoint: %s", w)
	}
}

// The shipped example could not start: its trust key was the literal string
// REPLACE_WITH_BASE64_ED25519_PUBLIC_KEY, which is not base64, and it declared
// four providers of which three demand a non-empty key variable. An example
// guaranteed to fail is worse than no example, and nothing caught it because
// nothing loaded it.
func TestShippedExampleConfigActuallyStarts(t *testing.T) {
	t.Setenv("LOCAL_TOKEN", strings.Repeat("x", 32))
	t.Setenv("OPENAI_API_KEY", "sk-example-not-real")
	c, err := LoadConfig("../../config.example.json")
	if err != nil {
		t.Fatalf("the shipped example does not validate: %v", err)
	}
	// It should demonstrate the file-only path, which is what LOCAL.md now
	// routes a first real request through.
	if c.ControlURL != "" {
		t.Errorf("example sets control_url=%q; the documented first path is file-only", c.ControlURL)
	}
	if len(c.Providers) != 1 {
		t.Errorf("example declares %d providers; each one costs the reader a key variable "+
			"before the process will start", len(c.Providers))
	}
}

// File-only operation is the documented evaluation path, so the validation that
// used to forbid it is the thing under test.
func TestFileOnlyConfigIsAccepted(t *testing.T) {
	t.Setenv("LOCAL_TOKEN", strings.Repeat("x", 32))
	t.Setenv("PROVIDER_KEY", "k")
	base := func() Config {
		return Config{
			Listen: "127.0.0.1:8080", Tenant: "acme", DataDir: "/data",
			LocalTokenEnv: "LOCAL_TOKEN",
			TrustedKeys:   map[string]string{"k1": base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))},
			Providers:     map[string]ProviderConfig{"openai": {URL: "https://api.openai.com", KeyEnv: "PROVIDER_KEY"}},
			Concurrency:   2, Rate: 10, Burst: 10, RetryRate: 5, MaxAttempts: 3,
			TimeoutSeconds: 30, QueueSize: 16, SpoolBytes: 1 << 20,
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("file-only config rejected: %v", err)
	}
	// A control token with no control plane is a contradiction worth naming
	// rather than silently ignoring.
	c := base()
	c.ControlTokenEnv = "CP_TOKEN"
	if err := c.Validate(); err == nil {
		t.Error("control_token_env with an empty control_url was accepted")
	}
}

// One error naming none of thirteen conditions turned a typo into an afternoon.
func TestEachLimitNamesItself(t *testing.T) {
	t.Setenv("LOCAL_TOKEN", strings.Repeat("x", 32))
	t.Setenv("PROVIDER_KEY", "k")
	for _, tc := range []struct {
		field  string
		break_ func(*Config)
	}{
		{"concurrency", func(c *Config) { c.Concurrency = 0 }},
		{"rate", func(c *Config) { c.Rate = 0 }},
		{"burst", func(c *Config) { c.Burst = 999999 }},
		{"retry_rate", func(c *Config) { c.RetryRate = 0 }},
		{"max_attempts", func(c *Config) { c.MaxAttempts = 9 }},
		{"timeout_seconds", func(c *Config) { c.TimeoutSeconds = 500 }},
		{"queue_size", func(c *Config) { c.QueueSize = 0 }},
		{"spool_bytes", func(c *Config) { c.SpoolBytes = 5 }},
		{"tenant", func(c *Config) { c.Tenant = "not a valid identifier!" }},
		{"data_dir", func(c *Config) { c.DataDir = "" }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			c := Config{
				Listen: "127.0.0.1:8080", Tenant: "acme", DataDir: "/data",
				LocalTokenEnv: "LOCAL_TOKEN",
				TrustedKeys:   map[string]string{"k1": base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))},
				Providers:     map[string]ProviderConfig{"openai": {URL: "https://api.openai.com", KeyEnv: "PROVIDER_KEY"}},
				Concurrency:   2, Rate: 10, Burst: 10, RetryRate: 5, MaxAttempts: 3,
				TimeoutSeconds: 30, QueueSize: 16, SpoolBytes: 1 << 20,
			}
			tc.break_(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("%s accepted an invalid value", tc.field)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error does not name %s: %v", tc.field, err)
			}
		})
	}
}
