package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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
