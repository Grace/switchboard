package gateway

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type ProviderConfig struct {
	URL    string `json:"url"`
	KeyEnv string `json:"key_env"`
	// Bedrock only. SigV4 binds a signature to a region, so it cannot be
	// inferred safely from the URL.
	Region string `json:"region,omitempty"`
}
type Config struct {
	Listen          string                    `json:"listen"`
	Tenant          string                    `json:"tenant"`
	DataDir         string                    `json:"data_dir"`
	ControlURL      string                    `json:"control_url"`
	ControlTokenEnv string                    `json:"control_token_env"`
	LocalTokenEnv   string                    `json:"local_token_env"`
	TrustedKeys     map[string]string         `json:"trusted_keys"`
	Providers       map[string]ProviderConfig `json:"providers"`
	Concurrency     int                       `json:"concurrency"`
	Rate            int                       `json:"rate"`
	Burst           int                       `json:"burst"`
	RetryRate       int                       `json:"retry_rate"`
	MaxAttempts     int                       `json:"max_attempts"`
	TimeoutSeconds  int                       `json:"timeout_seconds"`
	QueueSize       int                       `json:"queue_size"`
	SpoolBytes      int64                     `json:"spool_bytes"`
	OTLPURL         string                    `json:"otlp_url"`
	// OTLPMetricsURL is the full OTLP/HTTP metrics endpoint. Empty disables
	// metric export. It is separate from OTLPURL rather than derived from it,
	// because OTLPURL is a complete traces endpoint an operator may have pointed
	// anywhere, and rewriting a path inside it would be guessing. Without this
	// set, nothing collects /metrics: the endpoint is loopback-only and the
	// scraping collector is an opt-in sidecar that most deployments do not run.
	OTLPMetricsURL string             `json:"otlp_metrics_url"`
	Marketplace    *MarketplaceConfig `json:"marketplace,omitempty"`
	AllowLocalHTTP bool               `json:"allow_local_http"`
	// ProviderCheckStrict makes a failed startup provider check hold /readyz at
	// 503 instead of merely warning. Default false: a warning plus the provider
	// being withheld from routing is the right default for a gateway whose whole
	// purpose is to keep serving when one provider cannot.
	ProviderCheckStrict bool `json:"provider_check_strict"`
	// EnablePprof exposes Go runtime profiles for debugging. Off by default, and
	// authenticated when on, because a heap profile contains whatever is in
	// memory: provider API keys read from the environment into request headers,
	// prompt text and completion text. The gateway shares a network namespace
	// with the customer's application, so an unauthenticated pprof would let
	// that application read provider credentials out of this process, which is
	// the one thing the local-token design exists to prevent.
	EnablePprof bool `json:"enable_pprof"`
}

func secureURL(s string, local bool) bool {
	u, e := url.Parse(s)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return u.Scheme == "https" || (local && u.Scheme == "http" && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback()))
}

// UncollectedMetricsWarning returns the warning an operator should see when no
// metrics path is configured, or "" when one is.
//
// The default state is that no counter ever leaves the task: /metrics is bound
// to loopback with the rest of the gateway, and the collector that would scrape
// it is an opt-in container most deployments do not run. Nothing about that is
// visible unless something says it, so the gateway says it on every start rather
// than leaving it to be discovered from a docs page.
func (c Config) UncollectedMetricsWarning() string {
	if c.OTLPMetricsURL != "" {
		return ""
	}
	return "no metrics are being collected; /metrics is loopback only. " +
		"Set otlp_metrics_url to an OTLP/HTTP metrics endpoint, or run the collector " +
		"sidecar from deploy/collector.yaml. See docs/DEPLOYMENT.md."
}

func LoadConfig(path string) (Config, error) {
	var c Config
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	if e = strictJSON(b, &c); e != nil {
		return c, e
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	host, _, e := net.SplitHostPort(c.Listen)
	if e != nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("listen must be a loopback IP:port; use one sidecar per tenant")
	}
	if !identifier.MatchString(c.Tenant) {
		return errors.New("tenant must be a short identifier of letters, digits, dashes or underscores")
	}
	if c.DataDir == "" {
		return errors.New("data_dir is required; it holds the policy cache and the telemetry spool")
	}
	// Each limit reports itself. These were one error naming none of thirteen
	// conditions, which turned a typo into an afternoon.
	for _, l := range []struct {
		name     string
		v        int64
		min, max int64
	}{
		{"concurrency", int64(c.Concurrency), 1, 4096},
		{"rate", int64(c.Rate), 1, 100000},
		{"burst", int64(c.Burst), 1, 100000},
		{"retry_rate", int64(c.RetryRate), 1, 10000},
		{"max_attempts", int64(c.MaxAttempts), 1, 3},
		{"timeout_seconds", int64(c.TimeoutSeconds), 1, 90},
		{"queue_size", int64(c.QueueSize), 1, 65536},
		{"spool_bytes", c.SpoolBytes, 1 << 20, 10 << 30},
	} {
		if l.v < l.min || l.v > l.max {
			return fmt.Errorf("%s is %d; it must be between %d and %d", l.name, l.v, l.min, l.max)
		}
	}
	// An empty control_url is file-only operation: the gateway serves a policy
	// restored from data_dir and never polls. Requiring a control plane that is
	// never contacted put Postgres, migrations, roles, tenants and an admin
	// principal in front of a first real request that needs none of them.
	if c.ControlURL != "" {
		if !secureURL(c.ControlURL, c.AllowLocalHTTP) {
			return errors.New("control_url must be https, or http on loopback with allow_local_http")
		}
		if len(os.Getenv(c.ControlTokenEnv)) < 32 {
			return fmt.Errorf("control_url is set, so %s must hold at least 32 bytes", c.ControlTokenEnv)
		}
	} else if c.ControlTokenEnv != "" {
		return errors.New("control_token_env is set but control_url is empty; remove one or the other")
	}
	if c.OTLPURL != "" && !secureURL(c.OTLPURL, c.AllowLocalHTTP) {
		return errors.New("otlp_url must be https, or http on loopback with allow_local_http")
	}
	if c.OTLPMetricsURL != "" && !secureURL(c.OTLPMetricsURL, c.AllowLocalHTTP) {
		return errors.New("otlp_metrics_url must be https, or http on loopback with allow_local_http")
	}
	if len(os.Getenv(c.LocalTokenEnv)) < 32 {
		return fmt.Errorf("%s must hold at least 32 bytes; it is the token your application presents", c.LocalTokenEnv)
	}
	if len(c.TrustedKeys) == 0 {
		return errors.New("empty trust store")
	}
	for k, v := range c.TrustedKeys {
		if !identifier.MatchString(k) {
			return fmt.Errorf("trust key id %q must be letters, digits, dashes or underscores", k)
		}
		b, e := base64.StdEncoding.Strict().DecodeString(v)
		if e != nil {
			return fmt.Errorf("trust key %q is not valid base64; derive it with 'gateway -public-key'", k)
		}
		if len(b) != ed25519.PublicKeySize {
			return fmt.Errorf("trust key %q decodes to %d bytes; an ed25519 public key is %d", k, len(b), ed25519.PublicKeySize)
		}
	}
	for name, p := range c.Providers {
		if name != "openai" && name != "anthropic" && name != "gemini" && name != "bedrock" {
			return fmt.Errorf("unknown provider %q; supported: openai, anthropic, gemini, bedrock", name)
		}
		if !secureURL(p.URL, c.AllowLocalHTTP) {
			return fmt.Errorf("provider %q: url must be https, or http on loopback with allow_local_http", name)
		}
		if name == "bedrock" {
			// Authenticated by the task's IAM role, so there is no key to
			// require. A region is mandatory instead: SigV4 binds a signature
			// to one, and guessing it produces a signature the service rejects.
			if !identifier.MatchString(p.Region) {
				return errors.New("provider \"bedrock\": region is required; SigV4 binds a signature to one")
			}
			continue
		}
		if p.KeyEnv == "" {
			return fmt.Errorf("provider %q: key_env is required", name)
		}
		if os.Getenv(p.KeyEnv) == "" {
			return fmt.Errorf("provider %q: %s is empty; every configured provider needs its key, even one the policy never routes to", name, p.KeyEnv)
		}
	}
	if len(c.Providers) == 0 {
		return errors.New("no providers configured")
	}
	return c.Marketplace.Validate()
}
func (c Config) Store() *PolicyStore {
	keys := map[string]ed25519.PublicKey{}
	for k, v := range c.TrustedKeys {
		b, _ := base64.StdEncoding.DecodeString(v)
		keys[k] = b
	}
	return &PolicyStore{Tenant: c.Tenant, Path: c.DataDir + "/policy.json", Keys: keys}
}
func client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, IdleConnTimeout: 60 * time.Second, MaxIdleConns: 128, MaxIdleConnsPerHost: 64, MaxConnsPerHost: 256, ForceAttemptHTTP2: true}}
}
func jsonBytes(v any) []byte  { b, _ := json.Marshal(v); return b }
func trimURL(s string) string { return strings.TrimRight(s, "/") }
