package gateway

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	AllowLocalHTTP  bool                      `json:"allow_local_http"`
}

func secureURL(s string, local bool) bool {
	u, e := url.Parse(s)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return u.Scheme == "https" || (local && u.Scheme == "http" && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback()))
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
	if !identifier.MatchString(c.Tenant) || c.DataDir == "" || c.Concurrency < 1 || c.Concurrency > 4096 || c.Rate < 1 || c.Rate > 100000 || c.Burst < 1 || c.Burst > 100000 || c.RetryRate < 1 || c.RetryRate > 10000 || c.MaxAttempts < 1 || c.MaxAttempts > 3 || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 90 || c.QueueSize < 1 || c.QueueSize > 65536 || c.SpoolBytes < 1048576 || c.SpoolBytes > 10737418240 {
		return errors.New("invalid configuration limits")
	}
	if !secureURL(c.ControlURL, c.AllowLocalHTTP) || (c.OTLPURL != "" && !secureURL(c.OTLPURL, c.AllowLocalHTTP)) {
		return errors.New("invalid control/OTLP URL")
	}
	if len(os.Getenv(c.ControlTokenEnv)) < 32 || len(os.Getenv(c.LocalTokenEnv)) < 32 {
		return errors.New("control and local tokens must contain at least 32 bytes")
	}
	if len(c.TrustedKeys) == 0 {
		return errors.New("empty trust store")
	}
	for k, v := range c.TrustedKeys {
		b, e := base64.StdEncoding.Strict().DecodeString(v)
		if !identifier.MatchString(k) || e != nil || len(b) != ed25519.PublicKeySize {
			return errors.New("invalid trust key")
		}
	}
	for name, p := range c.Providers {
		if name != "openai" && name != "anthropic" && name != "gemini" {
			return errors.New("unknown provider")
		}
		if !secureURL(p.URL, c.AllowLocalHTTP) || p.KeyEnv == "" || os.Getenv(p.KeyEnv) == "" {
			return errors.New("invalid provider configuration")
		}
	}
	if len(c.Providers) == 0 {
		return errors.New("no providers")
	}
	return nil
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
