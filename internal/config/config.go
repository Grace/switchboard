// Package config loads switchboard's configuration file.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Backend identifiers usable in a Line.
const (
	BackendLocal   = "local"
	BackendBedrock = "bedrock"
)

// Line is one routable model as configured: everything needed to reach it,
// whether that is weights on disk or a model id in a region.
type Line struct {
	// Name is what callers ask for, e.g. "qwen3-8b".
	Name string `json:"name"`
	// Backend is "local" or "bedrock".
	Backend string `json:"backend"`
	// Path is the .gguf file, for local models. Supports ~ expansion.
	Path string `json:"path,omitempty"`
	// ModelID is the Bedrock model id or inference profile ARN.
	ModelID string `json:"model_id,omitempty"`
	// Context is the context window to allocate, for local models.
	Context int `json:"context,omitempty"`
	// GPULayers overrides automatic device selection for local models.
	// 0 forces CPU-only; a large number offloads everything.
	GPULayers *int `json:"gpu_layers,omitempty"`
	// Args are extra flags passed straight through to llama-server.
	Args []string `json:"args,omitempty"`
}

// Local configures the on-device backend.
type Local struct {
	// Server is the llama-server binary; looked up on PATH if unset.
	Server string `json:"server,omitempty"`
	// Device is auto, metal, cuda, or cpu.
	Device string `json:"device,omitempty"`
	// IdleTimeout unloads a model after this long without a request.
	// "0" keeps models resident forever.
	IdleTimeout Duration `json:"idle_timeout,omitempty"`
}

// Bedrock configures the AWS backend. Credentials come from the normal chain:
// environment, shared config, SSO, instance role.
type Bedrock struct {
	Region  string `json:"region,omitempty"`
	Profile string `json:"profile,omitempty"`
}

// Config is the whole file.
type Config struct {
	// Listen is the server's bind address.
	Listen string `json:"listen"`
	// DefaultModel answers requests that name no model.
	DefaultModel string  `json:"default_model,omitempty"`
	Local        Local   `json:"local"`
	Bedrock      Bedrock `json:"bedrock"`
	Models       []Line  `json:"models"`

	// Profile declares the regulatory regime this deployment operates under,
	// which turns the advisory audit floors into load-time errors. See profile.go.
	Profile Profile `json:"profile,omitempty"`
	// Attribution splits provider spend back out by caller. See attribution.go.
	Attribution Attribution `json:"attribution,omitempty"`
	// Redaction strips sensitive content before anything is written down.
	Redaction Redaction `json:"redaction,omitempty"`
	// Audit records what was sent to which provider.
	Audit Audit `json:"audit,omitempty"`
	// Vault seals redacted values for recovery during an investigation.
	Vault Vault `json:"vault,omitempty"`
	// Limits bounds what callers may consume.
	Limits Limits `json:"limits,omitempty"`
	// TLS secures the listener itself.
	TLS TLS `json:"tls,omitempty"`
	// Telemetry exports aggregates over OTLP.
	Telemetry Telemetry `json:"telemetry,omitempty"`
	// Teams are the attribution units and their API keys.
	Teams []Team `json:"teams,omitempty"`
	// OIDC trusts an identity provider instead of shared keys.
	OIDC OIDC `json:"oidc,omitempty"`
}

// Duration is a time.Duration that round-trips as a JSON string ("10m").
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"10m\": %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// Duration converts back to the standard type.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// DefaultPath is ~/.switchboard/switchboard.json, overridable with SWITCHBOARD_CONFIG.
func DefaultPath() string {
	if p := os.Getenv("SWITCHBOARD_CONFIG"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "switchboard.json"
	}
	return filepath.Join(home, ".switchboard", "switchboard.json")
}

// Default is the config used when no file exists: an empty roster, sensible
// server settings, and nothing that assumes AWS is reachable.
func Default() *Config {
	return &Config{
		Listen: "127.0.0.1:11435",
		Local: Local{
			Device:      "auto",
			IdleTimeout: Duration(10 * time.Minute),
		},
		Bedrock: Bedrock{Region: os.Getenv("AWS_REGION")},
	}
}

// Load reads path, falling back to Default when the file does not exist. The
// returned bool reports whether a file was actually found.
func Load(path string) (*Config, bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Default(), false, nil
	}
	if err != nil {
		return nil, false, err
	}

	cfg := Default()
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, true, fmt.Errorf("%s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, true, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, true, nil
}

// Validate catches the config mistakes that would otherwise surface as a
// confusing runtime error much later.
func (c *Config) Validate() error {
	seen := make(map[string]bool, len(c.Models))
	for i, m := range c.Models {
		switch {
		case m.Name == "":
			return fmt.Errorf("models[%d]: name is required", i)
		case seen[m.Name]:
			return fmt.Errorf("models[%d]: duplicate model name %q", i, m.Name)
		}
		seen[m.Name] = true

		switch m.Backend {
		case BackendLocal:
			if m.Path == "" {
				return fmt.Errorf("model %q: local models need a path to a .gguf file", m.Name)
			}
		case BackendBedrock:
			if m.ModelID == "" {
				return fmt.Errorf("model %q: bedrock models need a model_id", m.Name)
			}
		case "":
			return fmt.Errorf("model %q: backend is required (%q or %q)", m.Name, BackendLocal, BackendBedrock)
		default:
			return fmt.Errorf("model %q: unknown backend %q", m.Name, m.Backend)
		}
	}

	if c.DefaultModel != "" && !seen[c.DefaultModel] {
		return fmt.Errorf("default_model %q is not in models", c.DefaultModel)
	}
	switch c.Local.Device {
	case "", "auto", "metal", "cuda", "gpu", "cpu":
	default:
		return fmt.Errorf("local.device %q: want auto, metal, cuda, or cpu", c.Local.Device)
	}
	// Each concern validates explicitly and unconditionally. An earlier version
	// hung several of these off validateIO, which returns early when auditing
	// is disabled — so limits, TLS and vault checks silently never ran for
	// anyone who had not turned auditing on.
	if err := c.Attribution.validate(c.Teams, c.OIDC.Enabled); err != nil {
		return err
	}
	if err := c.OIDC.validate(c.Teams); err != nil {
		return err
	}
	if err := c.Limits.validate(c.Teams); err != nil {
		return err
	}
	if err := c.TLS.validate(c.Listen); err != nil {
		return err
	}
	if err := c.Telemetry.validate(); err != nil {
		return err
	}
	if err := c.Vault.validate(c.Redaction, c.Audit); err != nil {
		return err
	}
	if err := c.validateIO(); err != nil {
		return err
	}
	// Last, deliberately. A profile asserts obligations over a configuration
	// that already has to make sense on its own terms, and "audit.enabled
	// requires audit.path" is a more useful first error than a citation.
	return c.Profile.validate(c)
}

// Save writes the config, creating the parent directory if needed.
func (c *Config) Save(path string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// ModelsFor returns the lines bound to one backend.
func (c *Config) ModelsFor(backend string) []Line {
	var out []Line
	for _, m := range c.Models {
		if m.Backend == backend {
			out = append(out, m)
		}
	}
	return out
}

// ExpandPath resolves a leading ~ against the user's home directory.
func ExpandPath(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}
