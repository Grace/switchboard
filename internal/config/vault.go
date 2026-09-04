package config

import "fmt"

// Vault seals redacted values so an investigation can recover them.
//
// Enabling it changes what this system retains. Without it, a redacted value is
// gone and the log holds only a token saying something of that shape was there.
// With it, the value exists — encrypted to a key the gateway does not hold, and
// recoverable only by whoever holds the private half.
//
// That is a deliberate trade, not a default, which is why it is off unless
// configured and why the public key must be named explicitly.
type Vault struct {
	Enabled bool `json:"enabled"`
	// Path is the sealed-value store, alongside the audit log.
	Path string `json:"path,omitempty"`
	// PublicKey is a PEM file holding *only* the public half. Handing the
	// gateway a private key is refused at startup.
	PublicKey string `json:"public_key,omitempty"`
}

func (v *Vault) validate(r Redaction, a Audit) error {
	if !v.Enabled {
		return nil
	}
	if v.Path == "" {
		return fmt.Errorf("vault.enabled requires vault.path")
	}
	if v.PublicKey == "" {
		return fmt.Errorf("vault.enabled requires vault.public_key — the gateway " +
			"seals values to a key it cannot read back")
	}
	if r.Empty() {
		return fmt.Errorf("vault.enabled but no redaction rules are configured: " +
			"there would be nothing to seal")
	}
	if !a.Enabled {
		return fmt.Errorf("vault.enabled but audit.enabled is false: sealed values " +
			"are recovered by the token in an audit entry, so a vault without a log " +
			"is unreadable by design")
	}
	return nil
}
