package config

import (
	"crypto/ed25519"
	"fmt"

	"github.com/Grace/switchboard/internal/approval"
)

// ChangeControl requires that somebody authorised the configuration before the
// gateway runs it.
//
// A model roster, a prompt, a tool grant and a redaction rule are all
// configuration that changes what this system does in production, and almost
// nowhere are they under the change control that covers application code. That
// gap is the usual finding: changes made through a console rather than a
// repository, because nothing forces them through a process.
//
// This forces them, at the only place that can — the thing that reads the
// configuration and refuses to start without an approval for it.
type ChangeControl struct {
	Enabled bool `json:"enabled"`
	// Required refuses to serve an unapproved configuration.
	//
	// Off, an unapproved policy is served with a warning, which makes this a
	// detective control: the report will show which periods ran unapproved. On,
	// it is a preventive one. Both are defensible and they are not the same
	// claim, so this is a decision rather than a default.
	Required bool `json:"required,omitempty"`
	// Minimum valid signatures. Defaults to 1.
	//
	// Two matters more than it looks. One person who can both edit the
	// configuration and sign for it is approving their own change, which is
	// true of every approval scheme and is what a second signature fixes.
	Minimum   int        `json:"minimum,omitempty"`
	Approvers []Approver `json:"approvers,omitempty"`
}

// Approver is one person who may authorise a configuration.
type Approver struct {
	Name string `json:"name"`
	// PublicKey is base64 PKIX, inline — not a path.
	//
	// Inline so the policy fingerprint covers the key material itself. Held as
	// a filename, somebody could swap the file behind a name and the
	// configuration would not change, which is precisely the substitution this
	// mechanism exists to make visible.
	PublicKey string `json:"public_key"`
}

// Roster resolves the configured approvers to keys.
func (c ChangeControl) Roster() (map[string]ed25519.PublicKey, error) {
	if !c.Enabled {
		return nil, nil
	}
	out := make(map[string]ed25519.PublicKey, len(c.Approvers))
	for _, a := range c.Approvers {
		pub, err := approval.DecodePublic(a.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("change_control.approvers[%q]: %w", a.Name, err)
		}
		out[a.Name] = pub
	}
	return out, nil
}

// Threshold is the number of valid signatures a policy needs.
func (c ChangeControl) Threshold() int {
	if c.Minimum < 1 {
		return 1
	}
	return c.Minimum
}

func (c *ChangeControl) validate() error {
	if !c.Enabled {
		return nil
	}
	if len(c.Approvers) == 0 {
		return fmt.Errorf("change_control.enabled with no approvers: nothing could ever " +
			"authorise a configuration, so the gateway would refuse every one of them")
	}
	seen := map[string]bool{}
	for i, a := range c.Approvers {
		if a.Name == "" {
			return fmt.Errorf("change_control.approvers[%d]: an approver needs a name", i)
		}
		if seen[a.Name] {
			return fmt.Errorf("change_control.approvers: %q appears twice, and one person "+
				"signing twice would satisfy a minimum of two", a.Name)
		}
		seen[a.Name] = true
		if _, err := approval.DecodePublic(a.PublicKey); err != nil {
			return fmt.Errorf("change_control.approvers[%q]: %w", a.Name, err)
		}
	}
	if c.Minimum > len(c.Approvers) {
		return fmt.Errorf("change_control.minimum is %d with %d approver(s) configured: "+
			"no configuration could ever be approved", c.Minimum, len(c.Approvers))
	}
	return nil
}
