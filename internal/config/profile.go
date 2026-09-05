package config

import (
	"crypto/fips140"
	"fmt"
	"strings"

	"github.com/Grace/switchboard/internal/assess"
)

// The regulatory regimes live in internal/assess: a retention floor describes
// the world rather than this gateway, and an adapter assessing somebody else's
// deployment needs the same table. What stays here is enforcement — turning a
// declared regime into a load-time error for *this* config.

// Profile is the declared regulatory regime. See assess for the table.
type Profile = assess.Profile

const (
	ProfileNone    = assess.ProfileNone
	ProfileHIPAA   = assess.ProfileHIPAA
	ProfileFINRA   = assess.ProfileFINRA
	ProfileEUAIAct = assess.ProfileEUAIAct
	Profile800171  = assess.Profile800171
	ProfileFedRAMP = assess.ProfileFedRAMP
	Art26Minimum   = assess.Art26Minimum
)

// ProfileNames lists the declarable regimes.
func ProfileNames() []string { return assess.ProfileNames() }

// validate enforces the declared regime against the rest of the config.
//
// Each failure names the obligation and the citation, because the person
// reading it at startup is usually not the person who chose the number, and
// "audit.retention is too short" without an authority is an argument rather
// than an instruction.
func validateProfile(p Profile, c *Config) error {
	if p == ProfileNone {
		return nil
	}
	r, ok := p.Regime()
	if !ok {
		return fmt.Errorf("profile %q is not one of %s", string(p),
			strings.Join(ProfileNames(), ", "))
	}

	// A record you are obliged to keep is one you are obliged to have.
	if !c.Audit.Enabled {
		return fmt.Errorf("profile %q requires audit.enabled: %s is a record-keeping "+
			"regime and there is no record", p, r.Title)
	}

	// Zero means keep everything, which satisfies any floor. Only a positive
	// retention shorter than the floor is a problem — and it is a real one,
	// because it deletes evidence on a schedule.
	if got := c.Audit.Retention.Duration(); got > 0 && got < r.RetentionFloor {
		return fmt.Errorf("profile %q: audit.retention is %s but %s asks for at "+
			"least %s. Raise it, or set it to 0 to keep everything",
			p, assess.Roughly(got), r.RetentionCite, assess.Roughly(r.RetentionFloor))
	}

	// Retention beyond the point where segments leave this host needs somewhere
	// for them to go. Without an archive, a long retention is a promise the disk
	// makes and cannot keep.
	if c.Audit.MaxBytes > 0 && c.Audit.ArchiveCommand == "" && c.Audit.Retention == 0 {
		return fmt.Errorf("profile %q: audit.retention is 0 (keep everything) with "+
			"no audit.archive_command, so %s of records accumulate on this host. "+
			"Set archive_command to ship closed segments somewhere durable",
			p, assess.Roughly(r.RetentionFloor))
	}

	// An unrecorded completion under a record-keeping regime is the failure the
	// regime exists to prevent.
	if !c.Audit.Required {
		return fmt.Errorf("profile %q requires audit.required: without it a "+
			"completion whose entry cannot be written is served anyway, unrecorded", p)
	}

	if r.RequirePerson && !c.OIDC.Enabled {
		return fmt.Errorf("profile %q requires oidc.enabled: %s wants the record to "+
			"identify a person, and a shared team key identifies a team",
			p, r.PersonCite)
	}

	// Every regime here is an access-control regime. None of them has a notion
	// of an anonymous caller, and this is now assertable independently of AWS
	// role assumption — see attribution.go.
	if !c.Attribution.RequireCaller {
		return fmt.Errorf("profile %q requires attribution.require_caller: %s has "+
			"no notion of an anonymous caller", p, r.Title)
	}

	// Loopback is exempt everywhere else in switchboard because a plaintext
	// bind that cannot leave the host is a reasonable default. Under these
	// regimes it is not: SC-8 and 3.13.8 are about the channel, and an
	// assessor reads a config, not a routing table.
	if r.RequireTLS && c.TLS.CertFile == "" {
		return fmt.Errorf("profile %q requires tls.cert_file and tls.key_file: "+
			"%s treats transmission confidentiality as unconditional, loopback included", p, r.Title)
	}

	// FIPS is a property of the binary rather than of the file, which is
	// precisely why it belongs here: a config that is correct in every other
	// respect, running on a build with non-validated cryptography, is the
	// failure most likely to survive all the way to an assessor.
	if r.RequireFIPS && !fips140.Enabled() {
		return fmt.Errorf("profile %q requires FIPS 140-3 mode, and this binary is "+
			"not running under the Go Cryptographic Module. Build with GOFIPS140=v1.0.0 "+
			"or run with GODEBUG=fips140=on (see docs/profiles.md)", p)
	}

	// Required rules bind only when content is actually being written down.
	// Metadata-only auditing has no content to redact, and demanding rules for
	// it would be theatre.
	if c.Audit.LogContent {
		have := make(map[string]bool, len(c.Redaction.Rules))
		for _, name := range c.Redaction.Rules {
			have[name] = true
		}
		var missing []string
		for _, want := range r.RequiredRules {
			if !have[want] {
				missing = append(missing, want)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("profile %q: audit.log_content is on but redaction.rules "+
				"is missing %s. %s expects these stripped before content is written",
				p, strings.Join(missing, ", "), r.Title)
		}
	}
	return nil
}
