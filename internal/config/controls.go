package config

import (
	"crypto/fips140"
	"fmt"
)

// Control assessment against the running configuration.
//
// docs/controls.md says what switchboard is capable of. This says what your
// deployment is actually doing, which is a different and more useful question:
// every control below is one somebody can turn off, and most of the interesting
// findings in a security review are features that exist and are not enabled.
//
// The honest limit is that a config file is a statement of intent. It shows
// that redaction rules are declared, not that they match your data; that an
// archive command is set, not that the bucket it writes to is immutable. Rows
// that depend on facts outside the file are reported as such rather than
// counted as met, and Yours() lists the obligations no config can evidence.

// ControlStatus is how a single objective came out.
type ControlStatus string

const (
	StatusMet          ControlStatus = "met"
	StatusPartial      ControlStatus = "partial"
	StatusUnmet        ControlStatus = "unmet"
	StatusNotAddressed ControlStatus = "not addressed"
)

// Symbol renders a status the way docs/controls.md does.
func (s ControlStatus) Symbol() string {
	switch s {
	case StatusMet:
		return "OK"
	case StatusPartial:
		return "~~"
	case StatusUnmet:
		return "XX"
	default:
		return "--"
	}
}

// Control is one assessed objective.
type Control struct {
	Section   string        `json:"section"`
	Objective string        `json:"objective"`
	Refs      string        `json:"refs"`
	Status    ControlStatus `json:"status"`
	Evidence  string        `json:"evidence"`
}

// ControlReport is the whole assessment.
type ControlReport struct {
	Profile  Profile   `json:"profile"`
	Regime   string    `json:"regime,omitempty"`
	Controls []Control `json:"controls"`
	// Yours are obligations this regime places on you that no configuration
	// file can evidence. They are not failures; they are the part of the review
	// switchboard cannot do for you.
	Yours []string `json:"yours,omitempty"`
}

// Counts totals the statuses, for a summary line.
func (r ControlReport) Counts() map[ControlStatus]int {
	out := make(map[ControlStatus]int, 4)
	for _, c := range r.Controls {
		out[c.Status]++
	}
	return out
}

// Unmet reports whether anything came out unmet, which is what makes the
// command usable in CI.
func (r ControlReport) Unmet() bool {
	for _, c := range r.Controls {
		if c.Status == StatusUnmet {
			return true
		}
	}
	return false
}

// Controls assesses the configuration. A profile, when set, tightens some rows
// from advisory to unmet and adds its own citations.
func (c *Config) Controls() ControlReport {
	rep := ControlReport{Profile: c.Profile}
	reg, hasRegime := c.Profile.Regime()
	if hasRegime {
		rep.Regime = reg.Title
		rep.Yours = reg.Unaddressed
	}

	add := func(section, objective, refs string, status ControlStatus, evidence string) {
		rep.Controls = append(rep.Controls, Control{
			Section: section, Objective: objective, Refs: refs,
			Status: status, Evidence: evidence,
		})
	}

	// ---- Access control and authentication ----
	const access = "Access control and authentication"

	switch {
	case c.OIDC.Enabled:
		add(access, "Callers are authenticated before use",
			"SOC 2 CC6.1 · ISO 27001 A.5.15 · HIPAA §164.312(d)", StatusMet,
			fmt.Sprintf("OIDC against %s. Tokens expire on their own.", c.OIDC.Issuer))
	case len(c.Teams) > 0:
		add(access, "Callers are authenticated before use",
			"SOC 2 CC6.1 · ISO 27001 A.5.15 · HIPAA §164.312(d)", StatusPartial,
			fmt.Sprintf("%d team keys, compared in constant time. Shared credentials: "+
				"they name a team, not a person, and revoking one is a manual edit.", len(c.Teams)))
	default:
		add(access, "Callers are authenticated before use",
			"SOC 2 CC6.1 · ISO 27001 A.5.15 · HIPAA §164.312(d)", StatusUnmet,
			"No OIDC issuer and no teams configured. Every request is anonymous.")
	}

	if c.Attribution.RequireCaller {
		add(access, "Unauthenticated access is denied", "SOC 2 CC6.1 · NIST AC-3",
			StatusMet, "attribution.require_caller is on: an unattributed request is 401.")
	} else {
		add(access, "Unauthenticated access is denied", "SOC 2 CC6.1 · NIST AC-3",
			StatusUnmet, "attribution.require_caller is off, so a request presenting no "+
				"credential is served against the gateway's own role.")
	}

	personRefs := "SOC 2 CC7.2 · NIST AU-3"
	if hasRegime && reg.RequirePerson {
		personRefs = reg.PersonCite
	}
	if c.OIDC.Enabled {
		add(access, "Records identify a person, not a shared credential", personRefs,
			StatusMet, "Token subject is recorded alongside the team.")
	} else if hasRegime && reg.RequirePerson {
		add(access, "Records identify a person, not a shared credential", personRefs,
			StatusUnmet, "oidc.enabled is off. Entries carry a team only, and this "+
				"regime asks the record to identify who acted.")
	} else {
		add(access, "Records identify a person, not a shared credential", personRefs,
			StatusPartial, "oidc.enabled is off. Entries carry a team only.")
	}

	if c.Attribution.Enabled && c.Attribution.RoleARN != "" {
		add(access, "Least privilege for provider credentials", "SOC 2 CC6.3 · NIST AC-6",
			StatusMet, "A role is assumed per caller; provider permissions live on the "+
				"assumed role rather than the gateway's own. Trust policy scope is yours.")
	} else {
		add(access, "Least privilege for provider credentials", "SOC 2 CC6.3 · NIST AC-6",
			StatusPartial, "attribution is off, so every call uses the gateway's own "+
				"principal — and the provider's bill cannot distinguish teams.")
	}

	// ---- Audit and accountability ----
	const audit = "Audit and accountability"

	if !c.Audit.Enabled {
		add(audit, "Security-relevant events are recorded",
			"SOC 2 CC7.2 · HIPAA §164.312(b) · EU AI Act Art. 12", StatusUnmet,
			"audit.enabled is false. Nothing is written down.")
	} else {
		add(audit, "Security-relevant events are recorded",
			"SOC 2 CC7.2 · HIPAA §164.312(b) · EU AI Act Art. 12", StatusMet,
			fmt.Sprintf("One JSONL entry per completion at %s.", c.Audit.Path))

		add(audit, "Records are protected from modification",
			"SOC 2 CC7.2 · ISO 27001 A.8.15 · NIST AU-9", StatusPartial,
			"Hash-chained across segments, so alteration, deletion and reordering are "+
				"detectable. Tail truncation is not detectable from the file alone, and a "+
				"key holder can rewrite history. Anchor the head externally.")

		if c.Audit.Required {
			add(audit, "Auditing cannot fail silently", "SOC 2 CC7.2 · NIST AU-5",
				StatusMet, "audit.required is on: a completion that cannot be recorded is 503.")
		} else {
			add(audit, "Auditing cannot fail silently", "SOC 2 CC7.2 · NIST AU-5",
				StatusUnmet, "audit.required is off. A completion whose entry fails to "+
					"write is served anyway, unrecorded.")
		}

		if v := c.Audit.VerifyInterval.Duration(); v > 0 {
			add(audit, "Logs are reviewed", "SOC 2 CC7.2 · NIST AU-6", StatusMet,
				fmt.Sprintf("Chain verified at startup and every %s.", roughly(v)))
		} else {
			add(audit, "Logs are reviewed", "SOC 2 CC7.2 · NIST AU-6", StatusPartial,
				"Chain verified at startup only. Set audit.verify_interval to re-walk it "+
					"while the process is up.")
		}

		// Retention is the row a profile changes most.
		floor := Art26Minimum
		cite := "EU AI Act Art. 26"
		if hasRegime {
			floor, cite = reg.RetentionFloor, reg.RetentionCite
		}
		got := c.Audit.Retention.Duration()
		switch {
		case got == 0 && c.Audit.ArchiveCommand == "":
			add(audit, "Log retention", cite, StatusPartial,
				fmt.Sprintf("Retention is 0 (keep everything) with no archive command, so "+
					"%s of records accumulate on this host and the disk is the only copy.",
					roughly(floor)))
		case got == 0:
			add(audit, "Log retention", cite, StatusMet,
				"Retention is 0 (keep everything); closed segments are archived before "+
					"anything is pruned.")
		case got < floor:
			add(audit, "Log retention", cite, StatusUnmet,
				fmt.Sprintf("audit.retention is %s; %s asks for at least %s.",
					roughly(got), cite, roughly(floor)))
		case c.Audit.ArchiveCommand == "":
			add(audit, "Log retention", cite, StatusPartial,
				fmt.Sprintf("audit.retention of %s clears the floor, but with no "+
					"archive_command this host is the archive and retention deletes "+
					"evidence rather than draining a buffer.", roughly(got)))
		default:
			note := ""
			if hasRegime && reg.RetentionIsParameter {
				note = " That floor is switchboard's default, not a statutory number: " +
					"this regime leaves the period organization-defined, so confirm " +
					"it against your own records schedule."
			}
			add(audit, "Log retention", cite, StatusMet,
				fmt.Sprintf("audit.retention is %s, above the %s floor, and closed "+
					"segments are archived before pruning.%s",
					roughly(got), roughly(floor), note))
		}
	}

	// ---- Data protection ----
	const data = "Data protection"

	switch {
	case c.Redaction.Empty():
		add(data, "Sensitive data is not written to logs",
			"SOC 2 CC6.7 · ISO 27001 A.8.11 · HIPAA §164.312(a)(2)(iv)", StatusUnmet,
			"No redaction rules are configured.")
	case !c.Audit.LogContent:
		add(data, "Sensitive data is not written to logs",
			"SOC 2 CC6.7 · ISO 27001 A.8.11 · HIPAA §164.312(a)(2)(iv)", StatusMet,
			fmt.Sprintf("%d rules configured, and log_content is off — metadata only, "+
				"so no prompt text reaches the log at all.",
				len(c.Redaction.Rules)+len(c.Redaction.Custom)))
	default:
		add(data, "Sensitive data is not written to logs",
			"SOC 2 CC6.7 · ISO 27001 A.8.11 · HIPAA §164.312(a)(2)(iv)", StatusPartial,
			fmt.Sprintf("%d rules applied inside the log writer, so no call site can skip "+
				"them. Pattern-based: structured identifiers only, not a name or a "+
				"condition described in prose.",
				len(c.Redaction.Rules)+len(c.Redaction.Custom)))
	}

	switch {
	case c.TLS.CertFile != "" && c.TLS.ClientCAFile != "":
		add(data, "Encryption in transit", "SOC 2 CC6.7 · HIPAA §164.312(e)(1) · NIST SC-8",
			StatusMet, "Listener serves TLS 1.2+ and requires a client certificate signed "+
				"by the configured authority.")
	case c.TLS.CertFile != "":
		add(data, "Encryption in transit", "SOC 2 CC6.7 · HIPAA §164.312(e)(1) · NIST SC-8",
			StatusMet, "Listener serves TLS 1.2+. No client certificate is required.")
	case hasRegime && reg.RequireTLS:
		add(data, "Encryption in transit", "NIST SC-8 · 800-171 3.13.8", StatusUnmet,
			fmt.Sprintf("No tls.cert_file, so %s is plaintext. This regime treats "+
				"transmission confidentiality as unconditional, loopback included.", c.Listen))
	default:
		add(data, "Encryption in transit", "SOC 2 CC6.7 · HIPAA §164.312(e)(1) · NIST SC-8",
			StatusPartial, fmt.Sprintf("No tls.cert_file, so %s is plaintext. Provider "+
				"calls still use the SDK's TLS, and a non-loopback plaintext bind is "+
				"refused at load.", c.Listen))
	}

	// Validated cryptography is a property of this binary, not of the file, so
	// it is the one row here that would still be true if the config were empty
	// — and the one most likely to be assumed rather than checked.
	switch {
	case fips140.Enabled():
		add(data, "Cryptography is FIPS-validated", "NIST SC-13 · 800-171 3.13.11 · FIPS 140-3",
			StatusMet, "Running under the Go Cryptographic Module (CMVP certificate #5247). "+
				"GODEBUG=fips140=only additionally makes non-approved algorithms fail rather "+
				"than fall back.")
	case hasRegime && reg.RequireFIPS:
		add(data, "Cryptography is FIPS-validated", "NIST SC-13 · 800-171 3.13.11 · FIPS 140-3",
			StatusUnmet, "This binary is not in FIPS mode. Build with GOFIPS140=v1.0.0 or run "+
				"with GODEBUG=fips140=on.")
	default:
		add(data, "Cryptography is FIPS-validated", "NIST SC-13 · FIPS 140-3",
			StatusNotAddressed, "Not in FIPS mode, and this regime does not ask for it. "+
				"GODEBUG=fips140=on enables it if a customer does.")
	}

	if c.Vault.Enabled {
		add(data, "Redacted values are recoverable under control",
			"NIST SC-28 · HIPAA §164.312(a)(2)(iv)", StatusMet,
			"Sealed with AES-256-GCM under an RSA-OAEP-wrapped key the gateway holds no "+
				"private half of. Recovery needs the offline key.")
	} else {
		add(data, "Redacted values are recoverable under control",
			"NIST SC-28 · HIPAA §164.312(a)(2)(iv)", StatusNotAddressed,
			"Vault is off. Redacted values are discarded, which is the safe default and "+
				"means an investigation cannot recover them.")
	}

	// ---- Availability ----
	if c.Limits.Enabled {
		add("Availability and operations", "Resource limits",
			"SOC 2 A1.1 · NIST SC-5 · ATLAS AML.M0004", StatusMet,
			"Per-team request rate, concurrency and token budget, keyed on the resolved "+
				"caller identity.")
	} else {
		add("Availability and operations", "Resource limits",
			"SOC 2 A1.1 · NIST SC-5 · ATLAS AML.M0004", StatusUnmet,
			"limits.enabled is off. Nothing bounds what one caller can consume.")
	}

	return rep
}
