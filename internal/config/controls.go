package config

import (
	"crypto/fips140"

	"github.com/Grace/switchboard/internal/assess"
)

// switchboard's own adapter into the neutral assessment.
//
// The scoring lives in internal/assess so that the same rules apply to a
// LiteLLM or Azure OpenAI deployment read from the outside. All this file does
// is answer assess's questions about a switchboard config — and because it is
// reading a file it fully understands, it never answers Unknown.

// Types are re-exported so callers do not have to know where the table lives.
type (
	ControlStatus = assess.ControlStatus
	Control       = assess.Control
	ControlReport = assess.ControlReport
)

const (
	StatusMet          = assess.StatusMet
	StatusPartial      = assess.StatusPartial
	StatusUnmet        = assess.StatusUnmet
	StatusNotAddressed = assess.StatusNotAddressed
	StatusUnknown      = assess.StatusUnknown
)

// Deployment describes this configuration in assess's terms.
func (c *Config) Deployment() assess.Deployment {
	return assess.Deployment{
		Source:  "switchboard",
		Profile: c.Profile,
		Auth: assess.Auth{
			OIDC:                   assess.Bool(c.OIDC.Enabled),
			Issuer:                 c.OIDC.Issuer,
			StaticKeyTeams:         teamsWithKeys(c.Teams),
			DenyUnauthenticated:    assess.Bool(c.Attribution.RequireCaller),
			PerCallerProviderCreds: assess.Bool(c.Attribution.Enabled && c.Attribution.RoleARN != ""),
			CloudProvider:          assess.Bool(len(c.ModelsFor(BackendBedrock)) > 0),
		},
		Audit: assess.Audit{
			Enabled: assess.Bool(c.Audit.Enabled),
			Path:    c.Audit.Path,
			// The chain is a property of the log format, so it is on whenever
			// the log is.
			TamperEvident: assess.Bool(c.Audit.Enabled),
			TamperEvidentDetail: "Hash-chained, so alteration, deletion and reordering are " +
				"detectable. Tail truncation is not detectable from the file alone, and a " +
				"key holder can rewrite history. Anchor the head externally.",
			FailClosed:     assess.Bool(c.Audit.Required),
			VerifyInterval: c.Audit.VerifyInterval.Duration(),
			Retention:      c.Audit.Retention.Duration(),
			Archived:       assess.Bool(c.Audit.ArchiveCommand != ""),
		},
		Data: assess.Data{
			RedactionRules: len(c.Redaction.Rules) + len(c.Redaction.Custom),
			ContentLogged:  assess.Bool(c.Audit.LogContent),
			// Redaction runs inside the log writer rather than at its call
			// sites, which is the whole reason it counts as a control.
			RedactionUnbypassable: assess.Yes,
			TLS:                   assess.Bool(c.TLS.CertFile != ""),
			MutualTLS:             assess.Bool(c.TLS.ClientCAFile != ""),
			Listen:                c.Listen,
			SealedRecovery:        assess.Bool(c.Vault.Enabled),
		},
		Change: assess.Change{
			// Authorised is about the mechanism being in force, not about
			// whether today's configuration happens to be signed: that is a
			// per-policy fact and "switchboard policy history" answers it over
			// a period, which is what the control actually asks.
			Authorised: assess.Bool(c.ChangeControl.Enabled),
			AuthorisedDetail: "Each configuration is served only where an Ed25519 signature " +
				"over its policy fingerprint verifies against a configured approver. The " +
				"gateway holds public keys only, so the serving process cannot sign for " +
				"itself, and the approver roster is inside the fingerprint — adding an " +
				"approver is a change that needs approving. Whether every policy in a given " +
				"period was signed, and signed before it served, is what " +
				"'switchboard policy history' reports.",
			Enforced:  assess.Bool(c.ChangeControl.Enabled && c.ChangeControl.Required),
			Approvers: len(c.ChangeControl.Approvers),
			Minimum:   c.ChangeControl.Threshold(),
			// The archive is written beside the log, so it exists exactly when
			// the log does.
			Recoverable: assess.Bool(c.Audit.Enabled),
		},
		Assurance: assess.Assurance{
			// switchboard cannot know whether anyone red-teamed the models
			// behind it, and guessing either way would invent a finding.
			AdversarialTesting: assess.Unknown,
			// It declines to filter content, and the reason is measured rather
			// than asserted: see the injection-study harness.
			ContentPolicy: assess.No,
		},
		Agency: assess.Agency{
			// switchboard forwards whatever tools a caller puts in the request,
			// so the capability is always present even when nothing bounds it.
			ToolsOffered:     assess.Yes,
			Authorised:       assess.Bool(c.Tools.Enabled),
			AuthorisedDetail: c.Tools.describe(),
			CallsRecorded:    assess.Bool(c.Audit.Enabled),
		},
		Runtime: assess.Runtime{
			FIPS:     assess.Bool(fips140.Enabled()),
			FIPSHint: "Build with GOFIPS140=v1.0.0 or run with GODEBUG=fips140=on.",
			Limits:   assess.Bool(c.Limits.Enabled),
		},
	}
}

// Controls assesses this configuration.
func (c *Config) Controls() ControlReport { return assess.Assess(c.Deployment()) }

func teamsWithKeys(teams []Team) int {
	n := 0
	for _, t := range teams {
		if len(t.Keys) > 0 {
			n++
		}
	}
	return n
}
