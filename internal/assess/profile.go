package assess

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// A Profile names the regulatory regime a deployment is operating under.
//
// switchboard cannot infer this. The same binary in front of the same model is
// a six-month record under the EU AI Act and a six-year record under FINRA, and
// nothing observable at runtime distinguishes them. So the regime is declared,
// and declaring it changes what the config loader will accept.
//
// That is the whole point of the type. Without a profile the audit floors are
// advisory — serve.go warns and starts anyway, because a warning about a regime
// that may not apply to you is noise. With a profile you have asserted that the
// regime applies, and a configuration that cannot satisfy it becomes an error in
// front of whoever wrote it rather than a finding in front of an auditor.
//
// What a profile does not do is make you compliant. It checks the handful of
// obligations that are visible in a deployment's configuration. Everything else — a signed BAA,
// a retention schedule someone actually follows, the physical security of the
// archive — is yours, and `switchboard controls` prints that list too.
//
// This lives in assess rather than config because a regime describes the world,
// not this gateway: the same HIPAA floor applies to a LiteLLM deployment being
// assessed from the outside.
type Profile string

// The regimes with a table below. Unrecognised values are rejected at load.
const (
	ProfileNone    Profile = ""
	ProfileHIPAA   Profile = "hipaa"
	ProfileFINRA   Profile = "finra"
	ProfileEUAIAct Profile = "eu-ai-act"
	Profile800171  Profile = "nist-800-171"
	ProfileFedRAMP Profile = "fedramp-moderate"
)

// Retention floors, as durations rather than the calendar arithmetic the
// regulations are written in. A "year" here is 365 days: the floors are minima,
// the drift is in the safe direction, and nobody's retention schedule turns on
// a leap day.
const (
	// Art26Minimum is the retention floor the EU AI Act sets for deployers of
	// high-risk systems. switchboard cannot know which regime applies to you, so
	// without a profile it warns rather than enforces.
	Art26Minimum = 6 * 30 * 24 * time.Hour

	// hipaaMinimum follows 45 CFR §164.316(b)(2)(i) — six years from creation or
	// last effective date.
	hipaaMinimum = 6 * 365 * 24 * time.Hour

	// finraMinimum follows SEC 17a-4 and FINRA 4511 — six years, the first two
	// readily accessible. switchboard checks the six; "readily accessible" is a
	// property of where archive_command puts the segment, which it cannot see.
	finraMinimum = 6 * 365 * 24 * time.Hour

	// federalMinimum is a switchboard default, not a statute, and the regimes
	// using it say so.
	//
	// NIST 800-53 AU-11 and 800-171 3.3.1 both make the retention period
	// organization-defined: there is no federal number to enforce the way there
	// is for HIPAA or FINRA. One year sits above the FedRAMP baseline parameter
	// and comfortably above the 90 days DFARS 252.204-7012 requires media be
	// preserved after an incident report. Set your own if your SSP says
	// otherwise — the point is that the value is a decision, not a default
	// nobody made.
	federalMinimum = 365 * 24 * time.Hour
)

// Regime is what a profile actually asserts.
type Regime struct {
	// Title names the regime in reports.
	Title string
	// RetentionFloor is the minimum audit.retention this regime accepts. Zero
	// retention always satisfies it: zero means keep everything.
	RetentionFloor time.Duration
	// RetentionCite is the authority for that floor.
	RetentionCite []Ref
	// RequiredRules are built-in redaction rules that must be enabled whenever
	// content is being logged.
	RequiredRules []string
	// RetentionIsParameter marks a floor switchboard chose rather than one a
	// regulation states, so errors and reports can say which it is.
	RetentionIsParameter bool
	// RequireFIPS demands the binary be running under the FIPS 140-3 Go
	// Cryptographic Module.
	RequireFIPS bool
	// RequireTLS refuses a plaintext listener, loopback included.
	RequireTLS bool
	// RequirePerson means a shared team key is not sufficient to attribute an
	// entry — the caller must resolve to a person.
	RequirePerson bool
	// PersonCite is the authority for that.
	PersonCite []Ref
	// Unaddressed names obligations of this regime that switchboard does not
	// meet and does not intend to. They print in `controls` rather than hiding.
	Unaddressed []string
}

// regimes is the regulatory table. Every citation here needs a lawyer's eyes
// before it goes in front of a client — the code enforces what the table says,
// and the table is a starting point rather than an opinion.
var regimes = map[Profile]Regime{
	ProfileHIPAA: {
		Title:          "HIPAA Security Rule",
		RetentionFloor: hipaaMinimum,
		RetentionCite:  refs("HIPAA", "§164.316(b)(2)(i)"),
		RequiredRules:  []string{"us_ssn", "email", "phone_us"},
		RequirePerson:  true,
		PersonCite:     refs("HIPAA", "§164.312(d)"),
		Unaddressed: []string{
			"A Business Associate Agreement with every provider in the path. " +
				"Bedrock is HIPAA-eligible under the AWS BAA, accepted through AWS " +
				"Artifact; eligibility is not compliance, and no gateway can sign it for you.",
			"PHI described in prose. Redaction is pattern-based: it catches " +
				"structured identifiers and will not catch a diagnosis, a name, or a " +
				"date of birth written into a clinical narrative. For a deployment " +
				"where clinicians paste notes, this is the gap that matters most.",
			"Medical record numbers and dates of birth have no built-in rule. " +
				"MRN formats are site-specific, so no built-in pattern set covers them.",
		},
	},
	ProfileFINRA: {
		Title:          "SEC 17a-4 / FINRA 4511",
		RetentionFloor: finraMinimum,
		RetentionCite:  refs("SEC", "17a-4(b)(4)", "FINRA", "4511(c)"),
		RequiredRules:  []string{"us_ssn", "credit_card"},
		RequirePerson:  true,
		PersonCite:     refs("SEC", "17a-4 (supervisory attribution)"),
		Unaddressed: []string{
			"Account and routing numbers have no built-in rule: formats are " +
				"institution-specific, so no built-in pattern set covers them.",
			"Model risk management (SR 11-7) asks for a model inventory, " +
				"documented validation, and ongoing performance monitoring. " +
				"switchboard records what each model was asked and what it cost; it " +
				"is evidence for that programme, not the programme.",
			"Whether the archive is non-rewriteable, or an audit-trail system " +
				"acceptable in its place, is a property of where archive_command " +
				"ships segments. switchboard makes alteration detectable; it cannot " +
				"make storage immutable.",
		},
	},
	Profile800171: {
		Title:                "NIST SP 800-171 Rev 2 (CUI) / CMMC Level 2",
		RetentionFloor:       federalMinimum,
		RetentionCite:        refs("NIST 800-171", "3.3.1"),
		RetentionIsParameter: true,
		RequiredRules:        []string{"us_ssn", "email"},
		RequirePerson:        true,
		PersonCite:           refs("NIST 800-171", "3.1.1", "NIST 800-171", "3.3.2"),
		RequireFIPS:          true,
		RequireTLS:           true,
		Unaddressed: []string{
			"CUI is defined by your contract, not by a pattern. Redaction catches " +
				"structured identifiers; whether a prompt contains CUI is a judgement " +
				"about content switchboard is not equipped to make. Treat the gateway " +
				"as bounding where CUI may go, not as deciding what it is.",
			"DFARS 252.204-7012 requires reporting a cyber incident to DIBNet " +
				"within 72 hours and preserving media for at least 90 days. The audit " +
				"log is evidence for that report; the reporting is yours.",
			"CMMC Phase II third-party assessment was suspended in July 2026, but " +
				"Phase I self-assessment against 800-171 Rev 2 remains contractually " +
				"required and flows down to subcontractors. `switchboard controls " +
				"-json` is evidence for a self-assessment, not a substitute for one.",
			"Physical and personnel controls, incident response, and awareness " +
				"training are families of 800-171 no gateway touches.",
		},
	},
	ProfileFedRAMP: {
		Title:                "FedRAMP Moderate (NIST 800-53 Rev 5)",
		RetentionFloor:       federalMinimum,
		RetentionCite:        refs("NIST 800-53", "AU-11"),
		RetentionIsParameter: true,
		RequiredRules:        []string{"us_ssn", "email"},
		RequirePerson:        true,
		PersonCite:           refs("NIST 800-53", "IA-2", "NIST 800-53", "AU-3"),
		RequireFIPS:          true,
		RequireTLS:           true,
		Unaddressed: []string{
			"A self-hosted gateway is not FedRAMP authorized and does not need to be. " +
				"FedRAMP authorizes cloud service offerings; this is a self-hosted " +
				"binary that runs inside an authorization boundary you already have, " +
				"inheriting its controls rather than establishing new ones. What that " +
				"means practically: no third-party ATO to wait on, and no vendor in " +
				"your data path to assess.",
			"Inherited controls are only inherited if your SSP says so. The rows " +
				"above are evidence for a control implementation statement; writing " +
				"that statement, and having it assessed, is yours.",
			"Bedrock in a commercial region is not a GovCloud or IL-level " +
				"boundary. Where the models run is a question about your AWS account, " +
				"not about this gateway.",
		},
	},
	ProfileEUAIAct: {
		Title:          "EU AI Act (deployer of a high-risk system)",
		RetentionFloor: Art26Minimum,
		RetentionCite:  refs("EU AI Act", "Art. 26"),
		RequirePerson:  false,
		Unaddressed: []string{
			"Whether your system is high-risk at all. The demanding obligations " +
				"attach to the Annex classifications; an internal coding assistant " +
				"is probably not one and a model in a credit decision probably is. " +
				"Selecting this profile asserts that it applies to you.",
			"Human oversight, risk management, and conformity assessment are " +
				"obligations on the deployment, not on the gateway.",
		},
	},
}

// ProfileNames lists the declarable regimes, sorted, for help text and errors.
func ProfileNames() []string {
	out := make([]string, 0, len(regimes))
	for p := range regimes {
		out = append(out, string(p))
	}
	sort.Strings(out)
	return out
}

// Regime returns the table entry for a profile, and whether one exists.
func (p Profile) Regime() (Regime, bool) {
	r, ok := regimes[p]
	return r, ok
}

// String makes an unset profile print as something other than empty.
func (p Profile) String() string {
	if p == ProfileNone {
		return "none"
	}
	return string(p)
}

// Roughly renders a duration the way a person says it, because "61320h0m0s" is
// not a number anybody wrote down and a control report is read by people who
// did not choose it.
//
// Rounds down, deliberately: this renders retention against a regulatory floor,
// and a value that reads longer than it is would be the one dangerous direction
// to be imprecise in.
func Roughly(d time.Duration) string {
	plural := func(n int64, unit string) string {
		if n == 1 {
			return fmt.Sprintf("%d %s", n, unit)
		}
		return fmt.Sprintf("%d %ss", n, unit)
	}
	switch day := 24 * time.Hour; {
	case d >= 365*day:
		return plural(int64(d/(365*day)), "year")
	case d >= 30*day:
		return plural(int64(d/(30*day)), "month")
	case d >= day:
		return plural(int64(d/day), "day")
	default:
		// "1h0m0s" is the standard library being complete rather than readable.
		return strings.TrimSuffix(strings.TrimSuffix(d.String(), "0s"), "0m")
	}
}
