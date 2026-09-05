package config

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
// obligations that are visible in a config file. Everything else — a signed BAA,
// a retention schedule someone actually follows, the physical security of the
// archive — is yours, and `switchboard controls` prints that list too.
type Profile string

// The regimes with a table below. Unrecognised values are rejected at load.
const (
	ProfileNone    Profile = ""
	ProfileHIPAA   Profile = "hipaa"
	ProfileFINRA   Profile = "finra"
	ProfileEUAIAct Profile = "eu-ai-act"
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
)

// regime is what a profile actually asserts.
type regime struct {
	// Title names the regime in reports.
	Title string
	// RetentionFloor is the minimum audit.retention this regime accepts. Zero
	// retention always satisfies it: zero means keep everything.
	RetentionFloor time.Duration
	// RetentionCite is the authority for that floor.
	RetentionCite string
	// RequiredRules are built-in redaction rules that must be enabled whenever
	// content is being logged.
	RequiredRules []string
	// RequirePerson means a shared team key is not sufficient to attribute an
	// entry — the caller must resolve to a person.
	RequirePerson bool
	// PersonCite is the authority for that.
	PersonCite string
	// Unaddressed names obligations of this regime that switchboard does not
	// meet and does not intend to. They print in `controls` rather than hiding.
	Unaddressed []string
}

// regimes is the regulatory table. Every citation here needs a lawyer's eyes
// before it goes in front of a client — the code enforces what the table says,
// and the table is a starting point rather than an opinion.
var regimes = map[Profile]regime{
	ProfileHIPAA: {
		Title:          "HIPAA Security Rule",
		RetentionFloor: hipaaMinimum,
		RetentionCite:  "45 CFR §164.316(b)(2)(i)",
		RequiredRules:  []string{"us_ssn", "email", "phone_us"},
		RequirePerson:  true,
		PersonCite:     "45 CFR §164.312(d)",
		Unaddressed: []string{
			"A Business Associate Agreement with every provider in the path. " +
				"Bedrock is HIPAA-eligible under the AWS BAA, accepted through AWS " +
				"Artifact; eligibility is not compliance and the BAA is not switchboard's to sign.",
			"PHI described in prose. Redaction is pattern-based: it catches " +
				"structured identifiers and will not catch a diagnosis, a name, or a " +
				"date of birth written into a clinical narrative. For a deployment " +
				"where clinicians paste notes, this is the gap that matters most.",
			"Medical record numbers and dates of birth have no built-in rule. " +
				"MRN formats are site-specific; add them under redaction.custom.",
		},
	},
	ProfileFINRA: {
		Title:          "SEC 17a-4 / FINRA 4511",
		RetentionFloor: finraMinimum,
		RetentionCite:  "SEC 17a-4(b)(4), FINRA 4511(c)",
		RequiredRules:  []string{"us_ssn", "credit_card"},
		RequirePerson:  true,
		PersonCite:     "supervisory attribution — 17a-4 requires the record identify who acted",
		Unaddressed: []string{
			"Account and routing numbers have no built-in rule: formats are " +
				"institution-specific. Add them under redaction.custom.",
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
	ProfileEUAIAct: {
		Title:          "EU AI Act (deployer of a high-risk system)",
		RetentionFloor: Art26Minimum,
		RetentionCite:  "EU AI Act Art. 26",
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
func (p Profile) Regime() (regime, bool) {
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

// validate enforces the declared regime against the rest of the config.
//
// Each failure names the obligation and the citation, because the person
// reading it at startup is usually not the person who chose the number, and
// "audit.retention is too short" without an authority is an argument rather
// than an instruction.
func (p Profile) validate(c *Config) error {
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
			p, got, r.RetentionCite, roughly(r.RetentionFloor))
	}

	// Retention beyond the point where segments leave this host needs somewhere
	// for them to go. Without an archive, a long retention is a promise the disk
	// makes and cannot keep.
	if c.Audit.MaxBytes > 0 && c.Audit.ArchiveCommand == "" && c.Audit.Retention == 0 {
		return fmt.Errorf("profile %q: audit.retention is 0 (keep everything) with "+
			"no audit.archive_command, so %s of records accumulate on this host. "+
			"Set archive_command to ship closed segments somewhere durable",
			p, roughly(r.RetentionFloor))
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

// roughly renders a duration the way a person says it, because "61320h0m0s" is
// not a number anybody wrote down and a control report is read by people who
// did not choose it.
//
// Rounds down, deliberately: this renders retention against a regulatory floor,
// and a value that reads longer than it is would be the one dangerous direction
// to be imprecise in.
func roughly(d time.Duration) string {
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
