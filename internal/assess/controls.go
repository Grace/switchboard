package assess

import (
	"fmt"
	"sort"
	"strings"
)

// Control assessment against a described deployment.
//
// docs/controls.md says what switchboard is capable of. This says what a
// deployment is actually doing, which is a different and more useful question:
// every control below is one somebody can turn off, and most of the interesting
// findings in a security review are features that exist and are not enabled.
//
// The honest limit is that a configuration is a statement of intent. It shows
// that redaction rules are declared, not that they match your data; that an
// archive command is set, not that the bucket it writes to is immutable. Rows
// depending on facts outside the file say so rather than counting themselves
// met, and a profile's Unaddressed list names the obligations no file evidences.

// ControlStatus is how a single objective came out.
type ControlStatus string

const (
	StatusMet          ControlStatus = "met"
	StatusPartial      ControlStatus = "partial"
	StatusUnmet        ControlStatus = "unmet"
	StatusNotAddressed ControlStatus = "not addressed"
	// StatusUnknown is for a fact the source could not determine. It is not a
	// finding and not assurance; it is a question for the operator.
	StatusUnknown ControlStatus = "unknown"
)

// Symbol renders a status for a terminal table.
func (s ControlStatus) Symbol() string {
	switch s {
	case StatusMet:
		return "OK"
	case StatusPartial:
		return "~~"
	case StatusUnmet:
		return "XX"
	case StatusUnknown:
		return "??"
	default:
		return "--"
	}
}

// Ref is one framework's name for an objective.
//
// This is structured rather than a joined string because the string was doing
// three jobs badly. A report is read by someone who owns exactly one framework:
// a Databricks customer wants DASF identifiers, a hospital wants 45 CFR cites,
// a broker-dealer wants 17a-4. Handing all of them to all of them is how a
// control mapping becomes wallpaper.
//
// It also makes coverage computable — "this deployment addresses 23 of the 64
// DASF controls, here are the 41 it does not" — which is a better artifact
// than any list of rows, and impossible against a pre-joined string.
type Ref struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
}

func (r Ref) String() string { return r.Framework + " " + r.ID }

// refs is shorthand for the table below: refs("SOC 2", "CC7.2", "NIST", "AU-9").
func refs(pairs ...string) []Ref {
	if len(pairs)%2 != 0 {
		panic("refs: want framework/id pairs")
	}
	out := make([]Ref, 0, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, Ref{pairs[i], pairs[i+1]})
	}
	return out
}

// Render joins refs for display, optionally narrowed to one framework. An
// empty result means this objective is not one that framework speaks to, which
// is itself worth showing rather than hiding.
func Render(rs []Ref, only string) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		if only != "" && !strings.EqualFold(r.Framework, only) {
			continue
		}
		parts = append(parts, r.String())
	}
	if len(parts) == 0 && only != "" {
		return "—"
	}
	return strings.Join(parts, " · ")
}

// Frameworks lists every framework cited by the control table, sorted, so the
// CLI can offer them without a hardcoded list going stale.
func Frameworks(rep ControlReport) []string {
	seen := map[string]bool{}
	for _, c := range rep.Controls {
		for _, r := range c.Refs {
			seen[r.Framework] = true
		}
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// Control is one assessed objective.
type Control struct {
	Section   string        `json:"section"`
	Objective string        `json:"objective"`
	Refs      []Ref         `json:"refs"`
	Status    ControlStatus `json:"status"`
	Evidence  string        `json:"evidence"`
}

// ControlReport is the whole assessment.
type ControlReport struct {
	Source   string    `json:"source"`
	Origin   string    `json:"origin,omitempty"`
	Profile  Profile   `json:"profile"`
	Regime   string    `json:"regime,omitempty"`
	Controls []Control `json:"controls"`
	// Yours are obligations this regime places on you that no configuration can
	// evidence. They are not failures; they are the part of the review no tool
	// can do for you.
	Yours []string `json:"yours,omitempty"`
	// Caveats are what the adapter could not read.
	Caveats []string `json:"caveats,omitempty"`
}

// Counts totals the statuses, for a summary line.
func (r ControlReport) Counts() map[ControlStatus]int {
	out := make(map[ControlStatus]int, 5)
	for _, c := range r.Controls {
		out[c.Status]++
	}
	return out
}

// Unmet reports whether anything came out unmet, which is what makes the
// command usable in CI. Unknown deliberately does not count: a question the
// source could not answer is not a failure, and failing a build on it would
// teach people to stop asking.
func (r ControlReport) Unmet() bool {
	for _, c := range r.Controls {
		if c.Status == StatusUnmet {
			return true
		}
	}
	return false
}

// Assess scores a deployment.
func Assess(d Deployment) ControlReport {
	rep := ControlReport{
		Source: d.Source, Origin: d.Origin, Profile: d.Profile, Caveats: d.Caveats,
	}
	reg, hasRegime := d.Profile.Regime()
	if hasRegime {
		rep.Regime = reg.Title
		rep.Yours = reg.Unaddressed
	}

	add := func(section, objective string, rs []Ref, status ControlStatus, evidence string) {
		rep.Controls = append(rep.Controls, Control{
			Section: section, Objective: objective, Refs: rs,
			Status: status, Evidence: evidence,
		})
	}
	// unknown renders the same way everywhere: name the fact, name the source.
	unknown := func(section, objective string, rs []Ref, what string) {
		add(section, objective, rs, StatusUnknown,
			fmt.Sprintf("The %s configuration does not say whether %s.", d.Source, what))
	}

	// ---- Access control and authentication ----
	const access = "Access control and authentication"

	switch {
	case d.Auth.OIDC == Yes:
		ev := "Callers present tokens from an identity provider."
		if d.Auth.Issuer != "" {
			ev = fmt.Sprintf("OIDC against %s. Tokens expire on their own.", d.Auth.Issuer)
		}
		add(access, "Callers are authenticated before use",
			refs("SOC 2", "CC6.1", "ISO 27001", "A.5.15", "HIPAA", "§164.312(d)"), StatusMet, ev)
	case d.Auth.StaticKeyTeams > 0:
		add(access, "Callers are authenticated before use",
			refs("SOC 2", "CC6.1", "ISO 27001", "A.5.15", "HIPAA", "§164.312(d)"), StatusPartial,
			fmt.Sprintf("%d shared keys. They name a team, not a person, and revoking "+
				"one is a manual edit.", d.Auth.StaticKeyTeams))
	case d.Auth.OIDC == Unknown:
		unknown(access, "Callers are authenticated before use",
			refs("SOC 2", "CC6.1", "ISO 27001", "A.5.15"), "callers are authenticated")
	default:
		add(access, "Callers are authenticated before use",
			refs("SOC 2", "CC6.1", "ISO 27001", "A.5.15", "HIPAA", "§164.312(d)"), StatusUnmet,
			"No identity provider and no key roster. Every request is anonymous.")
	}

	switch d.Auth.DenyUnauthenticated {
	case Yes:
		add(access, "Unauthenticated access is denied", refs("SOC 2", "CC6.1", "NIST 800-53", "AC-3"),
			StatusMet, "A request presenting no valid credential is refused.")
	case No:
		add(access, "Unauthenticated access is denied", refs("SOC 2", "CC6.1", "NIST 800-53", "AC-3"),
			StatusUnmet, "A request presenting no credential is served under the "+
				"gateway's own identity.")
	default:
		unknown(access, "Unauthenticated access is denied", refs("SOC 2", "CC6.1", "NIST 800-53", "AC-3"),
			"an unauthenticated request is refused")
	}

	personRefs := refs("SOC 2", "CC7.2", "NIST 800-53", "AU-3")
	if hasRegime && reg.RequirePerson {
		personRefs = reg.PersonCite
	}
	switch {
	case d.Auth.OIDC == Yes:
		add(access, "Records identify a person, not a shared credential", personRefs,
			StatusMet, "The token subject is recorded alongside the team.")
	case d.Auth.OIDC == Unknown:
		unknown(access, "Records identify a person, not a shared credential", personRefs,
			"records name a person")
	case hasRegime && reg.RequirePerson:
		add(access, "Records identify a person, not a shared credential", personRefs,
			StatusUnmet, "No identity provider. Entries carry a team only, and this "+
				"regime asks the record to identify who acted.")
	default:
		add(access, "Records identify a person, not a shared credential", personRefs,
			StatusPartial, "No identity provider. Entries carry a team only.")
	}

	switch {
	case d.Auth.PerCallerProviderCreds == Yes:
		add(access, "Least privilege for provider credentials", refs("SOC 2", "CC6.3", "NIST 800-53", "AC-6"),
			StatusMet, "The provider is called under an identity derived from the caller, "+
				"so permissions and spend are scoped per team rather than pooled.")
	case d.Auth.CloudProvider == No:
		add(access, "Least privilege for provider credentials", refs("SOC 2", "CC6.3", "NIST 800-53", "AC-6"),
			StatusNotAddressed, "No cloud backend is configured, so there are no provider "+
				"credentials to scope.")
	case d.Auth.PerCallerProviderCreds == Unknown:
		unknown(access, "Least privilege for provider credentials", refs("SOC 2", "CC6.3", "NIST 800-53", "AC-6"),
			"provider credentials are scoped per caller")
	default:
		add(access, "Least privilege for provider credentials", refs("SOC 2", "CC6.3", "NIST 800-53", "AC-6"),
			StatusPartial, "Every call uses one shared provider identity, so the provider's "+
				"bill and its own logs cannot distinguish callers.")
	}

	// ---- Audit and accountability ----
	const audit = "Audit and accountability"
	auditRefs := refs("SOC 2", "CC7.2", "HIPAA", "§164.312(b)", "EU AI Act", "Art. 12")

	switch d.Audit.Enabled {
	case No:
		add(audit, "Security-relevant events are recorded", auditRefs, StatusUnmet,
			"Auditing is off. Nothing is written down.")
	case Unknown:
		unknown(audit, "Security-relevant events are recorded", auditRefs,
			"completions are recorded")
	default:
		ev := "One entry per completion."
		if d.Audit.Path != "" {
			ev = fmt.Sprintf("One entry per completion at %s.", d.Audit.Path)
		}
		add(audit, "Security-relevant events are recorded", auditRefs, StatusMet, ev)
		assessAuditDetail(add, unknown, d, reg, hasRegime)
	}

	// ---- Data protection ----
	assessData(add, unknown, d, reg, hasRegime)

	// ---- Assurance: evidence from outside the gateway ----
	const assur = "Assurance"

	testRefs := refs("EU AI Act", "Art. 15", "MITRE ATLAS", "AML.M0015", "NIST 800-53", "CA-8")
	switch d.Assurance.AdversarialTesting {
	case Yes:
		ev := "Adversarial testing has been performed."
		if d.Assurance.TestingDetail != "" {
			ev = "Adversarial testing: " + d.Assurance.TestingDetail + "."
		}
		add(assur, "The deployment has been adversarially tested", testRefs, StatusMet, ev)
	case No:
		add(assur, "The deployment has been adversarially tested", testRefs, StatusUnmet,
			"No red-team or probe results are recorded for this deployment.")
	default:
		add(assur, "The deployment has been adversarially tested", testRefs, StatusUnknown,
			fmt.Sprintf("Nothing attached to this %s assessment shows adversarial testing "+
				"results. garak, promptfoo, PyRIT and Giskard all produce them; attach the "+
				"output rather than leaving the obligation blank.", d.Source))
	}

	policyRefs := refs("MITRE ATLAS", "AML.M0020", "MITRE ATLAS", "AML.M0033")
	switch d.Assurance.ContentPolicy {
	case Yes:
		ev := "Content is filtered at the boundary."
		if d.Assurance.ContentPolicyDetail != "" {
			ev = d.Assurance.ContentPolicyDetail
		}
		add(assur, "Content policy is enforced at the boundary", policyRefs, StatusMet, ev)
	case No:
		// Declining to filter is a defensible position, and stating why is
		// stronger than a silent gap. It is not scored as a failure because no
		// regime here requires semantic filtering.
		add(assur, "Content policy is enforced at the boundary", policyRefs, StatusNotAddressed,
			"No content filtering. A gateway is well placed to bound what a model may do "+
				"and badly placed to guess what an input means; the structural controls above "+
				"are the mitigation. If your regime expects filtering, this is a gap.")
	default:
		add(assur, "Content policy is enforced at the boundary", policyRefs, StatusUnknown,
			fmt.Sprintf("The %s configuration does not say whether inputs or outputs are "+
				"filtered.", d.Source))
	}

	// ---- Model agency ----
	const agency = "Model agency"
	toolRefs := refs("NIST 800-53", "AC-6", "SOC 2", "CC6.3", "ISO 27001", "A.8.2")
	const authObj = "Tool calls are authorised before they take effect"
	switch {
	case d.Agency.ToolsOffered == No:
		add(agency, authObj, toolRefs, StatusNotAddressed,
			"No caller can put a tool in front of a model here, so there is no action "+
				"to authorise. This row becomes a gap the day that changes.")
	case d.Agency.Authorised == Yes:
		ev := "A tool call is checked against the caller's grant before it takes effect."
		if d.Agency.AuthorisedDetail != "" {
			ev = d.Agency.AuthorisedDetail
		}
		// The limit is stated in the evidence rather than in a footnote,
		// because a reviewer reads the row and stops. Overstating this one is
		// worse than having no row: it is the row that says an action was
		// prevented.
		add(agency, authObj, toolRefs, StatusMet, ev+" On a streaming response the "+
			"completing frame is withheld and the refusal recorded, which stops a client "+
			"that waits for the finish reason and does not stop one that acts on partial "+
			"deltas. Where this must be a control rather than a signal, do not offer tools "+
			"on streaming requests.")
	case d.Agency.Authorised == No:
		add(agency, authObj, toolRefs, StatusUnmet,
			"Tools can be offered and any call the model is talked into making is passed "+
				"through. The record will show what happened; nothing stopped it.")
	default:
		unknown(agency, authObj, toolRefs,
			"a tool call is checked against a grant before it takes effect")
	}

	const callObj = "Tool calls and refusals are recorded"
	callRefs := refs("NIST 800-53", "AU-3", "SOC 2", "CC7.2", "EU AI Act", "Art. 12")
	switch {
	case d.Agency.ToolsOffered == No:
		// Deliberately not repeated as a second not-addressed row. One line
		// about a deployment with no tools is a fact; two is padding.
	case d.Agency.CallsRecorded == Yes:
		add(agency, callObj, callRefs, StatusMet,
			"Every tool the model asked for is named in the entry for its request, in "+
				"order, with each refusal and its reason. The refusal is written before "+
				"the request fails, so a stopped call cannot be lost with it.")
	case d.Agency.CallsRecorded == No:
		add(agency, callObj, callRefs, StatusUnmet,
			"Nothing records which tools the model asked to call, so a call that should "+
				"not have happened leaves no trace to find it by.")
	default:
		unknown(agency, callObj, callRefs, "tool calls are recorded")
	}

	// ---- Availability ----
	const avail = "Availability and operations"
	limitRefs := refs("SOC 2", "A1.1", "NIST 800-53", "SC-5", "MITRE ATLAS", "AML.M0004")
	switch d.Runtime.Limits {
	case Yes:
		add(avail, "Resource limits", limitRefs, StatusMet,
			"Per-caller request rate, concurrency and token budget.")
	case No:
		add(avail, "Resource limits", limitRefs, StatusUnmet,
			"Nothing bounds what one caller can consume.")
	default:
		unknown(avail, "Resource limits", limitRefs, "one caller's consumption is bounded")
	}

	return rep
}

type addFunc func(section, objective string, rs []Ref, status ControlStatus, evidence string)
type unknownFunc func(section, objective string, rs []Ref, what string)

func assessAuditDetail(add addFunc, unknown unknownFunc, d Deployment, reg Regime, hasRegime bool) {
	const audit = "Audit and accountability"

	switch d.Audit.TamperEvident {
	case Yes:
		add(audit, "Records are protected from modification",
			refs("SOC 2", "CC7.2", "ISO 27001", "A.8.15", "NIST 800-53", "AU-9"), StatusPartial,
			"Hash-chained, so alteration, deletion and reordering are detectable. Tail "+
				"truncation is not detectable from the file alone, and a key holder can "+
				"rewrite history. Anchor the head externally.")
	case No:
		add(audit, "Records are protected from modification",
			refs("SOC 2", "CC7.2", "ISO 27001", "A.8.15", "NIST 800-53", "AU-9"), StatusUnmet,
			"Records are append-only at best. Anyone with write access to the store can "+
				"edit a past entry undetectably.")
	default:
		unknown(audit, "Records are protected from modification",
			refs("SOC 2", "CC7.2", "NIST 800-53", "AU-9"), "past records can be altered undetectably")
	}

	switch d.Audit.FailClosed {
	case Yes:
		add(audit, "Auditing cannot fail silently", refs("SOC 2", "CC7.2", "NIST 800-53", "AU-5"), StatusMet,
			"A completion that cannot be recorded is refused rather than served.")
	case No:
		add(audit, "Auditing cannot fail silently", refs("SOC 2", "CC7.2", "NIST 800-53", "AU-5"), StatusUnmet,
			"A completion whose record fails to write is served anyway, unrecorded.")
	default:
		unknown(audit, "Auditing cannot fail silently", refs("SOC 2", "CC7.2", "NIST 800-53", "AU-5"),
			"an unrecordable completion is refused")
	}

	if v := d.Audit.VerifyInterval; v > 0 {
		add(audit, "Logs are reviewed", refs("SOC 2", "CC7.2", "NIST 800-53", "AU-6"), StatusMet,
			fmt.Sprintf("The record is verified at startup and every %s.", Roughly(v)))
	} else {
		add(audit, "Logs are reviewed", refs("SOC 2", "CC7.2", "NIST 800-53", "AU-6"), StatusPartial,
			"No periodic verification configured. A record nobody re-reads is a record "+
				"nobody would notice being edited.")
	}

	floor, cite := Art26Minimum, refs("EU AI Act", "Art. 26")
	if hasRegime {
		floor, cite = reg.RetentionFloor, reg.RetentionCite
	}
	// The evidence sentence names the authority in prose; the refs column
	// carries it as data. Both, because a reader wants one and a filter the other.
	citeText := Render(cite, "")
	note := ""
	if hasRegime && reg.RetentionIsParameter {
		note = " That floor is a default rather than a statutory number: this regime " +
			"leaves the period organization-defined, so confirm it against your own " +
			"records schedule."
	}
	got := d.Audit.Retention
	switch {
	case got == 0 && d.Audit.Archived != Yes:
		add(audit, "Log retention", cite, StatusPartial,
			fmt.Sprintf("Retention is unlimited with no archive, so %s of records "+
				"accumulate on one host and the local disk is the only copy.%s",
				Roughly(floor), note))
	case got == 0:
		add(audit, "Log retention", cite, StatusMet,
			"Retention is unlimited, and closed records are archived before anything "+
				"is pruned."+note)
	case got < floor:
		add(audit, "Log retention", cite, StatusUnmet,
			fmt.Sprintf("Retention is %s; %s asks for at least %s.%s",
				Roughly(got), citeText, Roughly(floor), note))
	case d.Audit.Archived != Yes:
		add(audit, "Log retention", cite, StatusPartial,
			fmt.Sprintf("Retention of %s clears the floor, but with no archive this host "+
				"is the archive and retention deletes evidence rather than draining a "+
				"buffer.%s", Roughly(got), note))
	default:
		add(audit, "Log retention", cite, StatusMet,
			fmt.Sprintf("Retention is %s, above the %s floor, and closed records are "+
				"archived before pruning.%s", Roughly(got), Roughly(floor), note))
	}
}

func assessData(add addFunc, unknown unknownFunc, d Deployment, reg Regime, hasRegime bool) {
	const data = "Data protection"
	redactRefs := refs("SOC 2", "CC6.7", "ISO 27001", "A.8.11", "HIPAA", "§164.312(a)(2)(iv)")

	switch {
	case d.Audit.Enabled == No:
		add(data, "Sensitive data is not written to logs", redactRefs, StatusNotAddressed,
			"Nothing is recorded at all, so no prompt text reaches a log. That is the "+
				"absence of a record rather than the protection of one.")
	case d.Data.RedactionRules == 0 && d.Data.ContentLogged == No:
		add(data, "Sensitive data is not written to logs", redactRefs, StatusMet,
			"Content logging is off — metadata only, so no prompt text reaches the log "+
				"to be redacted.")
	case d.Data.RedactionRules == 0 && d.Data.ContentLogged == Unknown:
		unknown(data, "Sensitive data is not written to logs", redactRefs,
			"prompts and completions are stored")
	case d.Data.RedactionRules == 0:
		add(data, "Sensitive data is not written to logs", redactRefs, StatusUnmet,
			"Content is stored and no redaction rules are configured.")
	case d.Data.ContentLogged == No:
		add(data, "Sensitive data is not written to logs", redactRefs, StatusMet,
			fmt.Sprintf("%d rules configured, and content logging is off — metadata only.",
				d.Data.RedactionRules))
	case d.Data.RedactionUnbypassable == Yes:
		add(data, "Sensitive data is not written to logs", redactRefs, StatusPartial,
			fmt.Sprintf("%d rules applied at the chokepoint, so no call site can skip "+
				"them. Pattern-based: structured identifiers only, not a name or a "+
				"condition described in prose.", d.Data.RedactionRules))
	default:
		add(data, "Sensitive data is not written to logs", redactRefs, StatusPartial,
			fmt.Sprintf("%d rules configured, but applied where an application can skip "+
				"them. A rule each team opts into is a convention, not a control.",
				d.Data.RedactionRules))
	}

	tlsRefs := refs("SOC 2", "CC6.7", "HIPAA", "§164.312(e)(1)", "NIST 800-53", "SC-8")
	switch {
	case d.Data.TLS == Yes && d.Data.MutualTLS == Yes:
		add(data, "Encryption in transit", tlsRefs, StatusMet,
			"The listener serves TLS and requires a client certificate.")
	case d.Data.TLS == Yes:
		add(data, "Encryption in transit", tlsRefs, StatusMet,
			"The listener serves TLS. No client certificate is required.")
	case d.Data.TLS == Unknown:
		unknown(data, "Encryption in transit", tlsRefs, "the listener serves TLS")
	case hasRegime && reg.RequireTLS:
		add(data, "Encryption in transit", refs("NIST 800-53", "SC-8", "NIST 800-171", "3.13.8"), StatusUnmet,
			fmt.Sprintf("%s is plaintext. This regime treats transmission "+
				"confidentiality as unconditional, loopback included.", listenOr(d)))
	default:
		add(data, "Encryption in transit", tlsRefs, StatusPartial,
			fmt.Sprintf("%s is plaintext. Provider calls still use the SDK's TLS.",
				listenOr(d)))
	}

	sealRefs := refs("NIST 800-53", "SC-28", "HIPAA", "§164.312(a)(2)(iv)")
	switch d.Data.SealedRecovery {
	case Yes:
		add(data, "Redacted values are recoverable under control", sealRefs, StatusMet,
			"Redacted values are sealed to a key the gateway holds no private half of. "+
				"Recovery needs the offline key.")
	default:
		add(data, "Redacted values are recoverable under control", sealRefs,
			StatusNotAddressed, "Redacted values are discarded, which is the safe default "+
				"and means an investigation cannot recover them.")
	}

	fipsRefs := refs("NIST 800-53", "SC-13", "NIST 800-171", "3.13.11", "FIPS", "140-3")
	switch {
	case d.Runtime.FIPS == Yes:
		add(data, "Cryptography is FIPS-validated", fipsRefs, StatusMet,
			"Running under a validated cryptographic module.")
	case d.Runtime.FIPS == Unknown:
		unknown(data, "Cryptography is FIPS-validated", fipsRefs,
			"validated cryptography is in force")
	case hasRegime && reg.RequireFIPS:
		add(data, "Cryptography is FIPS-validated", fipsRefs, StatusUnmet,
			"Not running under a validated cryptographic module."+hint(d.Runtime.FIPSHint))
	default:
		add(data, "Cryptography is FIPS-validated", fipsRefs, StatusNotAddressed,
			"Not in FIPS mode, and this regime does not ask for it.")
	}
}

// hint appends an adapter-supplied remedy. How you turn validated cryptography
// on is a property of the toolchain, not of the control, so assess does not
// guess at it.
func hint(s string) string {
	if s == "" {
		return ""
	}
	return " " + s
}

func listenOr(d Deployment) string {
	if d.Data.Listen != "" {
		return d.Data.Listen
	}
	return "The listener"
}
