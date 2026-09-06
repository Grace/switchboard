// Package assess describes an LLM deployment in terms a security review asks
// about, and scores it.
//
// The split from config is deliberate. config knows what switchboard's own file
// looks like; assess knows what a reviewer wants to know. Keeping them apart is
// what lets a LiteLLM deployment, an Azure OpenAI setup or a raw provider
// integration be assessed by the same rules that assess this one — which is the
// more useful product, because almost nobody will replace a gateway to find out
// whether their current one is defensible.
package assess

import "time"

// Support is a fact about a deployment, and it has three states rather than two.
//
// Unknown is the reason this type exists. A tool reading somebody else's
// configuration has to distinguish "this is switched off" from "this file
// cannot tell me" — reporting the second as the first invents findings, and
// reporting it as met invents assurance. Both destroy the report's credibility
// on first contact with someone who knows their own system.
type Support int

const (
	Unknown Support = iota
	No
	Yes
)

func (s Support) String() string {
	switch s {
	case Yes:
		return "yes"
	case No:
		return "no"
	default:
		return "unknown"
	}
}

// Bool is a convenience for adapters reading a config that does answer the
// question one way or the other.
func Bool(b bool) Support {
	if b {
		return Yes
	}
	return No
}

// Deployment is one LLM gateway deployment, described neutrally.
type Deployment struct {
	// Source names the adapter that produced this — "switchboard", "litellm".
	Source string `json:"source"`
	// Origin is where it was read from, for a report header.
	Origin string `json:"origin,omitempty"`
	// Profile is the declared regulatory regime, if any.
	Profile Profile `json:"profile,omitempty"`
	// Caveats are what this adapter could not determine, stated plainly. An
	// assessment of a foreign config is only as good as its honesty about
	// what the file does not say.
	Caveats []string `json:"caveats,omitempty"`

	Auth      Auth      `json:"auth"`
	Assurance Assurance `json:"assurance"`
	Audit     Audit     `json:"audit"`
	Data      Data      `json:"data"`
	Agency    Agency    `json:"agency"`
	Change    Change    `json:"change"`
	Runtime   Runtime   `json:"runtime"`
}

// Agency is what the model may be made to do, as distinct from what the caller
// may ask for.
//
// Every other section here describes a request: who sent it, what it carried,
// whether it was written down. This one describes a consequence. A model that
// has been talked into calling a tool it was never granted is the failure a
// completion log is worst at showing after the fact, because the harm is not in
// the text — it is in the action the text caused, and by the time anyone reads
// the entry the action has happened.
// Change is whether the configuration this system runs is under control.
//
// A model roster, a prompt, a tool grant and a redaction rule all decide what a
// deployment does in production, and they are usually outside the change
// process that covers application code — changed through a console, by one
// person, with nothing forcing a review. That gap is the common finding and it
// is invisible to any check that only reads the configuration, because a
// configuration cannot say who agreed to it.
type Change struct {
	// Authorised means a configuration carries a signature from somebody who is
	// not the process running it.
	Authorised Support `json:"authorised"`
	// AuthorisedDetail is the mechanism in the adapter's own terms.
	AuthorisedDetail string `json:"authorised_detail,omitempty"`
	// Enforced separates a preventive control from a detective one: whether an
	// unauthorised configuration is refused, or served and reported.
	Enforced Support `json:"enforced"`
	// Approvers is how many people may authorise; Minimum how many must. One is
	// materially weaker than two and the report should not flatten them: a
	// single approver who can also edit the configuration is approving their
	// own change.
	Approvers int `json:"approvers,omitempty"`
	Minimum   int `json:"minimum,omitempty"`
	// Recoverable means the configuration behind a recorded fingerprint is
	// kept, not only its digest. A digest names a document; without the
	// document, a decision questioned later cannot be read against the rules
	// that produced it.
	Recoverable Support `json:"recoverable"`
}

type Agency struct {
	// ToolsOffered is whether callers can put tools in front of a model here at
	// all. Where they cannot, the objectives below are not gaps in the
	// deployment, and scoring them as gaps would invent a finding.
	ToolsOffered Support `json:"tools_offered"`
	// Authorised means a tool call is checked against a grant before it takes
	// effect, rather than being recorded after it already has.
	Authorised Support `json:"authorised"`
	// AuthorisedDetail names what is declared and who holds grants, so the row
	// is evidence rather than a claim.
	AuthorisedDetail string `json:"authorised_detail,omitempty"`
	// CallsRecorded means each call the model asked for — and each refusal —
	// lands in the record. A refusal is the more valuable of the two: it is
	// either an attack that was stopped or a permission somebody needs.
	CallsRecorded Support `json:"calls_recorded"`
}

// Assurance is evidence a gateway does not produce and a compliance programme
// still has to file.
//
// Red-team results come from garak, promptfoo, PyRIT or Giskard. Content policy
// comes from LLM Guard, NeMo, Guardrails AI or a platform's own guardrails.
// None of those tools compete with an assessment — they are its inputs, and
// today they produce artifacts that go nowhere.
//
// These fields default to Unknown, which is the point. A report that omits an
// obligation because no tool reported on it looks complete and is not; one that
// says "nothing here has shown me adversarial testing" asks the question the
// examiner will ask.
type Assurance struct {
	// AdversarialTesting is whether the deployment has been probed for
	// jailbreaks, injection and leakage before or during production.
	AdversarialTesting Support `json:"adversarial_testing"`
	// TestingDetail names the tool and date, so the row is evidence rather
	// than an assertion.
	TestingDetail string `json:"testing_detail,omitempty"`
	// ContentPolicy is whether inputs or outputs are filtered at the boundary.
	ContentPolicy       Support `json:"content_policy"`
	ContentPolicyDetail string  `json:"content_policy_detail,omitempty"`
}

// Auth is who may call, and as whom.
type Auth struct {
	// OIDC means callers present tokens from an identity provider, so an entry
	// can name a person rather than a shared credential.
	OIDC   Support `json:"oidc"`
	Issuer string  `json:"issuer,omitempty"`
	// StaticKeyTeams counts rosters authenticated by a shared secret.
	StaticKeyTeams int `json:"static_key_teams"`
	// DenyUnauthenticated means a request with no credential is refused rather
	// than served under the gateway's own identity.
	DenyUnauthenticated Support `json:"deny_unauthenticated"`
	// PerCallerProviderCreds means the provider is called under an identity
	// derived from the caller, so the provider's own bill can tell them apart.
	PerCallerProviderCreds Support `json:"per_caller_provider_creds"`
	// CloudProvider is whether any hosted model backend exists at all. Without
	// one there are no provider credentials to scope, and reporting a gap there
	// would be a finding nobody can act on.
	CloudProvider Support `json:"cloud_provider"`
}

// Audit is what is written down and whether it survives being disputed.
type Audit struct {
	Enabled Support `json:"enabled"`
	Path    string  `json:"path,omitempty"`
	// TamperEvident means altering a past entry is detectable.
	TamperEvident Support `json:"tamper_evident"`
	// TamperEvidentDetail is how this deployment resists modification, in its
	// own terms, supplied by the adapter.
	//
	// This field exists because the scorer once described the mechanism itself,
	// which meant a Bedrock account with S3 Object Lock was reported to a
	// reviewer as "hash-chained". Every deployment resists modification
	// differently — a chained record reveals an edit, object immutability
	// prevents one, and a versioned table does neither — and the difference is
	// the entire content of the row. A scorer that names a mechanism it was
	// never told about invents assurance, which is worse than inventing a
	// finding: nobody goes looking to disprove good news.
	TamperEvidentDetail string `json:"tamper_evident_detail,omitempty"`
	// FailClosed means a completion that cannot be recorded is refused rather
	// than served unrecorded.
	FailClosed Support `json:"fail_closed"`
	// VerifyInterval is how often the record is re-checked while running.
	VerifyInterval time.Duration `json:"verify_interval"`
	// Retention is how long records are kept. Zero means keep everything.
	Retention time.Duration `json:"retention"`
	// Archived means closed records are shipped somewhere durable before being
	// pruned locally.
	Archived Support `json:"archived"`
}

// Data is what leaves, and in what state.
type Data struct {
	// RedactionRules counts patterns applied before content is written down.
	RedactionRules int `json:"redaction_rules"`
	// ContentLogged means prompts and completions are stored, not just metadata.
	ContentLogged Support `json:"content_logged"`
	// RedactionUnbypassable means redaction happens at a chokepoint rather than
	// being each application's responsibility. A rule an application can skip
	// is a convention, not a control.
	RedactionUnbypassable Support `json:"redaction_unbypassable"`
	TLS                   Support `json:"tls"`
	MutualTLS             Support `json:"mutual_tls"`
	Listen                string  `json:"listen,omitempty"`
	// SealedRecovery means redacted values can be recovered under key control
	// rather than being discarded outright.
	SealedRecovery Support `json:"sealed_recovery"`
}

// Runtime is true of the running process rather than of the file.
type Runtime struct {
	// FIPS means validated cryptography is in force.
	FIPS Support `json:"fips"`
	// FIPSHint is how this particular stack turns it on, supplied by the
	// adapter because the answer differs per toolchain.
	FIPSHint string `json:"fips_hint,omitempty"`
	// Limits means one caller's consumption is bounded.
	Limits Support `json:"limits"`
}
