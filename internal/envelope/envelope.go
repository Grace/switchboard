// Package envelope decides which tools a caller may actually use.
//
// The idea is from Shen et al., "Sealing the Audit-Runtime Gap for LLM Skills"
// (arXiv:2605.05274), which computes a permission envelope over the manifests
// of everything loaded into an agent's context: the intersection executes by
// default, and anything only one source declared falls outside it and needs
// explicit authorisation. The property that buys is worth stating precisely — a
// permission held by one loaded thing cannot silently become available to the
// whole context.
//
// Their construction is anchored on an on-chain registry with a staked audit
// committee. None of that is needed here and it is not what makes the idea
// work: the paper itself notes the registry is "conceptually a tamper-evident
// storage abstraction" instantiable over "blockchains and append-only
// databases", and switchboard already has the second one. What is taken is the
// permission algebra. What is left is the token economics.
//
// The intersection itself is deliberately NOT implemented, and the reason is
// the most important thing in this file.
//
// Their T∩ = ⋂Tᵢ is an intersection over *skills*, each declaring its own tool
// set. It works because their loader can stop and ask a person to authorise
// everything in the difference. A gateway has nobody to ask, and a completion
// request carries a flat list of tool names rather than skills — so a name
// belongs to one declared source, the intersection across two or more sources
// is empty, and a faithful port would refuse every call the moment a second
// bundle appeared. That is not a strict control, it is a broken one, and it
// would be switched off within a day.
//
// What survives the transplant is their single-source check (Eq. 2, declared ⊆
// authorised), which is most of the value, plus one rule that captures the
// composition risk their intersection was reaching for without the degenerate
// behaviour: when tools from more than one bundle are loaded together, a tool
// that can send data outside is refused unless the caller was explicitly
// authorised for cross-bundle egress. That is the shape of the attack — read
// with one source, send with another, each individually permitted — and it is
// stopped without refusing the ninety per cent of calls that are fine.
//
// This is an adaptation and says so. A faithful-sounding port that is not
// faithful would be worse than an adapted one that names the difference.
//
// This package is deliberately free of dependencies on the rest of switchboard,
// and does no I/O. The enforcement point that matters most for skills is not a
// gateway at all — a Claude Code skill reads a file and calls an API without
// any completion crossing this process — so the algebra has to be liftable into
// whatever does sit on that path.
package envelope

import (
	"fmt"
	"sort"
	"strings"
)

// Manifest is what one tool declares about itself.
type Manifest struct {
	// Tool is the function name as callers offer it.
	Tool string
	// Bundle groups tools that arrive together, standing in for the paper's
	// skill. Empty means ungrouped, and ungrouped tools are checked
	// individually rather than intersected.
	Bundle string
	// Scopes are the data this tool touches — "customer_pii", "ledger".
	// They are opaque strings compared exactly; this package does not model
	// hierarchy, because a scope language is a bigger commitment than the
	// check it would serve.
	Scopes []string
	// Egress marks a tool that can send data outside the organisation. It is
	// separate from Scopes because it is the property that turns a sequence of
	// individually permitted calls into an exfiltration, and a caller reading
	// this struct should not have to infer it from a scope name.
	Egress bool
}

// Grant is what a caller is authorised for.
type Grant struct {
	// Tools the caller may use. Empty means no tool is authorised, which is
	// the safe reading of an absent grant: a deployment that has not said what
	// a team may call has not authorised anything.
	Tools []string
	// Scopes the caller may reach.
	Scopes []string
	// Egress allows tools that can send data outside.
	Egress bool
	// CrossBundleEgress additionally allows those tools when more than one
	// bundle is loaded in the same request. It is separate from Egress because
	// it is a different and larger trust decision: sending data outside is one
	// thing, and sending it outside from a context that also had another
	// source's reach is the composition the paper's intersection was aimed at.
	CrossBundleEgress bool
}

// Decision is why one tool was allowed or refused. Refusals carry a reason
// because a control that cannot explain itself gets switched off.
type Decision struct {
	Tool    string
	Allowed bool
	Reason  string
}

// Envelope is the outcome for one request.
type Envelope struct {
	// Allowed is what may be called.
	Allowed []string
	// Refused is everything else, with reasons.
	Refused []Decision
	// Bundles names the bundles the offered tools came from, in order. More
	// than one means the cross-bundle egress rule applied.
	Bundles []string
	// Undeclared names offered tools with no manifest. They are refused —
	// an undeclared tool is one nobody has said anything about, and defaulting
	// it open would make the whole declaration optional.
	Undeclared []string
}

// Permits reports whether a tool call may proceed.
func (e Envelope) Permits(tool string) bool {
	for _, t := range e.Allowed {
		if t == tool {
			return true
		}
	}
	return false
}

// Why returns the recorded reason a tool was refused, if it was.
func (e Envelope) Why(tool string) string {
	for _, d := range e.Refused {
		if d.Tool == tool {
			return d.Reason
		}
	}
	return ""
}

// Empty reports whether nothing at all may be called.
func (e Envelope) Empty() bool { return len(e.Allowed) == 0 }

// Compute derives the envelope for one request.
//
// offered is what the caller put in the request; manifests is what the
// deployment has declared, keyed by tool name; grant is what this caller may
// have. Order of the result is stable so that two identical requests produce
// identical audit entries.
func Compute(offered []string, manifests map[string]Manifest, grant Grant) Envelope {
	var env Envelope
	if len(offered) == 0 {
		return env
	}

	granted := set(grant.Tools)
	scopes := set(grant.Scopes)

	// Which bundles are in play. The intersection rule only has meaning when
	// tools arrive from more than one declared source.
	bundles := map[string]bool{}
	for _, name := range offered {
		if m, ok := manifests[name]; ok && m.Bundle != "" {
			bundles[m.Bundle] = true
		}
	}
	env.Bundles = keys(bundles)

	mixed := len(env.Bundles) > 1

	for _, name := range offered {
		m, declared := manifests[name]
		switch {
		case !declared:
			env.Undeclared = append(env.Undeclared, name)
			env.refuse(name, "no manifest declares this tool, so nothing is known "+
				"about what it reaches")
		case !granted[name]:
			env.refuse(name, fmt.Sprintf("not in this caller's grant (%s)",
				join(grant.Tools)))
		case m.Egress && !grant.Egress:
			env.refuse(name, "the tool can send data outside and this caller is not "+
				"authorised for egress")
		case len(missing(m.Scopes, scopes)) > 0:
			env.refuse(name, fmt.Sprintf("reaches %s, outside this caller's scopes (%s)",
				join(missing(m.Scopes, scopes)), join(grant.Scopes)))
		case mixed && m.Egress && !grant.CrossBundleEgress:
			// The composition case: this request loaded more than one source,
			// and one of them can send data out. Individually every call is
			// permitted; together they are a path off the premises.
			env.refuse(name, fmt.Sprintf("can send data outside and this request "+
				"loaded more than one bundle (%s), so a tool from one source could "+
				"carry what another reached; the caller is not authorised for "+
				"cross-bundle egress", join(env.Bundles)))
		default:
			env.Allowed = append(env.Allowed, name)
		}
	}
	sort.Strings(env.Allowed)
	sort.Strings(env.Undeclared)
	sort.Slice(env.Refused, func(i, j int) bool { return env.Refused[i].Tool < env.Refused[j].Tool })
	return env
}

func (e *Envelope) refuse(tool, reason string) {
	e.Refused = append(e.Refused, Decision{Tool: tool, Reason: reason})
}

func set(in []string) map[string]bool {
	out := make(map[string]bool, len(in))
	for _, s := range in {
		out[s] = true
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// missing returns the elements of want that are not in have.
func missing(want []string, have map[string]bool) []string {
	var out []string
	for _, s := range want {
		if !have[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func join(in []string) string {
	if len(in) == 0 {
		return "none"
	}
	return strings.Join(in, ", ")
}
