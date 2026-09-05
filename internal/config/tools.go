package config

import (
	"fmt"
	"sort"

	"github.com/Grace/switchboard/internal/envelope"
)

// Tools bounds what a model may actually be made to do.
//
// The rest of switchboard records what happened. This is one of the few places
// that stops something, and it stops the thing a completion log is worst at
// showing: not a bad answer, but an action. A model that has been talked into
// calling a tool it was never meant to reach is the failure that leaves money
// moved rather than a sentence written.
//
// Declaration is mandatory and there is no default-open. An undeclared tool is
// refused, because a deployment that has said nothing about a tool has not
// authorised it, and a default-open list makes every declaration optional.
type Tools struct {
	// Enabled turns enforcement on. Off, tool calls are recorded and not
	// judged — which is the honest state of a deployment that has not yet
	// declared anything, and a better default than refusing every call.
	Enabled bool `json:"enabled"`
	// Declare describes each tool the deployment knows about, by name.
	Declare map[string]ToolDecl `json:"declare,omitempty"`
	// Grants are per-team allowances. A team with no grant gets Default.
	Grants map[string]ToolGrant `json:"grants,omitempty"`
	// Default applies to callers with no grant of their own, including
	// unattributed ones. Its zero value authorises nothing.
	Default ToolGrant `json:"default,omitempty"`
}

// ToolDecl is what a tool reaches.
type ToolDecl struct {
	// Bundle groups tools that ship together. When a single request loads
	// tools from more than one bundle, an egress-capable tool needs
	// cross_bundle_egress on top of egress — see internal/envelope for why,
	// and for whose idea it is.
	Bundle string `json:"bundle,omitempty"`
	// Scopes are the data this tool touches.
	Scopes []string `json:"scopes,omitempty"`
	// Egress marks a tool that can send data outside the organisation.
	Egress bool `json:"egress,omitempty"`
}

// ToolGrant is what one team may use.
type ToolGrant struct {
	Tools  []string `json:"tools,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
	Egress bool     `json:"egress,omitempty"`
	// CrossBundleEgress allows egress tools even when the request loaded more
	// than one bundle. See internal/envelope: that combination is the shape of
	// read-here-send-there, so it is a separate and larger decision.
	CrossBundleEgress bool `json:"cross_bundle_egress,omitempty"`
}

func (t *Tools) validate() error {
	if !t.Enabled {
		return nil
	}
	for team, g := range t.Grants {
		if g.CrossBundleEgress && !g.Egress {
			return fmt.Errorf("tools.grants[%q] sets cross_bundle_egress without egress, "+
				"which authorises nothing: cross_bundle_egress widens egress rather than "+
				"replacing it", team)
		}
	}
	if t.Default.CrossBundleEgress && !t.Default.Egress {
		return fmt.Errorf("tools.default sets cross_bundle_egress without egress")
	}
	if len(t.Declare) == 0 {
		return fmt.Errorf("tools.enabled but nothing is declared: every call would be " +
			"refused. Declare the tools this deployment expects, or leave tools.enabled off")
	}
	for name, d := range t.Declare {
		if name == "" {
			return fmt.Errorf("tools.declare has an entry with no name")
		}
		for _, s := range d.Scopes {
			if s == "" {
				return fmt.Errorf("tools.declare[%q]: a scope is empty", name)
			}
		}
	}
	// A grant naming a tool nobody declared is a typo with security
	// consequences: it reads as an authorisation and grants nothing, and the
	// day someone declares that name it silently starts granting.
	for team, g := range t.Grants {
		for _, name := range g.Tools {
			if _, ok := t.Declare[name]; !ok {
				return fmt.Errorf("tools.grants[%q] allows %q, which is not in tools.declare",
					team, name)
			}
		}
	}
	for _, name := range t.Default.Tools {
		if _, ok := t.Declare[name]; !ok {
			return fmt.Errorf("tools.default allows %q, which is not in tools.declare", name)
		}
	}
	return nil
}

// Manifests converts the declarations for the envelope package.
func (t Tools) Manifests() map[string]envelope.Manifest {
	if len(t.Declare) == 0 {
		return nil
	}
	out := make(map[string]envelope.Manifest, len(t.Declare))
	for name, d := range t.Declare {
		out[name] = envelope.Manifest{
			Tool: name, Bundle: d.Bundle, Scopes: d.Scopes, Egress: d.Egress,
		}
	}
	return out
}

// GrantFor returns the allowance for one team, falling back to the default.
func (t Tools) GrantFor(team string) envelope.Grant {
	g, ok := t.Grants[team]
	if !ok {
		g = t.Default
	}
	return envelope.Grant{
		Tools: g.Tools, Scopes: g.Scopes,
		Egress: g.Egress, CrossBundleEgress: g.CrossBundleEgress,
	}
}

// DeclaredTools lists what the deployment knows about, for a report.
func (t Tools) DeclaredTools() []string {
	out := make([]string, 0, len(t.Declare))
	for name := range t.Declare {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// describe states what is declared and who holds grants, for the control
// report's evidence line.
//
// It names counts rather than listing every tool: a reviewer needs to know
// that the deployment has enumerated its tools and bounded who reaches them,
// and a report that inlines forty names is one nobody finishes reading. The
// egress count is called out separately because it is the one property that
// turns a wrong grant from a mistake into an incident.
func (t Tools) describe() string {
	if !t.Enabled {
		return ""
	}
	bundles := map[string]bool{}
	egress := 0
	for _, d := range t.Declare {
		if d.Bundle != "" {
			bundles[d.Bundle] = true
		}
		if d.Egress {
			egress++
		}
	}
	s := fmt.Sprintf("%s declared", plural(len(t.Declare), "tool", "tools"))
	if len(bundles) > 0 {
		s += fmt.Sprintf(" across %s", plural(len(bundles), "bundle", "bundles"))
	}
	s += "."
	if egress > 0 {
		// Its own sentence on purpose. Hung off the clause above it reads as a
		// count of bundles, and this is the one number in the line that decides
		// how bad a wrong grant is.
		s += fmt.Sprintf(" %d of those tools can send data outside the organisation.", egress)
	}
	if len(t.Grants) == 1 {
		s += " 1 team holds an explicit grant"
	} else {
		s += fmt.Sprintf(" %d teams hold explicit grants", len(t.Grants))
	}
	if len(t.Default.Tools) == 0 {
		s += ", and a caller with no grant of its own may call nothing."
	} else {
		s += fmt.Sprintf(", and a caller with no grant of its own may call %s.",
			plural(len(t.Default.Tools), "tool", "tools"))
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
