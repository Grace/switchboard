package envelope

import (
	"strings"
	"testing"
)

func decl(tool, bundle string, egress bool, scopes ...string) Manifest {
	return Manifest{Tool: tool, Bundle: bundle, Scopes: scopes, Egress: egress}
}

func manifests(ms ...Manifest) map[string]Manifest {
	out := map[string]Manifest{}
	for _, m := range ms {
		out[m.Tool] = m
	}
	return out
}

// Nothing is open by default. A deployment that has said nothing about a tool
// has not authorised it, and the opposite default would make every declaration
// optional.
func TestAnUndeclaredToolIsRefused(t *testing.T) {
	env := Compute([]string{"drop_database"}, manifests(decl("lookup", "", false)),
		Grant{Tools: []string{"drop_database", "lookup"}})
	if env.Permits("drop_database") {
		t.Fatal("an undeclared tool was allowed")
	}
	if len(env.Undeclared) != 1 || env.Undeclared[0] != "drop_database" {
		t.Errorf("undeclared = %v", env.Undeclared)
	}
	if !strings.Contains(env.Why("drop_database"), "no manifest") {
		t.Errorf("reason = %q", env.Why("drop_database"))
	}
}

func TestAToolOutsideTheGrantIsRefused(t *testing.T) {
	ms := manifests(decl("lookup", "", false, "customer_pii"), decl("wire", "", false, "ledger"))
	env := Compute([]string{"lookup", "wire"}, ms,
		Grant{Tools: []string{"lookup"}, Scopes: []string{"customer_pii"}})
	if !env.Permits("lookup") {
		t.Error("a granted, in-scope tool should be allowed")
	}
	if env.Permits("wire") {
		t.Error("a tool outside the grant was allowed")
	}
	if !strings.Contains(env.Why("wire"), "grant") {
		t.Errorf("reason = %q", env.Why("wire"))
	}
}

// Scope and egress are separate gates because they fail for different reasons
// and a reader should not have to infer one from the other.
func TestScopeAndEgressAreCheckedSeparately(t *testing.T) {
	ms := manifests(
		decl("read_notes", "", false, "clinical"),
		decl("email", "", true, "customer_pii"),
	)
	g := Grant{Tools: []string{"read_notes", "email"}, Scopes: []string{"customer_pii"}}

	env := Compute([]string{"read_notes", "email"}, ms, g)
	if env.Permits("read_notes") {
		t.Error("a tool reaching an unauthorised scope was allowed")
	}
	if !strings.Contains(env.Why("read_notes"), "clinical") {
		t.Errorf("the reason should name the offending scope: %q", env.Why("read_notes"))
	}
	if env.Permits("email") {
		t.Error("an egress tool was allowed without egress authorisation")
	}
	if !strings.Contains(env.Why("email"), "egress") {
		t.Errorf("reason = %q", env.Why("email"))
	}

	// Same tools, egress granted: now only the scope failure remains.
	g.Egress = true
	env = Compute([]string{"read_notes", "email"}, ms, g)
	if !env.Permits("email") {
		t.Error("egress granted should allow the egress tool")
	}
	if env.Permits("read_notes") {
		t.Error("granting egress must not widen scopes")
	}
}

// The composition case the paper's intersection was aimed at: read with one
// source, send with another, each individually permitted.
func TestCrossBundleEgressIsRefused(t *testing.T) {
	ms := manifests(
		decl("lookup", "billing", false, "customer_pii"),
		decl("email", "support", true, "customer_pii"),
	)
	g := Grant{
		Tools:  []string{"lookup", "email"},
		Scopes: []string{"customer_pii"},
		Egress: true,
	}

	// Both bundles loaded: the egress tool is refused even though egress is
	// granted, because another source's reach is in the same context.
	env := Compute([]string{"lookup", "email"}, ms, g)
	if len(env.Bundles) != 2 {
		t.Fatalf("bundles = %v", env.Bundles)
	}
	if !env.Permits("lookup") {
		t.Error("a non-egress tool should still be allowed in a mixed context")
	}
	if env.Permits("email") {
		t.Fatal("an egress tool was allowed alongside another bundle's reach")
	}
	if !strings.Contains(env.Why("email"), "cross-bundle egress") {
		t.Errorf("reason = %q", env.Why("email"))
	}

	// Explicitly authorised: allowed.
	g.CrossBundleEgress = true
	if env = Compute([]string{"lookup", "email"}, ms, g); !env.Permits("email") {
		t.Errorf("cross-bundle egress granted should allow it: %q", env.Why("email"))
	}
}

// One bundle is not a composition, and the rule must not fire there — a control
// that refuses the ordinary case gets switched off.
func TestASingleBundleIsUnaffectedByTheEgressRule(t *testing.T) {
	ms := manifests(
		decl("lookup", "billing", false, "customer_pii"),
		decl("email", "billing", true, "customer_pii"),
	)
	g := Grant{Tools: []string{"lookup", "email"}, Scopes: []string{"customer_pii"}, Egress: true}
	env := Compute([]string{"lookup", "email"}, ms, g)
	if !env.Permits("email") || !env.Permits("lookup") {
		t.Errorf("a single bundle should be unaffected: %+v", env.Refused)
	}
}

// Ungrouped tools are not a mixed context either: a deployment that has not
// declared bundles has not asked for this rule.
func TestUngroupedToolsDoNotTriggerTheEgressRule(t *testing.T) {
	ms := manifests(decl("lookup", "", false, "pii"), decl("email", "", true, "pii"))
	g := Grant{Tools: []string{"lookup", "email"}, Scopes: []string{"pii"}, Egress: true}
	env := Compute([]string{"lookup", "email"}, ms, g)
	if !env.Permits("email") {
		t.Errorf("undeclared bundles should not trigger cross-bundle refusal: %q",
			env.Why("email"))
	}
}

// An empty grant authorises nothing. A deployment that has not said what a team
// may call has not said yes.
func TestAnEmptyGrantAuthorisesNothing(t *testing.T) {
	env := Compute([]string{"lookup"}, manifests(decl("lookup", "", false)), Grant{})
	if !env.Empty() {
		t.Error("an empty grant allowed something")
	}
	if len(env.Refused) != 1 {
		t.Errorf("refused = %+v", env.Refused)
	}
}

func TestNoToolsOfferedIsAnEmptyEnvelope(t *testing.T) {
	env := Compute(nil, manifests(decl("lookup", "", false)), Grant{Tools: []string{"lookup"}})
	if !env.Empty() || len(env.Refused) != 0 {
		t.Errorf("env = %+v", env)
	}
}

// Two identical requests must produce identical audit entries.
func TestOrderIsStable(t *testing.T) {
	ms := manifests(decl("c", "", false), decl("a", "", false), decl("b", "", false))
	g := Grant{Tools: []string{"a", "c"}}
	first := Compute([]string{"c", "b", "a"}, ms, g)
	second := Compute([]string{"a", "b", "c"}, ms, g)
	if strings.Join(first.Allowed, ",") != strings.Join(second.Allowed, ",") {
		t.Errorf("allowed differs: %v vs %v", first.Allowed, second.Allowed)
	}
	if len(first.Refused) != len(second.Refused) || first.Refused[0].Tool != second.Refused[0].Tool {
		t.Errorf("refused differs: %+v vs %+v", first.Refused, second.Refused)
	}
}
