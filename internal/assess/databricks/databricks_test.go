package databricks

import (
	"strings"
	"testing"

	"github.com/Grace/switchboard/internal/assess"
)

func read(t *testing.T, body string) *Endpoint {
	t.Helper()
	e, err := Read(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// The distinction the whole adapter exists to preserve: a field the export
// omits is not a field that is switched off.
func TestSilentFieldIsUnknownNotOff(t *testing.T) {
	silent := read(t, `{"name":"ep","ai_gateway":{}}`).Deployment(assess.ProfileNone)
	if got := silent.Audit.Enabled; got != assess.Unknown {
		t.Errorf("no inference_table_config: want unknown, got %v", got)
	}

	off := read(t, `{"name":"ep","ai_gateway":{"inference_table_config":{"enabled":false}}}`).
		Deployment(assess.ProfileNone)
	if got := off.Audit.Enabled; got != assess.No {
		t.Errorf("explicitly disabled: want no, got %v", got)
	}

	on := read(t, `{"name":"ep","ai_gateway":{"inference_table_config":{"enabled":true,
	  "catalog_name":"main","schema_name":"ml","table_name_prefix":"ep"}}}`).
		Deployment(assess.ProfileNone)
	if got := on.Audit.Enabled; got != assess.Yes {
		t.Errorf("explicitly enabled: want yes, got %v", got)
	}
	if on.Audit.Path != "main.ml.ep" {
		t.Errorf("path should name the Unity Catalog table, got %q", on.Audit.Path)
	}
}

// No governance block is a finding about the endpoint, not silence in the file.
func TestNoGatewayBlockIsAFinding(t *testing.T) {
	d := read(t, `{"name":"ep"}`).Deployment(assess.ProfileNone)
	if d.Audit.Enabled != assess.No || d.Runtime.Limits != assess.No {
		t.Errorf("an endpoint with no ai_gateway has no governance: %+v", d)
	}
	if len(d.Caveats) == 0 {
		t.Error("should say why it concluded that")
	}
}

func TestPayloadLoggingIsNotTamperEvident(t *testing.T) {
	// A Delta table keeps history and a workspace admin can still rewrite it.
	// There is no verification step that fails, so this is No, not Unknown.
	d := read(t, `{"name":"ep","ai_gateway":{"inference_table_config":{"enabled":true}}}`).
		Deployment(assess.ProfileNone)
	if d.Audit.TamperEvident != assess.No {
		t.Errorf("want no, got %v", d.Audit.TamperEvident)
	}
	row := findControl(t, assess.Assess(d), "protected from modification")
	if row.Status != assess.StatusUnmet {
		t.Errorf("want unmet, got %q — %s", row.Status, row.Evidence)
	}
}

func TestPIIGuardrailCountsAsRedaction(t *testing.T) {
	masked := read(t, `{"name":"ep","ai_gateway":{"guardrails":{"input":{"pii":{"behavior":"MASK"}}}}}`).
		Deployment(assess.ProfileNone)
	if masked.Data.RedactionRules == 0 {
		t.Error("a MASK guardrail is redaction at a chokepoint")
	}
	none := read(t, `{"name":"ep","ai_gateway":{"guardrails":{"input":{"pii":{"behavior":"NONE"}}}}}`).
		Deployment(assess.ProfileNone)
	if none.Data.RedactionRules != 0 {
		t.Error("NONE is not redaction")
	}
}

func TestRateLimitsMapToLimits(t *testing.T) {
	d := read(t, `{"name":"ep","ai_gateway":{"rate_limits":[{"calls":100,"key":"user","renewal_period":"minute"}]}}`).
		Deployment(assess.ProfileNone)
	if d.Runtime.Limits != assess.Yes {
		t.Errorf("want yes, got %v", d.Runtime.Limits)
	}
}

// The report must never claim FIPS either way from an endpoint export.
func TestFIPSIsNeverAsserted(t *testing.T) {
	d := read(t, `{"name":"ep","ai_gateway":{}}`).Deployment(assess.ProfileFedRAMP)
	if d.Runtime.FIPS != assess.Unknown {
		t.Errorf("an endpoint export cannot know this: got %v", d.Runtime.FIPS)
	}
	row := findControl(t, assess.Assess(d), "FIPS")
	if row.Status != assess.StatusUnknown {
		t.Errorf("want unknown even under a regime that requires it, got %q", row.Status)
	}
}

func TestRejectsSomethingThatIsNotAnEndpoint(t *testing.T) {
	if _, err := Read(strings.NewReader(`{"cluster_id":"abc"}`)); err == nil {
		t.Fatal("should refuse input with no endpoint name")
	}
}

func TestUnknownsDoNotFailStrict(t *testing.T) {
	// An export that says little must not manufacture failures.
	rep := assess.Assess(read(t, `{"name":"ep","ai_gateway":{}}`).Deployment(assess.ProfileNone))
	for _, c := range rep.Controls {
		if c.Status == assess.StatusUnknown && !strings.Contains(c.Evidence, "databricks") {
			t.Errorf("unknown rows must name the source: %q", c.Evidence)
		}
	}
}

func findControl(t *testing.T, rep assess.ControlReport, objective string) assess.Control {
	t.Helper()
	for _, c := range rep.Controls {
		if strings.Contains(c.Objective, objective) {
			return c
		}
	}
	t.Fatalf("no control matching %q", objective)
	return assess.Control{}
}
