// Package databricks adapts a Databricks model serving endpoint into an
// assessable deployment.
//
// The input is whatever `databricks serving-endpoints get <name> -o json`
// prints. That choice is deliberate and is most of the product:
//
//   - No credentials. An assessment tool that wants production access is a
//     six-week security review; one that reads an export a customer already
//     has permission to run is a conversation.
//   - No dependency. Parsing JSON is the standard library. A SQL driver and an
//     OAuth flow are not, and switchboard ships as one static binary.
//   - No live access means no ambiguity about what the tool did.
//
// Parsing is deliberately permissive. Every field here is read from Databricks'
// published feature set rather than from a schema I have verified against a
// live endpoint, and their JSON will drift regardless. So an absent or renamed
// field yields assess.Unknown rather than assess.No — the difference between
// "this control is off" and "this export does not say", which is the whole
// reason assess has three states. A wrong Unknown wastes a question. A wrong
// No invents a finding, and one invented finding is all it takes for a
// customer to stop reading the report.
//
// Verify against a real endpoint before trusting any row.
package databricks

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Grace/switchboard/internal/assess"
)

// Endpoint is the shape we read. Pointers throughout: a nil pointer is "the
// export did not mention this", which is different from false.
type Endpoint struct {
	Name      string     `json:"name"`
	ID        string     `json:"id"`
	Creator   string     `json:"creator"`
	AIGateway *AIGateway `json:"ai_gateway"`
	Config    *Config    `json:"config"`
}

// AIGateway mirrors the governance block Databricks attaches to an endpoint.
type AIGateway struct {
	UsageTracking  *Toggle       `json:"usage_tracking_config"`
	InferenceTable *InferenceTbl `json:"inference_table_config"`
	RateLimits     []RateLimit   `json:"rate_limits"`
	Guardrails     *Guardrails   `json:"guardrails"`
	Fallback       *Toggle       `json:"fallback_config"`
}

type Toggle struct {
	Enabled *bool `json:"enabled"`
}

// InferenceTbl is payload logging: requests and responses written to a Unity
// Catalog table.
type InferenceTbl struct {
	Enabled         *bool  `json:"enabled"`
	CatalogName     string `json:"catalog_name"`
	SchemaName      string `json:"schema_name"`
	TableNamePrefix string `json:"table_name_prefix"`
}

type RateLimit struct {
	Calls         int    `json:"calls"`
	Key           string `json:"key"` // "user" or "endpoint"
	RenewalPeriod string `json:"renewal_period"`
}

type Guardrails struct {
	Input  *GuardrailSide `json:"input"`
	Output *GuardrailSide `json:"output"`
}

type GuardrailSide struct {
	PII             *PII     `json:"pii"`
	Safety          *bool    `json:"safety"`
	InvalidKeywords []string `json:"invalid_keywords"`
	ValidTopics     []string `json:"valid_topics"`
}

type PII struct {
	Behavior string `json:"behavior"` // "NONE" | "BLOCK" | "MASK"
}

type Config struct {
	ServedEntities []ServedEntity `json:"served_entities"`
}

type ServedEntity struct {
	Name              string `json:"name"`
	ExternalModel     *any   `json:"external_model"`
	EntityName        string `json:"entity_name"`
	WorkloadType      string `json:"workload_type"`
	ScaleToZeroEnable *bool  `json:"scale_to_zero_enabled"`
}

// Read parses an endpoint export.
func Read(r io.Reader) (*Endpoint, error) {
	var e Endpoint
	if err := json.NewDecoder(r).Decode(&e); err != nil {
		return nil, fmt.Errorf("databricks endpoint export: %w", err)
	}
	if e.Name == "" {
		return nil, fmt.Errorf("databricks endpoint export: no `name` field; " +
			"expected the output of `databricks serving-endpoints get <name> -o json`")
	}
	return &e, nil
}

// tri turns a pointer-to-bool into a tri-state: nil means the export was silent.
func tri(b *bool) assess.Support {
	if b == nil {
		return assess.Unknown
	}
	return assess.Bool(*b)
}

// Deployment describes the endpoint in assess's terms.
func (e *Endpoint) Deployment(profile assess.Profile) assess.Deployment {
	d := assess.Deployment{
		Source:  "databricks",
		Origin:  e.Name,
		Profile: profile,
	}
	g := e.AIGateway
	if g == nil {
		// No governance block at all. That is a real finding about the
		// endpoint, not a gap in the export, so it is reported as such.
		d.Caveats = append(d.Caveats,
			"The endpoint has no ai_gateway block, so no governance is configured on it. "+
				"Controls below are assessed as unmet rather than unknown.")
		d.Audit.Enabled = assess.No
		d.Runtime.Limits = assess.No
		d.Auth.DenyUnauthenticated = assess.Unknown
		return finish(d, e)
	}

	// Payload logging is the closest thing to an audit record.
	d.Audit.Enabled = assess.Unknown
	if g.InferenceTable != nil {
		d.Audit.Enabled = tri(g.InferenceTable.Enabled)
		if g.InferenceTable.CatalogName != "" {
			d.Audit.Path = strings.Join([]string{
				g.InferenceTable.CatalogName, g.InferenceTable.SchemaName,
				g.InferenceTable.TableNamePrefix,
			}, ".")
		}
	}
	// A Delta table is versioned, not chained. History is retained, and a
	// workspace admin can still rewrite it — there is no verification step that
	// fails. That is a real No rather than an Unknown.
	d.Audit.TamperEvident = assess.No
	// Nothing in the endpoint configuration refuses a request whose payload
	// cannot be logged, so an unrecordable completion is served.
	d.Audit.FailClosed = assess.No
	d.Audit.VerifyInterval = 0
	// Retention is a property of the Unity Catalog table, not of the endpoint,
	// and this export cannot see it.
	d.Audit.Retention = 0
	d.Audit.Archived = assess.Unknown
	d.Caveats = append(d.Caveats,
		"Retention and archival of the inference table are Unity Catalog properties "+
			"and are not visible in an endpoint export. Query the table's history and "+
			"any lifecycle policy separately.")

	// Guardrails. PII masking is the nearest analogue to redaction, and it
	// applies at the gateway, which is a chokepoint.
	d.Data.RedactionUnbypassable = assess.Yes
	d.Data.ContentLogged = d.Audit.Enabled
	if g.Guardrails != nil {
		d.Assurance.ContentPolicy = assess.Yes
		d.Assurance.ContentPolicyDetail = "AI Gateway guardrails are configured on the endpoint."
	} else {
		d.Assurance.ContentPolicy = assess.No
	}
	if pii := pickPII(g.Guardrails); pii != "" {
		switch strings.ToUpper(pii) {
		case "MASK", "BLOCK":
			d.Data.RedactionRules = 1
		default:
			d.Data.RedactionRules = 0
		}
	} else {
		d.Caveats = append(d.Caveats,
			"No PII guardrail is declared on this endpoint, so content protection is "+
				"assessed as absent. If masking happens upstream, say so — the export "+
				"cannot see it.")
	}

	// Rate limits.
	d.Runtime.Limits = assess.Bool(len(g.RateLimits) > 0)

	// Usage tracking attributes spend, but inside Databricks' own tables rather
	// than on the upstream provider's invoice.
	if g.UsageTracking != nil && tri(g.UsageTracking.Enabled) == assess.Yes {
		d.Auth.PerCallerProviderCreds = assess.No
		d.Caveats = append(d.Caveats,
			"Usage tracking attributes spend in Databricks system tables. For external "+
				"models the upstream provider's own invoice still shows a single identity, "+
				"so provider-side attribution is not independently confirmable.")
	} else {
		d.Auth.PerCallerProviderCreds = assess.Unknown
	}

	return finish(d, e)
}

func finish(d assess.Deployment, e *Endpoint) assess.Deployment {
	// Databricks terminates TLS on its own endpoints; that is a platform
	// property rather than one this export declares.
	d.Data.TLS = assess.Yes
	d.Data.MutualTLS = assess.Unknown
	d.Data.SealedRecovery = assess.No

	// Authentication is Databricks workspace identity, so callers are
	// authenticated and resolve to a person. What the export cannot show is
	// *who* has been granted CAN_QUERY, which is the finding that matters.
	d.Auth.OIDC = assess.Yes
	d.Auth.Issuer = "Databricks workspace identity"
	d.Auth.DenyUnauthenticated = assess.Yes
	d.Caveats = append(d.Caveats,
		"Callers are authenticated by the workspace, but this export does not list who "+
			"holds CAN_QUERY on the endpoint. Pull the permissions separately: an "+
			"authenticated caller is not the same as an authorised one.")

	// FIPS is a property of Databricks' own runtime, not something an endpoint
	// export states, and guessing either way would be inventing a finding.
	d.Runtime.FIPS = assess.Unknown
	d.Runtime.FIPSHint = "Databricks runtime property; confirm with the workspace's compliance security profile."

	if e.Config != nil {
		d.Auth.CloudProvider = assess.Bool(len(e.Config.ServedEntities) > 0)
	} else {
		d.Auth.CloudProvider = assess.Unknown
	}
	return d
}

func pickPII(g *Guardrails) string {
	if g == nil {
		return ""
	}
	for _, side := range []*GuardrailSide{g.Input, g.Output} {
		if side != nil && side.PII != nil && side.PII.Behavior != "" {
			return side.PII.Behavior
		}
	}
	return ""
}

// Queries are the system-table queries that supply what an endpoint export
// cannot. They are documentation rather than code: the customer runs them, and
// the results answer the caveats above.
//
// Verify column names against your workspace before relying on these.
var Queries = []struct{ Name, Purpose, SQL string }{
	{
		"endpoint-permissions", "who may call the endpoint — an authenticated caller is not an authorised one",
		"-- Workspace API, not a system table:\n" +
			"-- databricks permissions get serving-endpoints <endpoint-id> -o json",
	},
	{
		"inference-table-retention", "how long payload logs actually survive",
		"DESCRIBE HISTORY <catalog>.<schema>.<prefix>_payload;",
	},
	{
		"endpoint-config-changes", "whether governance was ever switched off, and by whom",
		"SELECT event_time, user_identity.email, action_name, request_params\n" +
			"FROM system.access.audit\n" +
			"WHERE service_name = 'serverlessRealTimeInference'\n" +
			"  AND event_date >= current_date() - INTERVAL 90 DAYS\n" +
			"ORDER BY event_time DESC;",
	},
}

// Since is a convenience for report headers.
func Since(d time.Duration) string { return time.Now().Add(-d).Format(time.RFC3339) }
