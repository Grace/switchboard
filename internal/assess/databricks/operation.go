package databricks

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Grace/switchboard/internal/assess"
)

// An endpoint export describes the configuration in force *now*. An examiner
// asks about a period, and the two are not the same question — a control that
// is on today tells you nothing about whether it was on in March, and a
// deployment whose governance was switched off for three weeks looks identical
// to one that was never touched.
//
// Databricks already records the difference. system.access.audit carries every
// configuration change with a timestamp and an actor, and it is queryable SQL.
// This reads the result of that query and turns it into the half of an
// assessment a config file cannot supply.
//
// It reads exported rows rather than connecting, for the same reason the
// endpoint adapter does: an assessment tool that wants warehouse credentials is
// a security review, and one that reads a file the customer already ran is a
// conversation.

// AuditQuery is the query whose output Operation parses. It is exported so the
// docs, the CLI help and the customer's runbook are all quoting the same text
// rather than three copies that drift.
//
// Column names are from Databricks' published audit log reference; confirm
// against your workspace before relying on a clean result.
const AuditQuery = `SELECT
  event_time,
  user_identity.email  AS actor,
  action_name,
  request_params
FROM system.access.audit
WHERE service_name = 'serverlessRealTimeInference'
  AND event_time >= '{from}' AND event_time < '{to}'
ORDER BY event_time`

// AuditRow is one configuration event, as the query returns it.
type AuditRow struct {
	EventTime  string            `json:"event_time"`
	Actor      string            `json:"actor"`
	ActionName string            `json:"action_name"`
	Params     map[string]string `json:"request_params"`
}

func (r AuditRow) when() (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999999", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, strings.TrimSpace(r.EventTime)); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised event_time %q", r.EventTime)
}

// Operation is what happened to an endpoint's governance across a period.
type Operation struct {
	From, To time.Time
	// Changes are the configuration events, oldest first.
	Changes []Change
	// Gaps are windows where a control was off. This is the finding: a period
	// containing a gap cannot be evidenced as compliant however the endpoint
	// is configured today.
	Gaps []Gap
	// Rows is how many audit events were read, so a report can say whether
	// the query returned anything at all.
	Rows int
}

// Change is one governance event with the actor who caused it.
type Change struct {
	At     time.Time
	Actor  string
	Action string
	// Disabled names the control this event switched off, if any.
	Disabled string
	// Enabled names the control it switched on.
	Enabled string
}

// Gap is a window during which a control was not in force.
type Gap struct {
	Control string
	From    time.Time
	// To is zero when the control was still off at the end of the period,
	// which is the worse case and reads as "and never came back".
	To time.Time
}

// Open reports whether the gap was still open when the period ended.
func (g Gap) Open() bool { return g.To.IsZero() }

// Duration is how long the control was off, bounded by the period end.
func (g Gap) Duration(periodEnd time.Time) time.Duration {
	end := g.To
	if end.IsZero() {
		end = periodEnd
	}
	return end.Sub(g.From)
}

// controls maps the request parameters Databricks records onto the control
// names this assessment uses. Only governance-affecting parameters are here:
// a change to an endpoint's compute size is not a control event and reporting
// it would bury the ones that are.
var controls = map[string]string{
	"inference_table_config": "payload logging",
	"usage_tracking_config":  "usage tracking",
	"guardrails":             "content guardrails",
	"rate_limits":            "rate limits",
}

// ReadAudit parses query output and derives the gaps.
//
// The input is a JSON array of rows — what `databricks sql` and most SQL
// clients emit with a JSON output flag.
func ReadAudit(r io.Reader, from, to time.Time) (*Operation, error) {
	var rows []AuditRow
	if err := json.NewDecoder(r).Decode(&rows); err != nil {
		return nil, fmt.Errorf("databricks audit rows: %w (expected a JSON array from %s)", err, "system.access.audit")
	}
	op := &Operation{From: from, To: to, Rows: len(rows)}

	for _, row := range rows {
		at, err := row.when()
		if err != nil {
			return nil, fmt.Errorf("databricks audit rows: %w", err)
		}
		c := Change{At: at, Actor: row.Actor, Action: row.ActionName}
		for param, name := range controls {
			v, ok := row.Params[param]
			if !ok {
				continue
			}
			// Databricks records the new value; "false"/"null"/absent enabled
			// flag is the control going off.
			if disabledValue(v) {
				c.Disabled = name
			} else {
				c.Enabled = name
			}
		}
		op.Changes = append(op.Changes, c)
	}
	sort.SliceStable(op.Changes, func(i, j int) bool { return op.Changes[i].At.Before(op.Changes[j].At) })

	// Walk forward closing gaps. A control switched off and never switched
	// back on leaves an open gap, which is the state worth shouting about.
	open := map[string]time.Time{}
	for _, c := range op.Changes {
		if c.Disabled != "" {
			if _, already := open[c.Disabled]; !already {
				open[c.Disabled] = c.At
			}
		}
		if c.Enabled != "" {
			if start, was := open[c.Enabled]; was {
				op.Gaps = append(op.Gaps, Gap{Control: c.Enabled, From: start, To: c.At})
				delete(open, c.Enabled)
			}
		}
	}
	for name, start := range open {
		op.Gaps = append(op.Gaps, Gap{Control: name, From: start})
	}
	sort.Slice(op.Gaps, func(i, j int) bool { return op.Gaps[i].From.Before(op.Gaps[j].From) })
	return op, nil
}

func disabledValue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "false", "null", "", "{}", `{"enabled":false}`, "none":
		return true
	}
	return strings.Contains(strings.ToLower(v), `"enabled":false`)
}

// Apply folds a period's operation into a deployment description.
//
// A gap does not merely add a caveat: it changes the answer. An endpoint with
// payload logging on today and off for three weeks in the period cannot be
// evidenced as having recorded that period, so the control is reported unmet
// rather than met, and the evidence says when and who.
func (op *Operation) Apply(d assess.Deployment) assess.Deployment {
	if op == nil {
		return d
	}
	if op.Rows == 0 {
		d.Caveats = append(d.Caveats, fmt.Sprintf(
			"The audit query returned no configuration events for %s to %s. Either nothing "+
				"changed, or the query did not reach system.access.audit — those look "+
				"identical from here, and only one of them is evidence.",
			op.From.Format("2006-01-02"), op.To.Format("2006-01-02")))
		return d
	}

	for _, g := range op.Gaps {
		switch g.Control {
		case "payload logging":
			d.Audit.Enabled = assess.No
		case "rate limits":
			d.Runtime.Limits = assess.No
		case "content guardrails":
			d.Assurance.ContentPolicy = assess.No
		}
		d.Caveats = append(d.Caveats, gapNote(g, op.To))
	}
	if len(op.Gaps) == 0 {
		d.Caveats = append(d.Caveats, fmt.Sprintf(
			"%d configuration event(s) in this period, none of which switched a governance "+
				"control off.", len(op.Changes)))
	}
	return d
}

func gapNote(g Gap, periodEnd time.Time) string {
	if g.Open() {
		return fmt.Sprintf("%s was switched off on %s and was still off at the end of the "+
			"period. This period cannot be evidenced as having that control in force, "+
			"whatever the endpoint looks like now.",
			g.Control, g.From.Format("2006-01-02 15:04"))
	}
	return fmt.Sprintf("%s was off from %s to %s — %s. A control that ran for most of a "+
		"period still failed the part it did not.",
		g.Control, g.From.Format("2006-01-02 15:04"), g.To.Format("2006-01-02 15:04"),
		roughDur(g.Duration(periodEnd)))
}

func roughDur(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
}
