// Package reconcile compares what this gateway recorded against what the
// provider billed.
//
// Every other comparison switchboard makes reads the log against the
// configuration, and both of those are ours. This one reads the log against a
// document produced by the company we buy inference from — the only account of
// the same events that nobody here can edit. That is what makes it the
// strongest test available: agreement is evidence, and a disagreement is a
// finding in one of two directions.
//
// Tokens the provider billed and the log did not record mean traffic reached
// the provider without passing through this gateway, or entries are missing
// from the log. Tokens the log recorded and the provider did not bill mean the
// reverse. The first is the one worth losing sleep over, because a route around
// the gateway is a route around every control attached to it.
//
// # Tokens, not requests
//
// The control this implements asks for request counts. Against Bedrock that is
// not answerable and saying so is part of the work: CUR carries no per-request
// line item and no request id, only usage aggregated by usage type over an hour
// or a day. Tokens are the quantity both sides actually hold.
//
// switchboard records all four of the token types providers bill separately,
// which is the other half of why this works. Reconciling input and output alone
// undercounts any deployment using a prompt cache, and those are most of the
// deployments worth having.
package reconcile

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Grace/switchboard/internal/audit"
)

// Kind is a token type, split the way providers bill rather than the way an
// API reports usage. They are priced differently by up to an order of
// magnitude, so a comparison that collapses them agrees with the bill only by
// coincidence.
type Kind string

const (
	Input      Kind = "input"
	Output     Kind = "output"
	CacheWrite Kind = "cache_write"
	CacheRead  Kind = "cache_read"
)

// Kinds is the fixed order every rendering uses.
var Kinds = []Kind{Input, Output, CacheWrite, CacheRead}

// Tokens is a count split by how it was billed.
type Tokens struct {
	Input      int64 `json:"input"`
	Output     int64 `json:"output"`
	CacheWrite int64 `json:"cache_write,omitempty"`
	CacheRead  int64 `json:"cache_read,omitempty"`
}

// Total is everything, however it was billed.
func (t Tokens) Total() int64 { return t.Input + t.Output + t.CacheWrite + t.CacheRead }

// Add folds one quantity in under its kind.
func (t *Tokens) Add(k Kind, n int64) {
	switch k {
	case Input:
		t.Input += n
	case Output:
		t.Output += n
	case CacheWrite:
		t.CacheWrite += n
	case CacheRead:
		t.CacheRead += n
	}
}

// Get returns one kind's count.
func (t Tokens) Get(k Kind) int64 {
	switch k {
	case Input:
		return t.Input
	case Output:
		return t.Output
	case CacheWrite:
		return t.CacheWrite
	case CacheRead:
		return t.CacheRead
	}
	return 0
}

func (t Tokens) empty() bool { return t.Total() == 0 }

// Line is one row of a provider's invoice, normalised.
//
// Model is the provider's own name for the thing, kept verbatim. It is not the
// name callers ask for and it is usually not the model id either: AWS bills
// "Claude4.6Sonnet" for what this gateway invoked as
// "anthropic.claude-sonnet-4-6-...". Nothing here tries to bridge that gap by
// resemblance — see Mapping.
type Line struct {
	// Month is YYYY-MM in UTC, because that is the calendar a bill is drawn on.
	Month string `json:"month"`
	Model string `json:"model"`
	Kind  Kind   `json:"kind"`
	// Tokens is the billed quantity.
	Tokens int64 `json:"tokens"`
	// Cost and CostKnown are kept apart because an export that does not carry
	// cost is not an export reporting zero.
	Cost      float64 `json:"cost,omitempty"`
	CostKnown bool    `json:"cost_known"`
	// Team is the attribution tag where the export carries one. Empty means the
	// bill did not say, which is not the same as unattributed traffic.
	Team string `json:"team,omitempty"`
}

// Invoice is a provider's own account of what it served.
type Invoice struct {
	// Source is where these lines were read from, for the report's header.
	Source   string `json:"source"`
	Currency string `json:"currency,omitempty"`
	Lines    []Line `json:"lines"`

	// Skipped counts rows the reader recognised as belonging to this provider
	// and could not interpret as token usage — guardrail charges, storage,
	// anything that is not inference. They are counted rather than dropped so
	// the report can say the export was not fully understood.
	Skipped int `json:"skipped,omitempty"`
	// TeamsPresent reports whether the export carried an attribution tag at
	// all. Without it, per-team reconciliation is unknown rather than absent.
	TeamsPresent bool `json:"teams_present"`
	// Notes are what the reader could not settle, in its own words.
	Notes []string `json:"notes,omitempty"`
}

// Months returns the distinct months on the invoice, in order.
func (inv Invoice) Months() []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range inv.Lines {
		if !seen[l.Month] {
			seen[l.Month] = true
			out = append(out, l.Month)
		}
	}
	sort.Strings(out)
	return out
}

// Mapping resolves a provider's billing name onto a model this gateway routes.
//
// It is declared, never guessed. A bill says "Claude4.6Sonnet" and a config
// says "claude-sonnet"; the resemblance is obvious to a person and worth
// nothing to a program, because the cost of being wrong is asymmetric. An
// unmapped line produces a question. A wrongly matched line produces a
// reconciliation that balances between two different models, and nobody goes
// looking to disprove a clean report.
type Mapping map[string]string

// Resolve returns the local model name for a billing name.
func (m Mapping) Resolve(billed string) (string, bool) {
	if m == nil {
		return "", false
	}
	if name, ok := m[billed]; ok {
		return name, true
	}
	// Case is the one difference not worth making a person configure around:
	// exports vary it and it never distinguishes two models.
	for k, v := range m {
		if strings.EqualFold(k, billed) {
			return v, true
		}
	}
	return "", false
}

// Row is one month of one model, from both sides.
type Row struct {
	Month string `json:"month"`
	// Model is this gateway's name. Billed is the name the invoice used, empty
	// where the log has rows and the invoice does not.
	Model  string `json:"model"`
	Billed string `json:"billed_as,omitempty"`

	Logged   Tokens `json:"logged"`
	Invoiced Tokens `json:"invoiced"`
	// Requests is the log's count. There is no counterpart on the invoice; it
	// is here because it is what makes a token gap actionable.
	Requests int `json:"requests"`

	Cost      float64 `json:"cost,omitempty"`
	CostKnown bool    `json:"cost_known"`

	// Edge marks a month more than a day of which falls outside the log's own
	// coverage. A shortfall there is expected and is not evidence of anything.
	Edge bool `json:"edge,omitempty"`
}

// Delta is logged minus invoiced. Negative means the provider billed for more
// than the log accounts for.
func (r Row) Delta() int64 { return r.Logged.Total() - r.Invoiced.Total() }

// Ratio is the delta as a fraction of what was invoiced, and whether that
// fraction means anything. It does not when nothing was invoiced: everything is
// infinitely more than nothing, and the renderer should say "never billed"
// rather than print a percentage.
func (r Row) Ratio() (float64, bool) {
	inv := r.Invoiced.Total()
	if inv == 0 {
		return 0, false
	}
	return float64(r.Delta()) / float64(inv), true
}

// Untagged is the team slot for traffic neither side named.
//
// On the log side it is a caller that presented no key; on the invoice side it
// is a line the provider recorded with no session tag. Those are different
// events and the report keeps the two columns apart rather than resolving them.
const Untagged = "(untagged)"

// TeamRow is one month of one team, from both sides.
//
// This is the check docs/cost-attribution.md asks for and cannot make on its
// own. switchboard assumes a role per caller and tags the session, and whether
// AWS then bills the way that expects is not testable from this side of the
// call — it needs the bill. A team the log knows and the invoice does not is
// the signature of the three failures that document names: a missing
// sts:TagSession, a cost allocation tag never activated, or looking before the
// billing lag has passed.
type TeamRow struct {
	Month string `json:"month"`
	Team  string `json:"team"`

	Logged   int64 `json:"logged"`
	Invoiced int64 `json:"invoiced"`
	Requests int   `json:"requests"`

	Edge bool `json:"edge,omitempty"`
}

// Delta is logged minus invoiced.
func (r TeamRow) Delta() int64 { return r.Logged - r.Invoiced }

// Ratio is the delta as a fraction of what was invoiced, where that means
// anything.
func (r TeamRow) Ratio() (float64, bool) {
	if r.Invoiced == 0 {
		return 0, false
	}
	return float64(r.Delta()) / float64(r.Invoiced), true
}

// FindingKind names which way a month disagrees.
type FindingKind string

const (
	// Unlogged: the provider billed for tokens this log does not account for.
	// Either traffic reached the provider without passing through this gateway,
	// or entries are missing. Both are findings and the first is the worse one.
	Unlogged FindingKind = "unlogged"
	// Unbilled: the log recorded work the provider did not charge for.
	Unbilled FindingKind = "unbilled"
)

// Finding is one month of one model where the two accounts disagree by more
// than the tolerance.
type Finding struct {
	Kind  FindingKind `json:"kind"`
	Month string      `json:"month"`
	// Exactly one of Model and Team is set. A month can disagree about what a
	// model served or about whom it was served for, and those are different
	// failures with different causes — see TeamRow.
	Model string `json:"model,omitempty"`
	Team  string `json:"team,omitempty"`

	Logged   int64   `json:"logged"`
	Invoiced int64   `json:"invoiced"`
	Delta    int64   `json:"delta"`
	Ratio    float64 `json:"ratio,omitempty"`
	// Absent marks the extreme case: one side has nothing at all. It reads
	// differently from a shortfall and deserves different words.
	Absent bool `json:"absent,omitempty"`
	Edge   bool `json:"edge,omitempty"`
}

// Unmapped is a name on the invoice that no mapping resolves.
//
// This is deliberately not a finding. It is the question that precedes one: an
// unmapped line is either a mapping nobody wrote down or a model running in
// this account that this gateway has never served, and only a person can say
// which. Reporting it as unlogged traffic would invent the answer.
type Unmapped struct {
	Model     string   `json:"model"`
	Tokens    int64    `json:"tokens"`
	Months    []string `json:"months"`
	Cost      float64  `json:"cost,omitempty"`
	CostKnown bool     `json:"cost_known"`
	// Suggest is a local model whose name resembles this one, offered so
	// somebody can confirm it. It is never applied.
	Suggest string `json:"suggest,omitempty"`
}

// Result is the comparison.
type Result struct {
	Rows     []Row      `json:"rows"`
	Findings []Finding  `json:"findings,omitempty"`
	Unmapped []Unmapped `json:"unmapped,omitempty"`

	// Teams and TeamFindings are the same comparison drawn per team, and are
	// present only where the invoice carried an attribution tag at all.
	// Without one, whether the bill splits is unknown rather than no.
	Teams        []TeamRow `json:"teams,omitempty"`
	TeamFindings []Finding `json:"team_findings,omitempty"`

	// Tolerance is the fraction below which a disagreement was not reported.
	Tolerance float64 `json:"tolerance"`
	Currency  string  `json:"currency,omitempty"`
	Source    string  `json:"invoice_source,omitempty"`

	// Entries, First and Last describe what was read from the log.
	Entries int       `json:"entries"`
	First   time.Time `json:"first_seen,omitempty"`
	Last    time.Time `json:"last_seen,omitempty"`

	// Local counts entries served by a backend that bills nobody. They are
	// excluded from the comparison rather than reported as never billed.
	Local int `json:"local_entries,omitempty"`
	// UnknownBackend counts entries recording no backend at all — written
	// before the field existed. They are included, because excluding an entry
	// on a guess would hide exactly the traffic this looks for.
	UnknownBackend int `json:"unknown_backend_entries,omitempty"`

	// NoInvoice names months the log holds traffic for and the invoice holds no
	// line of any kind for. It is reported once per month rather than as a
	// never-billed finding against every model in it: an export that stopped
	// short and a provider that billed nothing look identical from here, and
	// per-model findings would assert the second.
	NoInvoice []string `json:"months_with_no_invoice,omitempty"`
	// Outside names months the invoice covers that the log was not read for.
	// Comparing them would report every one as unlogged traffic, which would be
	// an artefact of the window rather than an observation.
	Outside []string `json:"outside_window,omitempty"`
	// TeamsPresent reports whether the invoice carried attribution tags.
	TeamsPresent bool `json:"teams_present"`
	// UnitHint is a factor every comparable month disagrees by, when there is
	// one. See unitHint.
	UnitHint float64 `json:"unit_hint,omitempty"`
	// Skipped is the invoice reader's count of rows it could not interpret.
	Skipped int      `json:"skipped_rows,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

// Clean reports whether every comparable month agreed within tolerance.
func (r Result) Clean() bool { return len(r.Findings) == 0 }

// SplitOnly reports that the teams disagree in months where the models did not.
//
// It is the difference between "tokens are missing" and "tokens are on the bill
// and charged to the wrong caller", which are different problems with different
// fixes, and the reader should not have to derive which one this is by
// comparing two tables.
func (r Result) SplitOnly() bool {
	if len(r.TeamFindings) == 0 {
		return false
	}
	bad := map[string]bool{}
	for _, f := range r.Findings {
		bad[f.Month] = true
	}
	for _, f := range r.TeamFindings {
		if bad[f.Month] {
			return false
		}
	}
	return true
}

type cell struct {
	row   Row
	first time.Time
	last  time.Time
}

// Builder accumulates the log side.
type Builder struct {
	cells map[string]*cell
	order []string
	teams map[string]*TeamRow

	entries        int
	first, last    time.Time
	local          int
	unknownBackend int
}

// New starts a comparison.
func New() *Builder {
	return &Builder{cells: map[string]*cell{}, teams: map[string]*TeamRow{}}
}

// Month is the bucket a time falls in, in UTC. A bill is drawn on the
// provider's calendar, so a local-midnight boundary would put a week of
// December traffic in the wrong month for anyone east of Greenwich.
func Month(t time.Time) string { return t.UTC().Format("2006-01") }

// Add folds one record into the log side.
func (b *Builder) Add(r audit.Record) {
	b.entries++
	if !r.Time.IsZero() {
		if b.first.IsZero() || r.Time.Before(b.first) {
			b.first = r.Time
		}
		if r.Time.After(b.last) {
			b.last = r.Time
		}
	}
	// Nothing bills for a model running on this machine, so counting it here
	// would produce a permanent, meaningless "never billed" row.
	if r.Backend == "local" {
		b.local++
		return
	}
	if r.Backend == "" {
		b.unknownBackend++
	}
	if r.Model == "" || r.Time.IsZero() {
		return
	}

	key := Month(r.Time) + "\x00" + r.Model
	c, ok := b.cells[key]
	if !ok {
		c = &cell{row: Row{Month: Month(r.Time), Model: r.Model}}
		b.cells[key] = c
		b.order = append(b.order, key)
	}
	c.row.Requests++
	// PromptTokens is the uncached part of the prompt — the record keeps the
	// three prompt figures apart, exactly as CUR bills them — so this is a
	// straight copy into four buckets and not a subtraction.
	c.row.Logged.Input += int64(r.PromptTokens)
	c.row.Logged.Output += int64(r.CompletionTokens)
	c.row.Logged.CacheWrite += int64(r.CacheWriteTokens)
	c.row.Logged.CacheRead += int64(r.CacheReadTokens)
	if c.first.IsZero() || r.Time.Before(c.first) {
		c.first = r.Time
	}
	if r.Time.After(c.last) {
		c.last = r.Time
	}

	// The team the gateway asserted. Whether the provider recorded the same one
	// is the question; keeping the two apart is how it stays a question.
	team := r.Team
	if team == "" {
		team = Untagged
	}
	tkey := Month(r.Time) + "\x00" + team
	tr, ok := b.teams[tkey]
	if !ok {
		tr = &TeamRow{Month: Month(r.Time), Team: team}
		b.teams[tkey] = tr
	}
	tr.Requests++
	tr.Logged += int64(r.PromptTokens) + int64(r.CompletionTokens) +
		int64(r.CacheWriteTokens) + int64(r.CacheReadTokens)
}

// DefaultTolerance is the fraction a month may disagree by before it is
// reported.
//
// Not zero, because exact agreement never happens and a report that cries every
// month is one nobody reads. A request that begins at 23:59:58 is logged in one
// month and may be billed in the next; a streamed response the client abandoned
// leaves a partial count; CUR aggregates and rounds. All of those are fractions
// of a percent on any real volume. One percent is above that noise and far
// below any gap worth the name — a single unlogged application is tens of
// percent, not one.
const DefaultTolerance = 0.01

// Compare sets the log side against the invoice.
func (b *Builder) Compare(inv Invoice, m Mapping, tolerance float64) Result {
	res := Result{
		Tolerance:      tolerance,
		Currency:       inv.Currency,
		Source:         inv.Source,
		Entries:        b.entries,
		First:          b.first,
		Last:           b.last,
		Local:          b.local,
		UnknownBackend: b.unknownBackend,
		TeamsPresent:   inv.TeamsPresent,
		Skipped:        inv.Skipped,
		Notes:          inv.Notes,
	}

	// Months the log was actually read for. An invoice month outside this is
	// not a discrepancy — nobody asked the log about it.
	covered := map[string]bool{}
	for _, key := range b.order {
		covered[b.cells[key].row.Month] = true
	}
	if !b.first.IsZero() {
		for t := b.first.UTC(); !t.After(b.last.UTC()); t = t.AddDate(0, 1, 0) {
			covered[Month(t)] = true
		}
		covered[Month(b.last)] = true
	}

	// Fold the invoice onto the same grid, and hold back what does not map.
	type inv2 struct {
		tok       Tokens
		cost      float64
		costKnown bool
		billed    string
	}
	billed := map[string]*inv2{}
	billedTeams := map[string]int64{}
	unmapped := map[string]*Unmapped{}
	var outside []string
	seenOutside := map[string]bool{}

	for _, l := range inv.Lines {
		name, ok := m.Resolve(l.Model)
		if !ok {
			u := unmapped[l.Model]
			if u == nil {
				u = &Unmapped{Model: l.Model}
				unmapped[l.Model] = u
			}
			u.Tokens += l.Tokens
			if l.CostKnown {
				u.Cost += l.Cost
				u.CostKnown = true
			}
			if !contains(u.Months, l.Month) {
				u.Months = append(u.Months, l.Month)
			}
			continue
		}
		if !covered[l.Month] {
			if !seenOutside[l.Month] {
				seenOutside[l.Month] = true
				outside = append(outside, l.Month)
			}
			continue
		}
		key := l.Month + "\x00" + name
		e := billed[key]
		if e == nil {
			e = &inv2{billed: l.Model}
			billed[key] = e
		}
		e.tok.Add(l.Kind, l.Tokens)
		if l.CostKnown {
			e.cost += l.Cost
			e.costKnown = true
		}
		// Only lines that mapped to a model this gateway routes. An unmapped
		// model's team would be compared against a log that never saw it, and
		// would report a team shortfall caused by a missing model mapping.
		team := l.Team
		if team == "" {
			team = Untagged
		}
		billedTeams[l.Month+"\x00"+team] += l.Tokens
	}
	sort.Strings(outside)
	res.Outside = outside

	// Every month/model either side knows about, so a row missing from one of
	// them is still a row.
	keys := map[string]bool{}
	for _, k := range b.order {
		keys[k] = true
	}
	for k := range billed {
		keys[k] = true
	}

	for k := range keys {
		month, model, _ := strings.Cut(k, "\x00")
		row := Row{Month: month, Model: model}
		if c, ok := b.cells[k]; ok {
			row = c.row
		}
		if e, ok := billed[k]; ok {
			row.Invoiced = e.tok
			row.Billed = e.billed
			row.Cost, row.CostKnown = e.cost, e.costKnown
		}
		row.Edge = b.edge(month)
		res.Rows = append(res.Rows, row)
	}
	sort.SliceStable(res.Rows, func(i, j int) bool {
		if res.Rows[i].Month != res.Rows[j].Month {
			return res.Rows[i].Month < res.Rows[j].Month
		}
		return res.Rows[i].Model < res.Rows[j].Model
	})

	// Months the invoice says nothing about at all, before mapping — an export
	// that stopped short is not a month of unbilled models.
	invMonths := map[string]bool{}
	for _, l := range inv.Lines {
		invMonths[l.Month] = true
	}
	silent := map[string]bool{}
	for _, row := range res.Rows {
		if row.Logged.Total() > 0 && !invMonths[row.Month] {
			silent[row.Month] = true
		}
	}
	for month := range silent {
		res.NoInvoice = append(res.NoInvoice, month)
	}
	sort.Strings(res.NoInvoice)

	for _, row := range res.Rows {
		if silent[row.Month] {
			continue
		}
		if f, ok := judge(judged{Month: row.Month, Model: row.Model,
			Logged: row.Logged.Total(), Invoiced: row.Invoiced.Total(), Edge: row.Edge}, tolerance); ok {
			res.Findings = append(res.Findings, f)
		}
	}
	// Biggest disagreement first: this list is triage, not a ledger.
	sort.SliceStable(res.Findings, func(i, j int) bool {
		return abs(res.Findings[i].Delta) > abs(res.Findings[j].Delta)
	})

	// The same comparison per team, which is what tests whether the bill splits
	// the way this gateway's attribution says it should. Only where the export
	// carried a tag at all: without one this would report every team as never
	// billed, which would be a finding about a missing column.
	if inv.TeamsPresent {
		tkeys := map[string]bool{}
		for k, tr := range b.teams {
			if covered[tr.Month] {
				tkeys[k] = true
			}
		}
		for k := range billedTeams {
			tkeys[k] = true
		}
		for k := range tkeys {
			month, team, _ := strings.Cut(k, "\x00")
			if silent[month] {
				continue
			}
			tr := TeamRow{Month: month, Team: team}
			if have, ok := b.teams[k]; ok {
				tr = *have
			}
			tr.Invoiced = billedTeams[k]
			tr.Edge = b.edge(month)
			res.Teams = append(res.Teams, tr)
			if f, ok := judge(judged{Month: month, Team: team,
				Logged: tr.Logged, Invoiced: tr.Invoiced, Edge: tr.Edge}, tolerance); ok {
				res.TeamFindings = append(res.TeamFindings, f)
			}
		}
		sort.SliceStable(res.Teams, func(i, j int) bool {
			if res.Teams[i].Month != res.Teams[j].Month {
				return res.Teams[i].Month < res.Teams[j].Month
			}
			return res.Teams[i].Team < res.Teams[j].Team
		})
		// Ledger order, not magnitude order. A mis-attribution is one fault
		// repeating every month, and sorting by size shuffles the months
		// together and hides that it is one fault.
		sort.SliceStable(res.TeamFindings, func(i, j int) bool {
			if res.TeamFindings[i].Month != res.TeamFindings[j].Month {
				return res.TeamFindings[i].Month < res.TeamFindings[j].Month
			}
			return res.TeamFindings[i].Team < res.TeamFindings[j].Team
		})
	}

	res.UnitHint = unitHint(res.Rows)

	local := make([]string, 0, len(b.order))
	seenLocal := map[string]bool{}
	for _, k := range b.order {
		if n := b.cells[k].row.Model; !seenLocal[n] {
			seenLocal[n] = true
			local = append(local, n)
		}
	}
	for _, u := range unmapped {
		sort.Strings(u.Months)
		u.Suggest = suggest(u.Model, local)
		res.Unmapped = append(res.Unmapped, *u)
	}
	sort.SliceStable(res.Unmapped, func(i, j int) bool {
		return res.Unmapped[i].Tokens > res.Unmapped[j].Tokens
	})
	return res
}

// unitHint looks for a discrepancy that is a unit and not a gap.
//
// Providers do not all denominate token usage the same way, and a bill drawn in
// thousands of tokens against a log counting tokens disagrees by a factor of a
// thousand in every row at once. That is not missing traffic and reporting it
// as missing traffic would send somebody looking for an application that does
// not exist — the opposite failure from staying silent, and just as expensive.
//
// The signature is specific: every comparable month, of every model, off by the
// same round factor. One month off by a thousand is a finding; all of them off
// by exactly a thousand is a units question, and this only claims the second.
func unitHint(rows []Row) float64 {
	var factors []float64
	for _, r := range rows {
		l, i := r.Logged.Total(), r.Invoiced.Total()
		if l == 0 || i == 0 {
			continue
		}
		factors = append(factors, float64(l)/float64(i))
	}
	// One row agreeing with itself proves nothing about a convention.
	if len(factors) < 2 {
		return 0
	}
	for _, want := range []float64{1e-6, 1e-3, 1e3, 1e6} {
		all := true
		for _, f := range factors {
			// Compared in ratio rather than difference, because a factor of a
			// millionth and a factor of a million are the same claim.
			if f/want > 1.02 || f/want < 0.98 {
				all = false
				break
			}
		}
		if all {
			return want
		}
	}
	return 0
}

// judged is the shape judge needs: two totals for one month, whatever they are
// totals of.
type judged struct {
	Month, Model, Team string
	Logged, Invoiced   int64
	Edge               bool
}

func (j judged) ratio() (float64, bool) {
	if j.Invoiced == 0 {
		return 0, false
	}
	return float64(j.Logged-j.Invoiced) / float64(j.Invoiced), true
}

// judge decides whether one month's disagreement is worth reporting.
func judge(row judged, tolerance float64) (Finding, bool) {
	logged, invoiced := row.Logged, row.Invoiced
	if logged == 0 && invoiced == 0 {
		return Finding{}, false
	}
	delta := logged - invoiced
	f := Finding{
		Month: row.Month, Model: row.Model, Team: row.Team,
		Logged: logged, Invoiced: invoiced, Delta: delta,
		Absent: logged == 0 || invoiced == 0,
		Edge:   row.Edge,
	}
	if delta < 0 {
		f.Kind = Unlogged
	} else {
		f.Kind = Unbilled
	}
	if r, ok := row.ratio(); ok {
		f.Ratio = r
		if abs64(r) <= tolerance {
			return Finding{}, false
		}
	}
	// A month the log only partly covers is short by construction. Reporting it
	// would train a reader to skip the section that holds the real findings.
	if f.Edge && f.Kind == Unlogged {
		return Finding{}, false
	}
	return f, true
}

// edge reports whether more than a day of a month falls outside the log's own
// coverage. Below a day this is a clock, not a gap: a log covering a whole
// January still begins a few minutes after midnight on the first.
func (b *Builder) edge(month string) bool {
	if b.first.IsZero() {
		return false
	}
	start, err := time.Parse("2006-01", month)
	if err != nil {
		return false
	}
	start = start.UTC()
	end := start.AddDate(0, 1, 0)
	const grace = 24 * time.Hour
	return b.first.UTC().Sub(start) > grace || end.Sub(b.last.UTC()) > grace
}

// suggest offers a local model whose name resembles a billing name, for a
// person to confirm. Resemblance is not evidence, so this never becomes a
// match — it only saves somebody typing a mapping.
//
// Where two local models resemble the same billing name, nothing is suggested.
// Ambiguity is the honest answer, and picking one of them is how a suggestion
// turns into the wrong mapping.
func suggest(billed string, local []string) string {
	want := letters(billed)
	if want == "" {
		return ""
	}
	found := ""
	for _, name := range local {
		got := letters(name)
		if got == "" || !(strings.Contains(want, got) || strings.Contains(got, want)) {
			continue
		}
		if found != "" {
			return ""
		}
		found = name
	}
	return found
}

// letters reduces a name to its lowercased letters, so "Claude4.6Sonnet" and
// "claude-sonnet" can be compared at all.
//
// Version digits are dropped rather than compared. A bill writes 4.6 where a
// config writes 4-6 or nothing, so keeping them would suppress every useful
// suggestion — and it would be the wrong place to be strict anyway, because
// this output is a prompt to a person and not a decision. Which version the
// bill means is exactly what they have to check before writing the mapping.
func letters(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func abs64(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

// subject names what this finding is about, in the words the sentence needs.
func (f Finding) subject() string {
	if f.Team != "" {
		if f.Team == Untagged {
			return "traffic carrying no team"
		}
		return "team " + f.Team
	}
	return f.Model
}

// Describe renders a finding as the sentence a report should carry.
func (f Finding) Describe() string {
	if f.Team != "" {
		return f.describeTeam()
	}
	switch {
	case f.Kind == Unlogged && f.Absent:
		return fmt.Sprintf("The provider billed %s tokens for %s in %s and this log holds no entry "+
			"for it at all. Either that traffic reached the provider without passing through this "+
			"gateway, or the entries are gone.", commas(f.Invoiced), f.Model, f.Month)
	case f.Kind == Unlogged:
		return fmt.Sprintf("The provider billed %s tokens more than the log accounts for (%.1f%% of "+
			"the bill). Either some of that traffic bypassed this gateway, or entries are missing.",
			commas(-f.Delta), 100*abs64(f.Ratio))
	case f.Kind == Unbilled && f.Absent:
		return fmt.Sprintf("The log recorded %s tokens for %s in %s and the invoice carries no line "+
			"for it. Nothing was charged for work this gateway believes it sent.",
			commas(f.Logged), f.Model, f.Month)
	default:
		return fmt.Sprintf("The log recorded %s tokens more than the provider billed (%.1f%% of the "+
			"bill). The gateway believes it sent work the provider did not charge for.",
			commas(f.Delta), 100*abs64(f.Ratio))
	}
}

// describeTeam is deliberately different wording, because a team disagreement
// is usually a different event from a model one.
//
// Tokens missing from a model's row may not have passed through this gateway at
// all. Tokens missing from a team's row are, most of the time, on the bill —
// charged to somebody else. Saying "traffic bypassed the gateway" here would
// send somebody hunting for an application that does not exist, when the answer
// is a session tag that never arrived.
func (f Finding) describeTeam() string {
	who := f.subject()
	switch {
	case f.Kind == Unlogged && f.Absent:
		return fmt.Sprintf("The provider attributed %s tokens to %s in %s and this gateway "+
			"attributed none. Either something reaches the provider under that identity without "+
			"passing through here, or the tag on the bill does not mean what this log's team means.",
			commas(f.Invoiced), who, f.Month)
	case f.Kind == Unlogged:
		return fmt.Sprintf("The provider attributed %s tokens more to %s than this gateway did "+
			"(%.1f%% of what it was billed for). Some other caller's traffic is being charged here.",
			commas(-f.Delta), who, 100*abs64(f.Ratio))
	case f.Kind == Unbilled && f.Absent:
		return fmt.Sprintf("This gateway attributed %s tokens to %s in %s and the bill carries none. "+
			"That work is on the bill under some other identity — usually the gateway's own role, "+
			"which is what an untagged session looks like.", commas(f.Logged), who, f.Month)
	default:
		return fmt.Sprintf("This gateway attributed %s tokens more to %s than the provider did "+
			"(%.1f%% of what it was billed for).", commas(f.Delta), who, 100*abs64(f.Ratio))
	}
}

// commas groups digits so a nine-figure token count can be read at a glance.
func commas(n int64) string {
	if n < 0 {
		return "-" + commas(-n)
	}
	s := fmt.Sprint(n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}
