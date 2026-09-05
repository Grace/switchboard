package reconcile

import (
	"strings"
	"testing"
	"time"

	"github.com/Grace/switchboard/internal/audit"
)

func at(day int) time.Time {
	return time.Date(2026, 8, day, 12, 0, 0, 0, time.UTC)
}

// rec is one completion on the given day of August 2026.
func rec(day int, model string, in, out int) audit.Record {
	return audit.Record{
		Time: at(day), Model: model, Backend: "bedrock",
		PromptTokens: in, CompletionTokens: out,
	}
}

// span fills a month either side of the window so no row is an edge month; the
// edge rule is tested on its own below.
func span(b *Builder, model string) {
	b.Add(audit.Record{Time: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		Model: model, Backend: "bedrock", PromptTokens: 0})
	b.Add(audit.Record{Time: time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC),
		Model: model, Backend: "bedrock", PromptTokens: 0})
}

func inv(lines ...Line) Invoice { return Invoice{Currency: "USD", Lines: lines} }

func line(month, model string, k Kind, n int64) Line {
	return Line{Month: month, Model: model, Kind: k, Tokens: n}
}

var m = Mapping{"Claude4.6Sonnet": "claude-sonnet"}

// The whole point of the exercise: two accounts of the same month, one of which
// this deployment did not write, agreeing.
func TestAgreementWithinToleranceIsNotAFinding(t *testing.T) {
	b := New()
	span(b, "claude-sonnet")
	b.Add(rec(4, "claude-sonnet", 1_000_000, 200_000))

	// A tenth of a percent apart, which is what a month boundary and a
	// rounded aggregate look like.
	res := b.Compare(inv(
		line("2026-08", "Claude4.6Sonnet", Input, 1_001_000),
		line("2026-08", "Claude4.6Sonnet", Output, 200_000),
	), m, DefaultTolerance)

	if !res.Clean() {
		t.Fatalf("a month agreeing to 0.08%% was reported: %+v", res.Findings)
	}
}

// The finding this exists for. Tokens on the bill that the log cannot account
// for are either a route around the gateway or a gap in the record.
func TestBilledMoreThanLoggedIsUnloggedTraffic(t *testing.T) {
	b := New()
	span(b, "claude-sonnet")
	b.Add(rec(4, "claude-sonnet", 1_000_000, 0))

	res := b.Compare(inv(line("2026-08", "Claude4.6Sonnet", Input, 1_400_000)), m, DefaultTolerance)
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %+v", res.Findings)
	}
	f := res.Findings[0]
	if f.Kind != Unlogged {
		t.Errorf("kind = %s, want %s", f.Kind, Unlogged)
	}
	if f.Delta != -400_000 {
		t.Errorf("delta = %d", f.Delta)
	}
	if f.Absent {
		t.Error("the log held entries for this month; it is a shortfall, not an absence")
	}
}

func TestLoggedMoreThanBilledIsUnbilled(t *testing.T) {
	b := New()
	span(b, "claude-sonnet")
	b.Add(rec(4, "claude-sonnet", 2_000_000, 0))

	res := b.Compare(inv(line("2026-08", "Claude4.6Sonnet", Input, 1_000_000)), m, DefaultTolerance)
	if len(res.Findings) != 1 || res.Findings[0].Kind != Unbilled {
		t.Fatalf("want one unbilled finding, got %+v", res.Findings)
	}
}

// A bill with no matching log rows at all reads differently from a shortfall,
// and the report says so in different words.
func TestNothingLoggedAtAllIsMarkedAbsent(t *testing.T) {
	b := New()
	span(b, "claude-sonnet")
	b.Add(rec(4, "claude-sonnet", 1_000_000, 0))

	res := b.Compare(inv(
		line("2026-08", "Claude4.6Sonnet", Input, 1_000_000),
		line("2026-08", "Titan", Input, 900_000),
	), Mapping{"Claude4.6Sonnet": "claude-sonnet", "Titan": "titan"}, DefaultTolerance)

	var found bool
	for _, f := range res.Findings {
		if f.Model == "titan" {
			found = true
			if !f.Absent || f.Kind != Unlogged {
				t.Errorf("titan finding = %+v", f)
			}
		}
	}
	if !found {
		t.Fatalf("a model billed and never logged produced no finding: %+v", res.Findings)
	}
}

// Reconciling input and output alone undercounts anything using a prompt
// cache, which is the single most common way this test is run and passed
// wrongly. The log keeps the four buckets apart and so must the comparison.
func TestCacheTokensAreReconciled(t *testing.T) {
	b := New()
	span(b, "claude-sonnet")
	r := rec(4, "claude-sonnet", 100_000, 50_000)
	r.CacheReadTokens = 4_000_000
	r.CacheWriteTokens = 200_000
	b.Add(r)

	full := inv(
		line("2026-08", "Claude4.6Sonnet", Input, 100_000),
		line("2026-08", "Claude4.6Sonnet", Output, 50_000),
		line("2026-08", "Claude4.6Sonnet", CacheRead, 4_000_000),
		line("2026-08", "Claude4.6Sonnet", CacheWrite, 200_000),
	)
	if res := b.Compare(full, m, DefaultTolerance); !res.Clean() {
		t.Fatalf("a month agreeing on all four token types was reported: %+v", res.Findings)
	}

	// And the same log against a bill that only mentions input and output is a
	// disagreement, not a pass.
	partial := inv(
		line("2026-08", "Claude4.6Sonnet", Input, 100_000),
		line("2026-08", "Claude4.6Sonnet", Output, 50_000),
	)
	if res := b.Compare(partial, m, DefaultTolerance); res.Clean() {
		t.Fatal("cached tokens were dropped from the comparison")
	}
}

// An unmapped billing name is a question for a person, not an answer. Reporting
// it as unlogged traffic would invent which of the two explanations is true.
func TestUnmappedIsAQuestionNotAFinding(t *testing.T) {
	b := New()
	span(b, "claude-sonnet")
	b.Add(rec(4, "claude-sonnet", 1_000_000, 0))

	res := b.Compare(inv(
		line("2026-08", "Claude4.6Sonnet", Input, 1_000_000),
		line("2026-08", "Nova2.0Lite", Input, 8_000_000),
	), m, DefaultTolerance)

	if len(res.Findings) != 0 {
		t.Fatalf("an unmapped line was reported as a finding: %+v", res.Findings)
	}
	if len(res.Unmapped) != 1 || res.Unmapped[0].Model != "Nova2.0Lite" {
		t.Fatalf("unmapped = %+v", res.Unmapped)
	}
	if res.Unmapped[0].Tokens != 8_000_000 {
		t.Errorf("unmapped tokens = %d", res.Unmapped[0].Tokens)
	}
}

// Resemblance is offered for a person to confirm and never acted on. A wrong
// automatic match reconciles two different models and reports a clean month,
// and nobody goes looking to disprove good news.
func TestResemblanceSuggestsAndDoesNotMatch(t *testing.T) {
	b := New()
	span(b, "claude-sonnet")
	b.Add(rec(4, "claude-sonnet", 1_000_000, 0))

	res := b.Compare(inv(line("2026-08", "Claude4.6Sonnet", Input, 1_000_000)), nil, DefaultTolerance)
	if len(res.Unmapped) != 1 {
		t.Fatalf("unmapped = %+v", res.Unmapped)
	}
	if res.Unmapped[0].Suggest != "claude-sonnet" {
		t.Errorf("suggest = %q, want the resembling local name", res.Unmapped[0].Suggest)
	}
	// And the log side still stands alone, unreconciled.
	for _, row := range res.Rows {
		if row.Model == "claude-sonnet" && row.Month == "2026-08" && !row.Invoiced.empty() {
			t.Fatal("a resembling name was silently reconciled")
		}
	}
}

// Nothing bills for a model on this machine, so counting it would produce a
// permanent unbilled finding that is true and means nothing.
func TestLocalTrafficIsExcluded(t *testing.T) {
	b := New()
	span(b, "claude-sonnet")
	b.Add(rec(4, "claude-sonnet", 1_000_000, 0))
	for d := 1; d <= 5; d++ {
		b.Add(audit.Record{Time: at(d), Model: "qwen3-8b", Backend: "local",
			PromptTokens: 900_000, CompletionTokens: 900_000})
	}

	res := b.Compare(inv(line("2026-08", "Claude4.6Sonnet", Input, 1_000_000)), m, DefaultTolerance)
	if !res.Clean() {
		t.Fatalf("local traffic leaked into the comparison: %+v", res.Findings)
	}
	if res.Local != 5 {
		t.Errorf("local = %d, want 5 counted and excluded", res.Local)
	}
}

// An entry written before the backend field existed says nothing about where it
// went. Excluding it on a guess would hide exactly the traffic this looks for.
func TestEntriesWithNoBackendAreCountedAndKept(t *testing.T) {
	b := New()
	b.Add(audit.Record{Time: at(4), Model: "claude-sonnet", PromptTokens: 1_000_000})
	res := b.Compare(Invoice{}, m, DefaultTolerance)
	if res.UnknownBackend != 1 {
		t.Errorf("unknown backend = %d, want 1", res.UnknownBackend)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("an entry with no backend was dropped: %+v", res.Rows)
	}
}

// A month the log only partly covers is short by construction. Reporting it
// would train a reader to skip past the section holding the real findings.
func TestPartlyCoveredMonthIsNotReportedAsUnlogged(t *testing.T) {
	b := New()
	// The log begins on the 20th, so most of August is outside it.
	b.Add(rec(20, "claude-sonnet", 100_000, 0))
	b.Add(rec(28, "claude-sonnet", 100_000, 0))

	res := b.Compare(inv(line("2026-08", "Claude4.6Sonnet", Input, 3_000_000)), m, DefaultTolerance)
	if !res.Clean() {
		t.Fatalf("an edge month was reported as unlogged traffic: %+v", res.Findings)
	}
	var marked bool
	for _, row := range res.Rows {
		if row.Month == "2026-08" {
			marked = row.Edge
		}
	}
	if !marked {
		t.Error("the edge month was not marked, so the report cannot explain the omission")
	}
}

// A log that covers a whole month begins a few minutes after midnight on the
// first. That is a clock, not a coverage gap.
func TestAFullMonthIsNotAnEdge(t *testing.T) {
	b := New()
	b.Add(audit.Record{Time: time.Date(2026, 8, 1, 0, 3, 0, 0, time.UTC),
		Model: "claude-sonnet", Backend: "bedrock", PromptTokens: 10})
	b.Add(audit.Record{Time: time.Date(2026, 8, 31, 23, 55, 0, 0, time.UTC),
		Model: "claude-sonnet", Backend: "bedrock", PromptTokens: 10})
	for _, row := range b.Compare(Invoice{}, m, DefaultTolerance).Rows {
		if row.Edge {
			t.Fatalf("a log covering the whole of %s was called an edge month", row.Month)
		}
	}
}

// A bill for a month nobody asked the log about is not a discrepancy. Comparing
// it would report the window as a finding.
func TestInvoiceMonthsOutsideTheWindowAreNotFindings(t *testing.T) {
	b := New()
	span(b, "claude-sonnet")
	b.Add(rec(4, "claude-sonnet", 1_000_000, 0))

	res := b.Compare(inv(
		line("2026-08", "Claude4.6Sonnet", Input, 1_000_000),
		line("2026-03", "Claude4.6Sonnet", Input, 9_000_000),
	), m, DefaultTolerance)

	if !res.Clean() {
		t.Fatalf("a month outside the window was reported: %+v", res.Findings)
	}
	if len(res.Outside) != 1 || res.Outside[0] != "2026-03" {
		t.Errorf("outside = %v", res.Outside)
	}
}

// The bill is drawn on the provider's calendar. Bucketing on local midnight
// would file a week of traffic in the wrong month for anyone east of Greenwich.
func TestMonthsAreBucketedInUTC(t *testing.T) {
	tokyo := time.FixedZone("JST", 9*3600)
	// 09:30 on 1 September in Tokyo is 00:30 on 1 September UTC, and 08:30 is
	// still 31 August.
	if got := Month(time.Date(2026, 9, 1, 8, 30, 0, 0, tokyo)); got != "2026-08" {
		t.Errorf("got %s, want the UTC month 2026-08", got)
	}
}

// Case is the one difference not worth making a person configure around.
func TestMappingIsCaseInsensitive(t *testing.T) {
	if got, ok := m.Resolve("claude4.6sonnet"); !ok || got != "claude-sonnet" {
		t.Errorf("resolve = %q, %v", got, ok)
	}
	if _, ok := m.Resolve("Claude4.5Haiku"); ok {
		t.Error("a name nothing maps resolved anyway")
	}
}

func teamLine(month, model, team string, k Kind, n int64) Line {
	return Line{Month: month, Model: model, Team: team, Kind: k, Tokens: n}
}

// teamsIn narrows to one month. The span helper widens the window either side
// so nothing is an edge month, and those records are rows too.
func teamsIn(res Result, month string) []TeamRow {
	var out []TeamRow
	for _, tr := range res.Teams {
		if tr.Month == month {
			out = append(out, tr)
		}
	}
	return out
}

func teamRec(day int, model, team string, in, out int) audit.Record {
	r := rec(day, model, in, out)
	r.Team = team
	return r
}

// The check docs/cost-attribution.md asks for and cannot make on its own:
// switchboard tags the session, and only the bill can say whether AWS split on
// it.
func TestTheBillsOwnSplitIsCompared(t *testing.T) {
	b := New()
	span(b, "claude-sonnet")
	b.Add(teamRec(4, "claude-sonnet", "search", 600_000, 0))
	b.Add(teamRec(4, "claude-sonnet", "billing", 400_000, 0))

	res := b.Compare(Invoice{TeamsPresent: true, Lines: []Line{
		teamLine("2026-08", "Claude4.6Sonnet", "search", Input, 600_000),
		teamLine("2026-08", "Claude4.6Sonnet", "billing", Input, 400_000),
	}}, m, DefaultTolerance)

	if len(res.TeamFindings) != 0 {
		t.Fatalf("a matching split was reported: %+v", res.TeamFindings)
	}
	if got := teamsIn(res, "2026-08"); len(got) != 2 {
		t.Fatalf("teams = %+v", got)
	}
}

// The failure that document names first: the assume succeeds, sts:TagSession is
// missing, and everything bills to one identity. The models still reconcile
// perfectly, which is why this needs its own comparison.
func TestASplitLandingInTheWrongPlaceIsNotMissingTraffic(t *testing.T) {
	b := New()
	span(b, "claude-sonnet")
	b.Add(teamRec(4, "claude-sonnet", "search", 600_000, 0))
	b.Add(teamRec(4, "claude-sonnet", "billing", 400_000, 0))

	// The provider billed the same million tokens, all to one identity.
	res := b.Compare(Invoice{TeamsPresent: true, Lines: []Line{
		teamLine("2026-08", "Claude4.6Sonnet", "search", Input, 1_000_000),
	}}, m, DefaultTolerance)

	if !res.Clean() {
		t.Fatalf("the model totals reconcile and were reported anyway: %+v", res.Findings)
	}
	if len(res.TeamFindings) != 2 {
		t.Fatalf("team findings = %+v", res.TeamFindings)
	}
	if !res.SplitOnly() {
		t.Error("a disagreement only about the split was not distinguished from missing traffic")
	}
	// And the words have to differ, because the fix does. Sending somebody to
	// hunt for an application that bypassed the gateway, when the answer is a
	// session tag that never arrived, is the whole cost of getting this wrong.
	for _, f := range res.TeamFindings {
		if strings.Contains(f.Describe(), "bypassed this gateway") {
			t.Errorf("a team finding used the model wording: %s", f.Describe())
		}
	}
}

// Without a tag column the bill cannot say anything about teams. Reporting
// every team as never billed would be a finding about a missing column.
func TestNoTagsMeansNoTeamComparisonAtAll(t *testing.T) {
	b := New()
	span(b, "claude-sonnet")
	b.Add(teamRec(4, "claude-sonnet", "search", 1_000_000, 0))

	res := b.Compare(inv(line("2026-08", "Claude4.6Sonnet", Input, 1_000_000)), m, DefaultTolerance)
	if len(res.Teams) != 0 || len(res.TeamFindings) != 0 {
		t.Fatalf("teams compared against an invoice that carries none: %+v", res.Teams)
	}
	if res.TeamsPresent {
		t.Error("TeamsPresent set for an invoice with no tags")
	}
}

// An unmapped model's team would be compared against a log that never saw it,
// reporting a team shortfall whose actual cause is a missing model mapping.
func TestUnmappedModelsDoNotEnterTheTeamComparison(t *testing.T) {
	b := New()
	span(b, "claude-sonnet")
	b.Add(teamRec(4, "claude-sonnet", "search", 1_000_000, 0))

	res := b.Compare(Invoice{TeamsPresent: true, Lines: []Line{
		teamLine("2026-08", "Claude4.6Sonnet", "search", Input, 1_000_000),
		teamLine("2026-08", "Nova2.0Lite", "search", Input, 9_000_000),
	}}, m, DefaultTolerance)

	if len(res.TeamFindings) != 0 {
		t.Fatalf("an unmapped model's tokens entered the team split: %+v", res.TeamFindings)
	}
}

// A caller that presented no key and a bill line with no tag are different
// events, and neither is evidence of the other.
func TestUntaggedIsItsOwnRowOnBothSides(t *testing.T) {
	b := New()
	span(b, "claude-sonnet")
	b.Add(rec(4, "claude-sonnet", 1_000_000, 0)) // no team on the record

	res := b.Compare(Invoice{TeamsPresent: true, Lines: []Line{
		teamLine("2026-08", "Claude4.6Sonnet", "", Input, 1_000_000),
	}}, m, DefaultTolerance)

	got := teamsIn(res, "2026-08")
	if len(got) != 1 || got[0].Team != Untagged {
		t.Fatalf("teams = %+v", got)
	}
	if len(res.TeamFindings) != 0 {
		t.Errorf("two untagged sides that agree were reported: %+v", res.TeamFindings)
	}
}

// A bill drawn in thousands of tokens against a log counting tokens disagrees
// by a factor of a thousand in every row at once. Reporting that as missing
// traffic sends somebody hunting an application that does not exist.
func TestAConsistentFactorIsReportedAsAUnitQuestion(t *testing.T) {
	b := New()
	span(b, "claude-sonnet")
	b.Add(rec(4, "claude-sonnet", 2_000_000, 0))
	b.Add(rec(4, "claude-haiku", 500_000, 0))

	res := b.Compare(inv(
		line("2026-08", "Claude4.6Sonnet", Input, 2_000),
		line("2026-08", "Claude4.5Haiku", Input, 500),
	), Mapping{"Claude4.6Sonnet": "claude-sonnet", "Claude4.5Haiku": "claude-haiku"}, DefaultTolerance)

	if res.UnitHint != 1e3 {
		t.Fatalf("unit hint = %v, want 1000", res.UnitHint)
	}
}

// One month off by a thousand is a finding. Only all of them at once is a
// convention, and claiming otherwise would explain away a real gap.
func TestOneRowOffByAFactorIsStillAFinding(t *testing.T) {
	b := New()
	span(b, "claude-sonnet")
	b.Add(rec(4, "claude-sonnet", 2_000_000, 0))
	b.Add(rec(4, "claude-haiku", 500_000, 0))

	res := b.Compare(inv(
		line("2026-08", "Claude4.6Sonnet", Input, 2_000),
		line("2026-08", "Claude4.5Haiku", Input, 500_000),
	), Mapping{"Claude4.6Sonnet": "claude-sonnet", "Claude4.5Haiku": "claude-haiku"}, DefaultTolerance)

	if res.UnitHint != 0 {
		t.Errorf("a single outlier was explained away as a unit: %v", res.UnitHint)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

// An export that stopped short and a provider that billed nothing look
// identical from here. Reporting every model in the month as never billed would
// assert the second, and the usual cause is the first.
func TestAMonthTheInvoiceIsSilentAboutIsNotAPerModelFinding(t *testing.T) {
	b := New()
	span(b, "claude-sonnet")
	b.Add(rec(4, "claude-sonnet", 1_000_000, 0))
	b.Add(rec(4, "claude-haiku", 200_000, 0))
	for d := 1; d <= 5; d++ {
		r := rec(d, "claude-sonnet", 100_000, 0)
		r.Time = time.Date(2026, 9, d, 12, 0, 0, 0, time.UTC)
		b.Add(r)
	}

	res := b.Compare(inv(
		line("2026-08", "Claude4.6Sonnet", Input, 1_000_000),
		line("2026-08", "Claude4.5Haiku", Input, 200_000),
	), Mapping{"Claude4.6Sonnet": "claude-sonnet", "Claude4.5Haiku": "claude-haiku"}, DefaultTolerance)

	if len(res.NoInvoice) != 1 || res.NoInvoice[0] != "2026-09" {
		t.Fatalf("no-invoice months = %v", res.NoInvoice)
	}
	for _, f := range res.Findings {
		if f.Month == "2026-09" {
			t.Errorf("a month the invoice says nothing about produced a per-model finding: %+v", f)
		}
	}
}
