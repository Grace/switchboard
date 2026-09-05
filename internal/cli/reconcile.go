package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/config"
	"github.com/Grace/switchboard/internal/evidence"
	"github.com/Grace/switchboard/internal/reconcile"
)

// runReconcile sets the log against the provider's own invoice.
//
// Every other comparison in this binary reads our log against our config. This
// one reads it against a document produced by the company we buy inference
// from, which is the only account of the same events that nobody here can edit
// — and that is what makes it worth running.
func runReconcile(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("reconcile", flag.ContinueOnError)
	cfgPath := configFlag(fs)
	logPath := fs.String("path", "", "audit log to read (default: audit.path from config)")
	invoice := fs.String("invoice", "", "provider export to compare against (a CUR export, or switchboard's normalised CSV)")
	period := fs.String("period", "", "window to cover: 2026-Q3, 2026-09, 2026, 2026-09-04, or 2026-07-01..2026-10-01")
	tolerance := fs.Float64("tolerance", reconcile.DefaultTolerance, "fraction a month may disagree by before it is reported")
	scale := fs.Float64("scale", 1, "multiply every invoice quantity by this, where the export denominates tokens in thousands")
	asJSON := fs.Bool("json", false, "emit the comparison as JSON")
	strict := fs.Bool("strict", false, "exit non-zero if the two accounts disagree, or if any invoice line could not be compared")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: switchboard reconcile -invoice FILE [-period window] [-json] [-strict]

Compares the tokens this gateway recorded against the tokens the provider
billed, month by month. It is the only check here that reads the log against a
document nobody in this organisation can edit.

  switchboard reconcile -invoice cur-2026-q3.csv -period 2026-Q3
  switchboard reconcile -invoice invoice.csv -strict     # for CI

Tokens on the bill that the log cannot account for are traffic that reached the
provider without passing through this gateway, or entries missing from the
record. Tokens the log holds and the bill does not are the reverse. Both are
findings; the first is the one that matters, because a route around the gateway
is a route around every control attached to it.

Tokens, not requests: a Cost and Usage Report carries no per-request line item
and no request id, so a request count has no counterpart on the bill.

Invoice names are mapped, never guessed. Add them under reconciliation.models;
see docs/reconciliation.md.

`)
		fs.PrintDefaults()
	}
	if err := parse(fs, args); err != nil {
		return err
	}
	if *invoice == "" {
		fs.Usage()
		return fmt.Errorf("no invoice given: pass -invoice with a provider export")
	}

	cfg, found, err := config.LoadForReport(config.ExpandPath(*cfgPath))
	if err != nil {
		return err
	}
	if !found {
		fmt.Fprintf(os.Stderr, "switchboard: no config at %s — reading defaults\n", *cfgPath)
	}
	path := *logPath
	if path == "" {
		if cfg.Audit.Path == "" {
			return fmt.Errorf("no audit log configured: set audit.path, or pass -path")
		}
		path = cfg.Audit.Path
	}
	path = config.ExpandPath(path)

	var from, to time.Time
	if *period != "" {
		p, err := evidence.ParsePeriod(*period)
		if err != nil {
			return err
		}
		from, to = p.From, p.To
	}

	// The tag the gateway sets on assumed sessions is the one to look for on
	// the bill, so the export is read with this deployment's own key.
	inv, err := reconcile.ReadInvoice(config.ExpandPath(*invoice), cfg.Attribution.TagKey)
	if err != nil {
		return fmt.Errorf("reading %s: %w", *invoice, err)
	}

	if *scale != 1 {
		if *scale <= 0 {
			return fmt.Errorf("-scale must be positive, got %v", *scale)
		}
		for i := range inv.Lines {
			inv.Lines[i].Tokens = int64(float64(inv.Lines[i].Tokens) * *scale)
		}
	}

	b := reconcile.New()
	err = audit.Walk(path, func(r audit.Record) error {
		if !from.IsZero() && r.Time.Before(from) {
			return nil
		}
		if !to.IsZero() && !r.Time.Before(to) {
			return nil
		}
		b.Add(r)
		return nil
	})
	if err != nil {
		return err
	}
	res := b.Compare(inv, cfg.Reconciliation.Models, *tolerance)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return err
		}
	} else {
		writeReconcile(os.Stdout, res, path)
	}

	switch {
	case !*strict:
		return nil
	case len(res.Findings) > 0:
		// Phrased so the subject follows the verb: "1 month ... disagree" is the
		// same agreement bug this codebase has shipped twice.
		return fmt.Errorf("the log and the provider's invoice disagree by more than %.1f%% in %s",
			100**tolerance, plural(len(res.Findings), "month of one model", "months of one model"))
	case len(res.TeamFindings) > 0:
		return fmt.Errorf("%s split differently on the provider's invoice than this gateway "+
			"attributed them", plural(len(res.TeamFindings), "month of one team", "months of one team"))
	case len(res.NoInvoice) > 0:
		return fmt.Errorf("the invoice carries no line at all for %s, so %s not reconciled",
			strings.Join(res.NoInvoice, ", "), isAre(len(res.NoInvoice)))
	case len(res.Unmapped) > 0:
		// An incomplete comparison passing CI is the failure this whole command
		// exists to prevent, so it is not a pass.
		return fmt.Errorf("%s on the invoice could not be compared: nothing in reconciliation.models "+
			"names %s", plural(len(res.Unmapped), "model", "models"), namesOf(res.Unmapped))
	}
	return nil
}

func namesOf(us []reconcile.Unmapped) string {
	out := make([]string, 0, len(us))
	for _, u := range us {
		out = append(out, u.Model)
	}
	return strings.Join(out, ", ")
}

func writeReconcile(w io.Writer, res reconcile.Result, path string) {
	fmt.Fprintf(w, "%s entries from %s", count(res.Entries), path)
	if !res.First.IsZero() {
		fmt.Fprintf(w, "\n%s → %s", res.First.Format(time.RFC3339), res.Last.Format(time.RFC3339))
	}
	fmt.Fprintf(w, "\ninvoice: %s", res.Source)
	if res.Currency != "" {
		fmt.Fprintf(w, " (%s)", res.Currency)
	}
	fmt.Fprint(w, "\n\n")

	if len(res.Rows) == 0 {
		fmt.Fprintln(w, "Nothing to compare: neither the log nor the invoice has a comparable row")
		fmt.Fprintln(w, "in this window.")
		writeReconcileLimits(w, res)
		return
	}

	var edged bool
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "MONTH\tMODEL\tBILLED AS\tLOGGED\tINVOICED\tDELTA")
	for _, row := range res.Rows {
		month := row.Month
		if row.Edge {
			month += "~"
			edged = true
		}
		billed := row.Billed
		if billed == "" {
			billed = "—"
		}
		delta := "—"
		if r, ok := row.Ratio(); ok {
			delta = fmt.Sprintf("%+.1f%%", 100*r)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			month, row.Model, billed,
			commas(row.Logged.Total()), commas(row.Invoiced.Total()), delta)
	}
	tw.Flush()
	fmt.Fprintln(w)

	if edged {
		for _, line := range wrap("~ marks a month more than a day of which falls outside this log's "+
			"own coverage. A shortfall there is expected, and is not reported below.", 72) {
			fmt.Fprintf(w, "  %s\n", line)
		}
		fmt.Fprintln(w)
	}

	if res.UnitHint != 0 {
		// Ahead of the findings, because it changes what they mean. A reader
		// who meets the list first goes looking for an application that does
		// not exist.
		for _, line := range wrap(fmt.Sprintf("Every comparable month is off by the same factor of "+
			"%s, which is a unit and not a gap: this export denominates tokens differently from the "+
			"log. Re-run with -scale %s before reading anything below as a finding.",
			factor(res.UnitHint), flagValue(res.UnitHint)), 74) {
			fmt.Fprintf(w, "  %s\n", line)
		}
		fmt.Fprintln(w)
	}

	if len(res.Findings) == 0 {
		for _, line := range wrap(fmt.Sprintf("Every comparable month agrees with the provider's own "+
			"account of it, within %.1f%%.", 100*res.Tolerance), 74) {
			fmt.Fprintf(w, "  %s\n", line)
		}
	} else {
		fmt.Fprintln(w, "Where the two accounts disagree:")
		fmt.Fprintln(w)
		for _, f := range res.Findings {
			mark := "!"
			if f.Kind == reconcile.Unlogged {
				// The direction that means traffic may not have passed through
				// this gateway at all.
				mark = "!!"
			}
			fmt.Fprintf(w, "  %-2s %s  %s\n", mark, f.Month, f.Model)
			for _, line := range wrap(f.Describe(), 68) {
				fmt.Fprintf(w, "     %s\n", line)
			}
		}
	}

	if len(res.NoInvoice) > 0 {
		fmt.Fprintln(w)
		msg := fmt.Sprintf("The invoice carries no line of any kind for %s, and the log holds "+
			"traffic in %s. Either the export did not cover %s, or the provider billed nothing "+
			"at all — and this cannot tell which, so it reports neither as a finding. Check the "+
			"export before reading the table above as complete.",
			strings.Join(res.NoInvoice, ", "), themIt(len(res.NoInvoice)), themIt(len(res.NoInvoice)))
		for i, line := range wrap(msg, 70) {
			if i == 0 {
				fmt.Fprintf(w, "  ?  %s\n", line)
			} else {
				fmt.Fprintf(w, "     %s\n", line)
			}
		}
	}

	if len(res.Unmapped) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "On the invoice, and this configuration does not name:")
		fmt.Fprintln(w)
		for _, u := range res.Unmapped {
			fmt.Fprintf(w, "  %s  %s tokens  %s", u.Model, commas(u.Tokens), strings.Join(u.Months, ", "))
			if u.CostKnown {
				fmt.Fprintf(w, "  %s", amount(u.Cost, res.Currency))
			}
			fmt.Fprintln(w)
			msg := fmt.Sprintf("Either add %q to reconciliation.models, or this is a model "+
				"answering in this account that never passed through the gateway. Until one of "+
				"those is true, these tokens are outside the comparison.", u.Model)
			for _, line := range wrap(msg, 68) {
				fmt.Fprintf(w, "     %s\n", line)
			}
			if u.Suggest != "" {
				// Offered for a person to confirm. Applying a resemblance would
				// reconcile two different models and report a clean month.
				for _, line := range wrap(fmt.Sprintf("Resembles %q — not applied, and the "+
					"version is the part to check.", u.Suggest), 68) {
					fmt.Fprintf(w, "     %s\n", line)
				}
			}
		}
	}

	writeReconcileTeams(w, res)
	writeReconcileLimits(w, res)
}

// writeReconcileTeams sets the bill's own split beside the split this gateway
// asserted.
//
// This is the test docs/cost-attribution.md asks for and cannot run: switchboard
// assumes a role per caller and tags the session, and whether AWS bills the way
// that expects is only observable from the bill.
func writeReconcileTeams(w io.Writer, res reconcile.Result) {
	if len(res.Teams) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The bill's own split, against the split this gateway asserted:")
	fmt.Fprintln(w)

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "MONTH\tTEAM\tREQUESTS\tLOGGED\tBILLED\tDELTA")
	for _, tr := range res.Teams {
		month := tr.Month
		if tr.Edge {
			month += "~"
		}
		delta := "—"
		if r, ok := tr.Ratio(); ok {
			delta = fmt.Sprintf("%+.1f%%", 100*r)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			month, tr.Team, count(tr.Requests), commas(tr.Logged), commas(tr.Invoiced), delta)
	}
	tw.Flush()

	if len(res.TeamFindings) == 0 {
		fmt.Fprintln(w)
		for _, line := range wrap("The provider's own attribution matches this gateway's, so the "+
			"chargeback split is evidenced by the bill and not only by the log.", 74) {
			fmt.Fprintf(w, "  %s\n", line)
		}
		return
	}
	fmt.Fprintln(w)
	// A mis-attribution is one fault repeating every month, so a long list is
	// the same finding several times. Enough of it to see the shape, then a
	// count — the JSON carries all of them.
	const shown = 8
	for i, f := range res.TeamFindings {
		if i == shown {
			fmt.Fprintf(w, "  .. and %s, the same shape. -json carries all of them.\n",
				plural(len(res.TeamFindings)-shown, "more month", "more months"))
			break
		}
		fmt.Fprintf(w, "  !  %s  %s\n", f.Month, f.Team)
		for _, line := range wrap(f.Describe(), 68) {
			fmt.Fprintf(w, "     %s\n", line)
		}
	}
	fmt.Fprintln(w)
	if res.SplitOnly() {
		for _, line := range wrap("The model totals for these months reconcile, so every token "+
			"here is on both sides of the comparison. This is a split landing in the wrong place, "+
			"not traffic that went missing — the provider is charging the same work to somebody "+
			"else.", 74) {
			fmt.Fprintf(w, "  %s\n", line)
		}
		fmt.Fprintln(w)
	}
	for _, line := range wrap("A team this log knows and the bill does not is one of three "+
		"things, in the order they usually turn out to be: the role's trust policy allows "+
		"sts:AssumeRole and not sts:TagSession, so the tag is silently absent; the tag was never "+
		"activated in Billing → Cost allocation tags; or the bill was pulled inside the 24–48 "+
		"hour lag. See docs/cost-attribution.md.", 74) {
		fmt.Fprintf(w, "  %s\n", line)
	}
}

// writeReconcileLimits states what the comparison did not cover. It is the half
// of the report that keeps a clean table from reading as more than it is.
func writeReconcileLimits(w io.Writer, res reconcile.Result) {
	fmt.Fprintln(w)
	notes := []string{
		"Tokens, not requests. A Cost and Usage Report carries no per-request line item " +
			"and no request id — it aggregates by usage type over an hour or a day — so a request " +
			"count has no counterpart on the bill. Tokens are the quantity both sides hold, and " +
			"all four types are compared, because summing input and output alone undercounts " +
			"anything using a prompt cache.",
		"Tokens, not money. One model bills at different unit prices by service tier and by " +
			"cross-region routing, so the rate card in this config prices the log and does not " +
			"reproduce the bill. The invoice is the authority on what is owed.",
	}
	if res.Local > 0 {
		notes = append(notes, fmt.Sprintf("%s excluded: nothing bills for a model running on "+
			"this machine, so counting it would produce a permanent shortfall that means nothing.",
			plural(res.Local, "entry served locally was", "entries served locally were")))
	}
	if res.UnknownBackend > 0 {
		notes = append(notes, fmt.Sprintf("%s no backend and %s kept in the comparison anyway. "+
			"Excluding an entry on a guess would hide exactly the traffic this looks for.",
			plural(res.UnknownBackend, "entry records", "entries record"),
			isAre(res.UnknownBackend)))
	}
	if len(res.Outside) > 0 {
		notes = append(notes, fmt.Sprintf("The invoice also covers %s, which this log was not read "+
			"for. Comparing %s would report the window as a finding.",
			strings.Join(res.Outside, ", "), themIt(len(res.Outside))))
	}
	if res.Skipped > 0 {
		notes = append(notes, fmt.Sprintf("%s in the export could not be read as token usage — a "+
			"guardrail charge, storage, an evaluation. Those charges carry no tokens, so they sit "+
			"outside this comparison and inside your bill.",
			plural(res.Skipped, "row", "rows")))
	}
	if !res.TeamsPresent {
		notes = append(notes, "No line on this invoice carries a team. Per-team reconciliation is "+
			"unknown here rather than absent — see docs/cost-attribution.md for the three reasons "+
			"a tag does not reach the bill.")
	}
	notes = append(notes, res.Notes...)
	for _, n := range notes {
		for _, line := range wrap(n, 74) {
			fmt.Fprintf(w, "  %s\n", line)
		}
		fmt.Fprintln(w)
	}
}

// factor renders a power of ten as the number a person would type.
func factor(f float64) string {
	if f >= 1 {
		return commas(int64(f + 0.5))
	}
	return fmt.Sprintf("%g", f)
}

// flagValue renders the same number as something that can be typed after
// -scale. factor() groups digits to be read; "1,000" on a command line is a
// parse error.
func flagValue(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

// amount renders a sum in the currency the invoice was drawn in. money() prints
// dollars, and an invoice in euros priced with a dollar sign is a wrong number
// on a page somebody forwards to finance.
func amount(v float64, currency string) string {
	if currency == "" || strings.EqualFold(currency, "USD") {
		return money(v)
	}
	return fmt.Sprintf("%.2f %s", v, currency)
}

// commas groups digits so a nine-figure token count is readable.
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

func themIt(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}
