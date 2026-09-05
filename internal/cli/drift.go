package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/config"
	"github.com/Grace/switchboard/internal/drift"
	"github.com/Grace/switchboard/internal/evidence"
)

// runDrift compares the models the log saw against the models the config
// approves.
//
// The test is trivial to describe and almost nobody runs it, which is exactly
// why it finds things: a model that answered production traffic and was never
// on anyone's approved list is a finding no amount of policy documentation
// would have surfaced.
func runDrift(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("drift", flag.ContinueOnError)
	cfgPath := configFlag(fs)
	logPath := fs.String("path", "", "audit log to read (default: audit.path from config)")
	period := fs.String("period", "", "window to cover: 2026-Q3, 2026-09, 2026, 2026-09-04, or 2026-07-01..2026-10-01")
	asJSON := fs.Bool("json", false, "emit the comparison as JSON")
	strict := fs.Bool("strict", false, "exit non-zero if any model answered that the config does not list")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: switchboard drift [-period window] [-json] [-strict] [-config path]

Compares what the log shows against what the configuration approves. Today that
is the model roster: every distinct model that answered a request, set beside
the models this deployment lists.

  switchboard drift
  switchboard drift -period 2026-Q3
  switchboard drift -strict          # for CI

A model answering production traffic that no review ever passed is a finding,
and this is the cheapest way to find it — the data was already recorded.

What it cannot see: the log records the name a caller asked for, not the model
id it resolved to. A provider repointed underneath an unchanged name looks
identical here. The policy fingerprint covers the roster including its ids, so
a repoint moves it; the count of fingerprints below is that signal, and
"switchboard agents -changes" dates it.

`)
		fs.PrintDefaults()
	}
	if err := parse(fs, args); err != nil {
		return err
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

	approved := make([]string, 0, len(cfg.Models))
	for _, m := range cfg.Models {
		approved = append(approved, m.Name)
	}

	b := drift.New(approved)
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
	res := b.Build()

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return err
		}
	} else {
		writeDrift(os.Stdout, res, path)
	}
	if *strict && len(res.Unapproved) > 0 {
		return fmt.Errorf("%d model(s) answered requests that the configuration does not list: %s",
			len(res.Unapproved), strings.Join(res.Unapproved, ", "))
	}
	return nil
}

func writeDrift(w io.Writer, res drift.Models, path string) {
	fmt.Fprintf(w, "%s entries from %s", count(res.Entries), path)
	if !res.First.IsZero() {
		fmt.Fprintf(w, "\n%s → %s", res.First.Format(time.RFC3339), res.Last.Format(time.RFC3339))
	}
	fmt.Fprint(w, "\n\n")

	if len(res.Seen) == 0 {
		fmt.Fprintln(w, "No traffic in this window.")
		return
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "MODEL\tRESOLVED\tBACKEND\tREQUESTS\tSEEN\tSTATUS")
	for _, m := range res.Seen {
		status := "unknown"
		switch {
		case !res.RosterKnown:
			// Nothing to compare against. Printing "approved" here would report
			// assurance nobody supplied.
			status = "no roster"
		case m.Approved:
			status = "approved"
		default:
			status = "NOT ON ROSTER"
		}
		// The provider's own answer wins the column when there is one: it is
		// the only value here the gateway did not choose.
		resolved := "—"
		switch {
		case len(m.ProviderIDs) > 0:
			resolved = strings.Join(m.ProviderIDs, ", ")
		case len(m.IDs) > 0:
			resolved = strings.Join(m.IDs, ", ")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s → %s\t%s\n",
			m.Name, resolved, strings.Join(m.Backends, ","), count(m.Requests),
			m.First.Format("2006-01-02"), m.Last.Format("2006-01-02"), status)
	}
	tw.Flush()
	fmt.Fprintln(w)

	if !res.RosterKnown {
		for _, line := range wrap("This configuration lists no models, so nothing here could be "+
			"compared. An empty roster is not evidence that the models above were reviewed.", 74) {
			fmt.Fprintf(w, "  %s\n", line)
		}
		return
	}

	if len(res.Unapproved) > 0 {
		for i, line := range wrap(fmt.Sprintf("%s answered requests and %s not listed in this "+
			"configuration: %s.", plural(len(res.Unapproved), "model", "models"),
			isAre(len(res.Unapproved)), strings.Join(res.Unapproved, ", ")), 72) {
			if i == 0 {
				fmt.Fprintf(w, "  !  %s\n", line)
			} else {
				fmt.Fprintf(w, "     %s\n", line)
			}
		}
	}
	if len(res.Unused) > 0 {
		for i, line := range wrap(fmt.Sprintf("Approved and never called: %s. An unused route to a "+
			"provider is still a route; removing it is free.",
			strings.Join(res.Unused, ", ")), 72) {
			if i == 0 {
				fmt.Fprintf(w, "  -  %s\n", line)
			} else {
				fmt.Fprintf(w, "     %s\n", line)
			}
		}
	}
	if len(res.Unapproved) == 0 && len(res.Unused) == 0 {
		fmt.Fprintln(w, "  Every model that answered is on the roster, and every model on the")
		fmt.Fprintln(w, "  roster answered.")
	}

	// Repoints. The finding a comparison of names cannot make, and the reason
	// the resolved identifier is recorded at all.
	if len(res.Repoints) > 0 {
		fmt.Fprintf(w, "\nOne name, more than one thing behind it:\n\n")
		for _, rp := range res.Repoints {
			src := "this gateway's own routing changed"
			if rp.Reported {
				src = "the provider reported a different model"
			}
			fmt.Fprintf(w, "  %s  %s\n", rp.At.Format("2006-01-02"), rp.Name)
			for _, line := range wrap(fmt.Sprintf("%s → %s (%s)", rp.From, rp.To, src), 68) {
				fmt.Fprintf(w, "      %s\n", line)
			}
		}
	}

	fmt.Fprintln(w)
	// Coverage before conclusions. A clean table across a period that was never
	// instrumented is not a pass, and saying so here is the difference between
	// a report and a reassurance.
	switch {
	case res.Unevidenced == res.Entries:
		for _, line := range wrap("No entry in this window records what actually served the "+
			"request — only the name the caller asked for. A provider repointing an alias, or "+
			"updating a pinned name server-side, would be invisible here. This control is "+
			"UNKNOWN rather than met: upgrade and the evidence begins accruing from that day, "+
			"not retroactively.", 74) {
			fmt.Fprintf(w, "  %s\n", line)
		}
	case res.Unevidenced > 0:
		for _, line := range wrap(fmt.Sprintf("%s of %s carry no resolved identifier. The "+
			"earliest that does is %s, so anything before that is unevidenced for this control "+
			"and no change made today recovers it.",
			count(res.Unevidenced), plural(res.Entries, "entry", "entries"),
			res.Evidenced.Format("2006-01-02")), 74) {
			fmt.Fprintf(w, "  %s\n", line)
		}
	default:
		for _, line := range wrap("Every entry records what served it, so the comparison above "+
			"covers the whole window.", 74) {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}

	fmt.Fprintln(w)
	// What remains outside even a resolved identifier.
	msg := fmt.Sprintf("%s in force across this window. A resolved identifier is what the "+
		"provider says served the request, which is an attestation and not a measurement — a "+
		"backend change under a stable name reports nothing. Only a behavioural canary observes "+
		"that directly.",
		plural(res.Policies, "configuration fingerprint was", "configuration fingerprints were"))
	for _, line := range wrap(msg, 74) {
		fmt.Fprintf(w, "  %s\n", line)
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}
