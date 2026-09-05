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
	fmt.Fprintln(tw, "MODEL\tBACKEND\tREQUESTS\tSEEN\tSTATUS")
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
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s → %s\t%s\n",
			m.Name, strings.Join(m.Backends, ","), count(m.Requests),
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

	fmt.Fprintln(w)
	// The limit, stated wherever this is rendered. A comparison of names cannot
	// see a name that changed meaning, and a reader who takes this for a
	// complete repointing check has been misled by a table that looked clean.
	msg := fmt.Sprintf("%s in force across this window. The log records the name a "+
		"caller asked for, not the model id it resolved to, so a provider repointed under an "+
		"unchanged name looks identical above. The fingerprint covers the roster including its "+
		"ids, so a repoint moves it — date one with `switchboard agents -changes`.",
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
