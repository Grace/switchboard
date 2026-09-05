package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Grace/switchboard/internal/agents"
	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/config"
	"github.com/Grace/switchboard/internal/evidence"
)

// runAgents prints the programs calling this gateway, derived from the log.
//
// `controls` describes the configuration and `audit view` describes the
// traffic. This answers a question neither does and every AI governance
// programme is currently failing: what is actually running. Nobody's declared
// inventory survives contact with a team that shipped something on Thursday,
// and an auditor reaches for the inventory first.
func runAgents(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("agents", flag.ContinueOnError)
	cfgPath := configFlag(fs)
	logPath := fs.String("path", "", "audit log to read (default: audit.path from config)")
	period := fs.String("period", "", "window to cover: 2026-Q3, 2026-09, 2026, 2026-09-04, or 2026-07-01..2026-10-01")
	changes := fs.Bool("changes", false, "print what changed and when, instead of what is running")
	quiet := fs.Duration("quiet-after", agents.DefaultQuiet, "silence after which an agent is reported retired")
	asJSON := fs.Bool("json", false, "emit the inventory as JSON")
	strict := fs.Bool("strict", false, "exit non-zero if any agent offered a tool the config never declared")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: switchboard agents [-period window] [-json] [-strict] [-config path]

Lists the programs calling this gateway, as the traffic reveals them — not as
somebody wrote them down. An agent is identified by the set of tools it offers,
which is distinctive enough to serve as a fingerprint without anyone labelling
anything.

  switchboard agents
  switchboard agents -period 2026-Q3
  switchboard agents -changes -period 2026-Q3
  switchboard agents -json > inventory.json
  switchboard agents -strict          # for CI

Three findings fall out of it. Tools an agent offers but has never called are
authority nobody is using. Tools it offers that the config never declared are a
program that changed without anyone saying so. Tools declared that nobody has
ever offered are a grant with no consumer.

-changes answers the question an examiner actually asks, which is not "is this
on" but "did it operate throughout the period". It dates every appearance,
toolset change, retirement and policy move, and groups undeclared tools into the
bundles they arrived in — five names that always travel together are one skill
somebody installed, not five mistakes.

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

	b := agents.New(cfg.Tools.DeclaredTools(), cfg.Pricing)
	// Walk rather than Verify: this reads what the log says, and whether the
	// chain holds is `audit verify`'s question. Conflating them would mean a
	// single damaged entry hid the whole inventory.
	err = audit.Walk(path, func(r audit.Record) error {
		if !from.IsZero() && r.Time.Before(from) {
			return nil
		}
		// Half-open, matching evidence packages: an entry at exactly `to`
		// belongs to the next period, so two adjacent windows neither drop an
		// entry nor count one twice.
		if !to.IsZero() && !r.Time.Before(to) {
			return nil
		}
		b.Add(r)
		return nil
	})
	if err != nil {
		return err
	}
	inv := b.Build()

	var payload any = inv
	if *changes {
		payload = inv.Changes(*quiet)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(payload); err != nil {
			return err
		}
	} else if *changes {
		writeChanges(os.Stdout, payload.(agents.Changelog), path)
	} else {
		writeAgents(os.Stdout, inv, path)
	}

	if *strict {
		n := 0
		for _, a := range inv.Agents {
			n += len(a.Undeclared)
		}
		if n > 0 {
			return fmt.Errorf("%d undeclared tool(s) offered by callers", n)
		}
	}
	return nil
}

func writeAgents(w io.Writer, inv agents.Inventory, path string) {
	fmt.Fprintf(w, "%s entries from %s", count(inv.Entries), path)
	if !inv.First.IsZero() {
		fmt.Fprintf(w, "\n%s → %s", inv.First.Format(time.RFC3339), inv.Last.Format(time.RFC3339))
	}
	fmt.Fprint(w, "\n\n")

	if len(inv.Agents) == 0 {
		fmt.Fprintln(w, "No traffic in this window.")
		return
	}

	for _, a := range inv.Agents {
		if a.Anonymous {
			fmt.Fprintf(w, "(no tools)  %s requests", count(a.Requests))
			if len(a.Teams) > 0 {
				fmt.Fprintf(w, "  ·  %s", strings.Join(a.Teams, ", "))
			}
			fmt.Fprintln(w)
			// Named as a limit, not a row. These requests offered no tools, so
			// there is no fingerprint to tell one program from another, and
			// presenting them as a single agent would be a claim the log does
			// not support.
			for _, line := range wrap("These offered no tools, so the log cannot tell one "+
				"calling program from another. They are counted, not identified.", 74) {
				fmt.Fprintf(w, "    %s\n", line)
			}
			fmt.Fprintln(w)
			continue
		}

		fmt.Fprintf(w, "%s  %s tools  ·  %s requests", a.ID, count(len(a.Offered)), count(a.Requests))
		if a.CostKnown && a.Cost > 0 {
			fmt.Fprintf(w, "  ·  %s", money(a.Cost))
		} else if !a.CostKnown {
			fmt.Fprint(w, "  ·  cost partial")
		}
		fmt.Fprintln(w)

		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		if len(a.Teams) > 0 {
			fmt.Fprintf(tw, "    teams\t%s\n", strings.Join(a.Teams, ", "))
		}
		if len(a.Models) > 0 {
			fmt.Fprintf(tw, "    models\t%s\n", strings.Join(a.Models, ", "))
		}
		if !a.First.IsZero() {
			fmt.Fprintf(tw, "    seen\t%s → %s\n",
				a.First.Format("2006-01-02"), a.Last.Format("2006-01-02"))
		}
		if len(a.Called) > 0 {
			fmt.Fprintf(tw, "    called\t%s\n", topCalls(a.Called))
		}
		if len(a.Refused) > 0 {
			fmt.Fprintf(tw, "    refused\t%s\n", topCalls(a.Refused))
		}
		tw.Flush()

		// Findings last and unindented from the facts above, because they are
		// the reason to read the entry rather than detail about it.
		if len(a.Unused) > 0 {
			for i, line := range wrap(fmt.Sprintf("%s never called: %s",
				count(len(a.Unused)), strings.Join(a.Unused, ", ")), 70) {
				if i == 0 {
					fmt.Fprintf(w, "    !  %s\n", line)
				} else {
					fmt.Fprintf(w, "       %s\n", line)
				}
			}
		}
		if len(a.Undeclared) > 0 {
			for i, line := range wrap(fmt.Sprintf("%s not in tools.declare: %s",
				count(len(a.Undeclared)), strings.Join(a.Undeclared, ", ")), 70) {
				if i == 0 {
					fmt.Fprintf(w, "    !! %s\n", line)
				} else {
					fmt.Fprintf(w, "       %s\n", line)
				}
			}
		}
		fmt.Fprintln(w)
	}

	named := 0
	for _, a := range inv.Agents {
		if !a.Anonymous {
			named++
		}
	}
	fmt.Fprintf(w, "%s agent(s) identified by fingerprint\n", count(named))
	if len(inv.Unseen) > 0 {
		for i, line := range wrap(fmt.Sprintf("Declared but never offered by anybody: %s",
			strings.Join(inv.Unseen, ", ")), 74) {
			if i == 0 {
				fmt.Fprintf(w, "  - %s\n", line)
			} else {
				fmt.Fprintf(w, "    %s\n", line)
			}
		}
	}
	// The limit, every time, in the same place. An inventory read from traffic
	// is complete with respect to traffic; a program that has not called since
	// the log began does not appear, and a reader who assumes otherwise has
	// been misled by a document that looked complete.
	for _, line := range wrap("This is what called, not what exists. A program that has "+
		"not run in this window does not appear here, and an agent whose toolset changed "+
		"appears twice.", 74) {
		fmt.Fprintf(w, "  %s\n", line)
	}
}

// topCalls renders a call tally busiest-first, so the line reads as a profile
// of what the agent does rather than an alphabetical list.
func topCalls(m map[string]int) string {
	type kv struct {
		name string
		n    int
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].name < all[j].name
	})
	parts := make([]string, 0, len(all))
	for i, e := range all {
		if i == 5 {
			parts = append(parts, fmt.Sprintf("+%d more", len(all)-5))
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", e.name, count(e.n)))
	}
	return strings.Join(parts, ", ")
}

// money formats a total. Sub-cent sums are the normal case for a single agent
// on a cheap model, and rendering them as $0.00 would report real spend as
// nothing.
func money(v float64) string {
	if v > 0 && v < 0.01 {
		return fmt.Sprintf("$%.4f", v)
	}
	return fmt.Sprintf("$%.2f", v)
}

// writeChanges renders the period view.
//
// The ordering is deliberate: events first, because a dated line is what gets
// pasted into an audit response, and shadow skills after, because they are a
// standing condition rather than something that happened on a day.
func writeChanges(w io.Writer, log agents.Changelog, path string) {
	fmt.Fprintf(w, "changes in %s\n", path)
	if !log.First.IsZero() {
		fmt.Fprintf(w, "%s → %s\n", log.First.Format(time.RFC3339), log.Last.Format(time.RFC3339))
	}
	fmt.Fprintln(w)

	if len(log.Events) == 0 {
		fmt.Fprintln(w, "Nothing changed in this window: no agent appeared, changed,")
		fmt.Fprintln(w, "retired, and the configuration in force did not move.")
	}

	for _, e := range log.Events {
		mark := "  "
		if e.Shadow {
			mark = "!!"
		}
		fmt.Fprintf(w, "%s %s  %-14s %s\n", mark, e.Time.Format("2006-01-02"), e.Kind, firstLine(e.Detail))
		for _, line := range restLines(e.Detail) {
			fmt.Fprintf(w, "                             %s\n", line)
		}
		// An inference is labelled every time it is printed. That two
		// fingerprints are the same program is a conclusion from overlapping
		// toolsets, not something the log recorded, and a reader who takes it
		// for an observation will defend it to an auditor who can disprove it.
		if e.Inferred {
			fmt.Fprintf(w, "                             (inferred from toolset overlap, not recorded)\n")
		}
	}

	if len(log.Shadow) > 0 {
		fmt.Fprintf(w, "\nUndeclared capability, grouped by what arrived together:\n\n")
		for _, s := range log.Shadow {
			fmt.Fprintf(w, "  %s  %s\n", s.ID, strings.Join(s.Tools, ", "))
			fmt.Fprintf(w, "          carried by %s, %s → %s, %s requests",
				strings.Join(s.Agents, ", "),
				s.First.Format("2006-01-02"), s.Last.Format("2006-01-02"), count(s.Requests))
			if s.Refused > 0 {
				// Present and being used are different findings, and the second
				// is the one that needs an answer this week.
				fmt.Fprintf(w, ", %s refused", count(s.Refused))
			}
			fmt.Fprintln(w)
		}
	}

	fmt.Fprintln(w)
	for _, line := range wrap(fmt.Sprintf("Retirement means no traffic for %s, measured against the "+
		"end of this window rather than against now, so re-running the same period gives the "+
		"same answer. Everything here is derived from the log: a change nobody made through "+
		"this gateway does not appear.", roughDur(log.Quiet)), 74) {
		fmt.Fprintf(w, "  %s\n", line)
	}
}

func firstLine(s string) string {
	if lines := wrap(s, 46); len(lines) > 0 {
		return lines[0]
	}
	return s
}

func restLines(s string) []string {
	lines := wrap(s, 46)
	if len(lines) < 2 {
		return nil
	}
	return lines[1:]
}

func roughDur(d time.Duration) string {
	if days := int(d.Hours() / 24); days > 0 {
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
	return d.String()
}
