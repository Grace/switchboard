package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Grace/switchboard/internal/assess"
	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/config"
	"github.com/Grace/switchboard/internal/evidence"
	"github.com/Grace/switchboard/internal/push"
	"github.com/Grace/switchboard/internal/push/vanta"
)

// count renders a total with thousands separators, so a six-figure entry count
// is readable at a glance in a terminal.
func count(n int) string {
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

// runEvidence assembles a period of the log into a package for someone else.
//
// `controls` describes the configuration; `audit view` describes the traffic.
// This is for the case where neither is enough on its own, because the reader
// is not in the room: an examiner, a customer's security team, an incident
// review six months later. What that reader needs is the two together, plus the
// original bytes, plus a way to check all of it without asking you.
func runEvidence(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("evidence", flag.ContinueOnError)
	cfgPath := configFlag(fs)
	period := fs.String("period", "", "window to cover: 2026-Q3, 2026-09, 2026, 2026-09-04, or 2026-07-01..2026-10-01")
	out := fs.String("o", "", "directory to create (default: evidence-<period>)")
	logPath := fs.String("path", "", "audit log to read (default: audit.path from config)")
	profile := fs.String("profile", "", "assess against this regime instead of the configured one ("+
		strings.Join(config.ProfileNames(), ", ")+")")
	strict := fs.Bool("strict", false, "exit non-zero if the chain is broken or any control is unmet")
	pushTo := fs.String("push", "", "deliver the package to a compliance platform (`vanta`)")
	document := fs.String("document", "", "the document id to upload against, for -push vanta")
	submit := fs.Bool("submit", false, "with -push, also submit the document for review")
	dryRun := fs.Bool("dry-run", false, "with -push, show what would be sent and send nothing")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: switchboard evidence -period <window> [-o dir] [-profile name] [-config path]

Assembles one period of the audit log into a directory you can hand to somebody
who has no reason to trust you: the entries byte for byte as they were written,
a page of the same period, the control assessment of the configuration in force,
a manifest of digests, and instructions for checking all of it without running
switchboard.

  switchboard evidence -period 2026-Q3
  switchboard evidence -period 2026-09 -profile eu-ai-act -o q3-for-audit
  switchboard evidence -period 2026-07-01..2026-10-01 -strict
  switchboard evidence -period 2026-09 -push vanta -document <id> -dry-run

Delivering it puts the package where an auditor already looks, and records the
digest with a timestamp in a log you do not control. Credentials come from the
environment, never a flag: VANTA_API_TOKEN.

The package prints one digest at the end. Record it somewhere this package is
not — that is the step nothing inside the package can do for you.

`)
		fs.PrintDefaults()
	}
	if err := parse(fs, args); err != nil {
		return err
	}
	if *period == "" {
		fs.Usage()
		return fmt.Errorf("evidence needs -period: a package covers a stated window")
	}
	p, err := evidence.ParsePeriod(*period)
	if err != nil {
		return err
	}

	// The reporting loader, deliberately: the configuration most worth
	// packaging evidence about is the one that does not yet satisfy its regime.
	cfg, found, err := config.LoadForReport(*cfgPath)
	if err != nil {
		return err
	}
	if !found {
		fmt.Fprintf(os.Stderr, "switchboard: no config at %s — assessing defaults\n", *cfgPath)
	}
	dep := cfg.Deployment()
	if *profile != "" {
		prof := config.Profile(*profile)
		if _, ok := prof.Regime(); !ok {
			return fmt.Errorf("unknown profile %q: want one of %s", *profile,
				strings.Join(config.ProfileNames(), ", "))
		}
		dep.Profile = prof
	}

	path := *logPath
	if path == "" {
		if cfg.Audit.Path == "" {
			return fmt.Errorf("no audit log configured: set audit.path, or pass -path")
		}
		path = config.ExpandPath(cfg.Audit.Path)
	}
	prices, err := viewerPrices(*cfgPath)
	if err != nil {
		return err
	}

	// Resolve the delivery target first. A missing credential should fail
	// before a package directory exists, not after.
	var target push.Target
	if *pushTo != "" {
		switch strings.ToLower(*pushTo) {
		case "vanta":
			target = &vanta.Target{DocumentID: *document, Submit: *submit}
		default:
			return fmt.Errorf("unknown -push target %q: currently only \"vanta\"", *pushTo)
		}
		if err := target.Check(); err != nil {
			return err
		}
	}

	dir := *out
	if dir == "" {
		dir = "evidence-" + strings.ReplaceAll(p.Label, "..", "_")
	}

	res, err := evidence.Build(evidence.Options{
		LogPath: path, Out: dir, Key: audit.KeyFromEnv(), Period: p,
		Prices: prices, Deployment: dep, Report: assess.Assess(dep),
		Tool: versionString(),
	})
	if err != nil {
		return err
	}

	if target != nil {
		a, err := push.Zip(res.Dir, res.Digest, p.Label)
		if err != nil {
			return err
		}
		if *dryRun {
			fmt.Print(push.Describe(target, a))
		} else {
			receipt, err := target.Send(context.Background(), a)
			if err != nil {
				return err
			}
			fmt.Printf("%s\n\n", receipt)
		}
	}

	m := res.Manifest
	fmt.Printf("%s\n\n", p)
	for _, f := range m.Files {
		fmt.Printf("  %-14s %8d bytes  %s\n", f.Name, f.Bytes, f.What)
	}
	fmt.Printf("  %-14s %8s bytes  the index, and the digest below\n", "manifest.json", "—")
	fmt.Printf("\n  %s entries in this period", count(m.Extract.Entries))
	if m.Extract.Entries > 0 {
		fmt.Printf(" (seq %d–%d)", m.Extract.FirstSeq, m.Extract.LastSeq)
	}
	fmt.Println()

	switch {
	case m.Chain.Break != "":
		fmt.Printf("  chain BROKEN — %s\n", m.Chain.Break)
	case m.Chain.Signed:
		fmt.Printf("  chain intact, signed — %s entries across the whole log\n", count(m.Chain.Entries))
	default:
		fmt.Printf("  chain intact, UNSIGNED — set %s so an edit needs the key too\n", audit.KeyEnv)
	}
	if len(m.Policies) > 1 {
		fmt.Printf("  %d policy fingerprints in force during this period — the rules changed inside it\n",
			len(m.Policies))
	}
	if n := m.Controls.Counts[string(assess.StatusUnmet)]; n > 0 {
		fmt.Printf("  %d control objective(s) unmet — see controls.json\n", n)
	}

	fmt.Printf("\n  %s\n\n", filepath.Join(dir, "..."))
	fmt.Printf("package digest  %s\n\n", res.Digest)
	fmt.Println("Record that digest somewhere this package is not — a ticket, a mail you")
	fmt.Println("did not send yourself, a register you do not control. Nothing inside the")
	fmt.Println("package can do it, and without it a recipient can verify that the files")
	fmt.Println("agree with each other but not that they are the ones you produced.")
	fmt.Printf("\nAlso worth knowing: an intact chain cannot show that nothing was removed\n")
	fmt.Printf("from the end. %s says so in section 6 rather than leaving it implied.\n", "VERIFY.md")

	if *strict {
		if m.Chain.Break != "" {
			return errBroken
		}
		if n := m.Controls.Counts[string(assess.StatusUnmet)]; n > 0 {
			return fmt.Errorf("%d control objective(s) unmet", n)
		}
	}
	return nil
}
