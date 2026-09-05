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

	"github.com/Grace/switchboard/internal/config"
)

// runControls prints the control assessment for the running configuration.
//
// docs/controls.md describes the software. This describes the deployment, which
// is the document a reviewer actually wants and the one no vendor ships,
// because generating it from live configuration means it cannot flatter you.
func runControls(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("controls", flag.ContinueOnError)
	cfgPath := configFlag(fs)
	profile := fs.String("profile", "", "assess against this regime instead of the configured one ("+
		strings.Join(config.ProfileNames(), ", ")+")")
	asJSON := fs.Bool("json", false, "emit the report as JSON")
	strict := fs.Bool("strict", false, "exit non-zero if any control is unmet")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: switchboard controls [-profile name] [-json] [-strict] [-config path]

Assesses the configuration against the control objectives a security review
asks about, and prints what this deployment actually satisfies — not what the
software is capable of.

  switchboard controls
  switchboard controls -profile hipaa
  switchboard controls -profile finra -json > controls.json
  switchboard controls -strict          # for CI

A profile also names the obligations of that regime which no configuration file
can evidence. Those print at the end and are yours, not switchboard's.

`)
		fs.PrintDefaults()
	}
	if err := parse(fs, args); err != nil {
		return err
	}

	// Deliberately the reporting loader: a profile turns unmet obligations into
	// load errors, and refusing to open the file is the least helpful possible
	// response to "show me my gaps".
	cfg, found, err := config.LoadForReport(*cfgPath)
	if err != nil {
		return err
	}
	if !found {
		fmt.Fprintf(os.Stderr, "switchboard: no config at %s — reporting on defaults\n", *cfgPath)
	}

	if *profile != "" {
		p := config.Profile(*profile)
		if _, ok := p.Regime(); !ok {
			return fmt.Errorf("unknown profile %q: want one of %s",
				*profile, strings.Join(config.ProfileNames(), ", "))
		}
		cfg.Profile = p
	}

	rep := cfg.Controls()

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		writeControls(os.Stdout, rep)
	}

	if *strict && rep.Unmet() {
		return fmt.Errorf("%d control(s) unmet", rep.Counts()[config.StatusUnmet])
	}
	return nil
}

func writeControls(w io.Writer, rep config.ControlReport) {
	fmt.Fprintf(w, "profile: %s", rep.Profile)
	if rep.Regime != "" {
		fmt.Fprintf(w, " (%s)", rep.Regime)
	}
	fmt.Fprint(w, "\n\n")

	// One writer and one flush. A tabwriter line with no tab terminates the
	// column block, so each section headline starts a fresh block and every
	// section is measured on its own widths — which is what we want, since one
	// long citation would otherwise indent every objective in the report.
	section := ""
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, c := range rep.Controls {
		if c.Section != section {
			if section != "" {
				fmt.Fprintln(tw)
			}
			section = c.Section
			fmt.Fprintln(tw, section)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", c.Status.Symbol(), c.Objective, c.Refs)
		// Evidence is the reason the row says what it says, so it is not
		// optional detail behind a flag. A status with no evidence is the kind
		// of claim this whole command exists to avoid making.
		for _, line := range wrap(c.Evidence, 76) {
			fmt.Fprintf(tw, "  \t%s\n", line)
		}
	}
	tw.Flush()

	counts := rep.Counts()
	fmt.Fprintf(w, "\n%d met · %d partial · %d unmet · %d not addressed\n",
		counts[config.StatusMet], counts[config.StatusPartial],
		counts[config.StatusUnmet], counts[config.StatusNotAddressed])

	if len(rep.Yours) > 0 {
		fmt.Fprintf(w, "\nNot switchboard's to evidence — %s obligations that live outside this file:\n", rep.Profile)
		for _, y := range rep.Yours {
			lines := wrap(y, 74)
			for i, line := range lines {
				if i == 0 {
					fmt.Fprintf(w, "  - %s\n", line)
				} else {
					fmt.Fprintf(w, "    %s\n", line)
				}
			}
		}
	}
}

// wrap breaks text on spaces at width, so evidence stays readable in a terminal
// without depending on the terminal to do it.
func wrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var out []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			out = append(out, line)
			line = w
			continue
		}
		line += " " + w
	}
	return append(out, line)
}
