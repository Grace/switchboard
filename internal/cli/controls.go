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

	"github.com/Grace/switchboard/internal/assess"
	awslib "github.com/Grace/switchboard/internal/assess/aws"
	"github.com/Grace/switchboard/internal/assess/databricks"
	"github.com/Grace/switchboard/internal/assess/redteam"
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
	dbx := fs.String("databricks", "", "assess a Databricks serving endpoint export instead "+
		"of this config (`databricks serving-endpoints get <name> -o json`)")
	awsDir := fs.String("aws", "", "assess a Bedrock account instead of this config, from a "+
		"directory of `aws ... --output json` exports (see docs/adapters.md)")
	framework := fs.String("framework", "", "render citations for one framework only "+
		"(e.g. \"DASF\", \"HIPAA\", \"NIST 800-53\"); -framework list prints what is available")
	redteam := fs.String("redteam", "", "a promptfoo results JSON file, to evidence the adversarial-testing row")
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
  switchboard controls -redteam promptfoo-results.json
  switchboard controls -aws ./bedrock-export -profile finra
  switchboard controls -databricks endpoint.json
  switchboard controls -strict          # for CI

The adversarial-testing row is Unknown until something evidences it. -redteam
reads a promptfoo report and fills it in with the tool, its version, when it ran
and how many assertions failed — a row a reviewer can act on, rather than a
claim somebody made.

A profile also names the obligations of that regime which no configuration file
can evidence. Those print at the end and are yours, not switchboard's.

`)
		fs.PrintDefaults()
	}
	if err := parse(fs, args); err != nil {
		return err
	}

	// A foreign deployment short-circuits the whole config path: there is no
	// switchboard here to load, only somebody else's export to read.
	if *awsDir != "" && *dbx != "" {
		return fmt.Errorf("-aws and -databricks describe two different deployments; " +
			"assess them one at a time")
	}
	if *awsDir != "" {
		p := config.Profile(*profile)
		if *profile != "" {
			if _, ok := p.Regime(); !ok {
				return fmt.Errorf("unknown profile %q: want one of %s",
					*profile, strings.Join(config.ProfileNames(), ", "))
			}
		}
		export, err := awslib.ReadDir(config.ExpandPath(*awsDir))
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "switchboard: read %d Bedrock export(s) from %s\n",
			len(export.Read), *awsDir)
		dep, err := withRedTeam(export.Deployment(p), *redteam)
		if err != nil {
			return err
		}
		return emit(assess.Assess(dep), *framework, *asJSON, *strict)
	}
	if *dbx != "" {
		p := config.Profile(*profile)
		if *profile != "" {
			if _, ok := p.Regime(); !ok {
				return fmt.Errorf("unknown profile %q: want one of %s",
					*profile, strings.Join(config.ProfileNames(), ", "))
			}
		}
		f, err := os.Open(*dbx)
		if err != nil {
			return err
		}
		defer f.Close()
		ep, err := databricks.Read(f)
		if err != nil {
			return err
		}
		dep, err := withRedTeam(ep.Deployment(p), *redteam)
		if err != nil {
			return err
		}
		return emit(assess.Assess(dep), *framework, *asJSON, *strict)
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

	dep, err := withRedTeam(cfg.Deployment(), *redteam)
	if err != nil {
		return err
	}
	return emit(assess.Assess(dep), *framework, *asJSON, *strict)
}

// withRedTeam attaches adversarial-testing evidence to a deployment.
//
// It attaches to the deployment rather than patching the finished report,
// because a report is a rendering of a deployment and evidence belongs to the
// thing being described. It also means the same file evidences a switchboard
// config and somebody else's Databricks endpoint identically — the testing was
// of a deployment, not of a config format.
//
// A run with failures still sets the row to met. The objective is that the
// deployment has been adversarially tested, and it has been; what the testing
// found belongs in the evidence sentence, where a reviewer will read it, rather
// than collapsed into a status that cannot carry it.
func withRedTeam(dep assess.Deployment, path string) (assess.Deployment, error) {
	if path == "" {
		return dep, nil
	}
	res, err := redteam.ReadFile(config.ExpandPath(path))
	if err != nil {
		return dep, err
	}
	dep.Assurance.AdversarialTesting = assess.Yes
	dep.Assurance.TestingDetail = res.Describe(time.Now())
	return dep, nil
}

// emit renders a report and decides the exit status.
func emit(rep assess.ControlReport, framework string, asJSON, strict bool) error {
	if strings.EqualFold(framework, "list") {
		for _, f := range assess.Frameworks(rep) {
			fmt.Println(f)
		}
		return nil
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		writeControls(os.Stdout, rep, framework)
	}
	// Unknown deliberately does not fail: a question the source could not
	// answer is not a failure, and failing a build on it teaches people to
	// stop asking.
	if strict && rep.Unmet() {
		return fmt.Errorf("%d control(s) unmet", rep.Counts()[assess.StatusUnmet])
	}
	return nil
}

func writeControls(w io.Writer, rep assess.ControlReport, framework string) {
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
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", c.Status.Symbol(), c.Objective, assess.Render(c.Refs, framework))
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

	if len(rep.Caveats) > 0 {
		fmt.Fprintf(w, "\nWhat this source could not tell us:\n")
		for _, c := range rep.Caveats {
			for i, line := range wrap(c, 74) {
				if i == 0 {
					fmt.Fprintf(w, "  - %s\n", line)
				} else {
					fmt.Fprintf(w, "    %s\n", line)
				}
			}
		}
	}

	if len(rep.Yours) > 0 {
		fmt.Fprintf(w, "\nNot evidenced by configuration — %s obligations that live outside it:\n", rep.Profile)
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
