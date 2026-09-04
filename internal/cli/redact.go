package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/Grace/switchboard/internal/redact"
)

// runRedact lets someone check redaction rules before trusting them.
//
// A custom pattern that has never been run against real text is a rule you
// believe in without evidence, and the failure is silent in both directions: it
// either never fires, or it eats the correlation ids you needed. This makes
// that checkable in one command.
func runRedact(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("redact", flag.ContinueOnError)
	cfgPath := configFlag(fs)
	list := fs.Bool("list", false, "print the built-in rules and exit")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: switchboard redact [-list] [-config path]

Reads text on stdin, applies the redaction rules from your config, and writes
the redacted text to stdout. Counts go to stderr, so they stay out of a pipe.

  switchboard redact -list
  echo "mail grace@example.com" | switchboard redact
  cat sample-prompts.txt | switchboard redact > redacted.txt

`)
		fs.PrintDefaults()
	}
	if err := parse(fs, args); err != nil {
		return err
	}

	if *list {
		fmt.Println("built-in redaction rules:")
		for _, name := range redact.BuiltinNames() {
			fmt.Printf("  %-20s %s\n", name, ruleBlurb[name])
		}
		fmt.Println("\nname them in redaction.rules, and add site-specific")
		fmt.Println("patterns under redaction.custom.")
		return nil
	}

	cfg, err := loadConfig(*cfgPath, os.Stderr)
	if err != nil {
		return err
	}
	red, err := cfg.Redaction.Build()
	if err != nil {
		return fmt.Errorf("redaction: %w", err)
	}
	if red == nil {
		return fmt.Errorf("no redaction rules configured: add redaction.rules " +
			"to your config, or run with -list to see what is available")
	}

	in, err := io.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		return err
	}
	out, counts := red.Apply(string(in))
	fmt.Print(out)
	if !strings.HasSuffix(out, "\n") {
		fmt.Println()
	}

	fmt.Fprintf(os.Stderr, "\nrules applied: %s\n", strings.Join(red.Rules(), ", "))
	if len(counts) == 0 {
		fmt.Fprintln(os.Stderr, "nothing matched")
		return nil
	}
	names := make([]string, 0, len(counts))
	for k := range counts {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(os.Stderr, "  %-20s %d\n", n, counts[n])
	}
	return nil
}

var ruleBlurb = map[string]string{
	"email":             "addresses",
	"us_ssn":            "US social security numbers, 000-00-0000",
	"credit_card":       "card numbers — Luhn and issuer prefix checked",
	"phone_us":          "US phone numbers",
	"aws_access_key_id": "AKIA/ASIA/… access key ids",
	"bearer_token":      "Authorization: Bearer …",
	"private_key":       "PEM private key blocks, whole",
}
