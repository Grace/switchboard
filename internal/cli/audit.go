package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/config"
	"github.com/Grace/switchboard/internal/policy"
	"github.com/Grace/switchboard/internal/vault"
	"github.com/Grace/switchboard/internal/viewer"
)

const auditUsage = `usage: switchboard audit <verify|show> [flags]

  verify   walk the chain and report the first entry that does not hold
  policy   print the configuration an entry was served under, or list what is archived
  show     print every entry for one completion id
  recover  decrypt sealed values, given the private key
  view     serve a read-only page of this log on loopback, or -out it to a file

An audit log is evidence only if an edit to it is detectable. Each entry
carries the digest of the one before it, and its own digest covers that link,
so an alteration, a deletion or a reordering stops the recomputation at exactly
the entry where it happened.

Set ` + audit.KeyEnv + ` to sign entries, and keep the key somewhere the log is
not. Without it the chain still catches corruption and casual editing, but not
someone who can rewrite the file deliberately.
`

func runAudit(_ context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, auditUsage)
		return flag.ErrHelp
	}

	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("audit "+sub, flag.ContinueOnError)
	cfgPath := configFlag(fs)
	path := fs.String("path", "", "audit log to read (default: audit.path from config)")
	id := fs.String("id", "", "completion id, for show")
	keyPath := fs.String("key", "", "PEM private key, for recover")
	vaultPath := fs.String("vault", "", "sealed-value store (default: vault.path from config)")
	token := fs.String("token", "", "value token to recover; omit for all")
	addr := fs.String("addr", "127.0.0.1:11436", "address for view")
	allowRemote := fs.Bool("allow-remote", false, "let view bind somewhere other than loopback")
	out := fs.String("out", "", "for view: write the page to this file and exit, instead of serving")
	if err := parse(fs, rest); err != nil {
		return err
	}

	// Only verify and show read the log. recover works from the vault and the
	// private key alone, which is the point: it runs where the key is, which is
	// deliberately not where the gateway runs.
	logPath := *path
	if logPath == "" && sub != "recover" {
		cfg, err := loadConfig(*cfgPath, os.Stderr)
		if err != nil {
			return err
		}
		if cfg.Audit.Path == "" {
			return fmt.Errorf("no audit log configured: set audit.path, or pass -path")
		}
		logPath = config.ExpandPath(cfg.Audit.Path)
	}

	switch sub {
	case "verify":
		return auditVerify(logPath)
	case "show":
		if *id == "" {
			return fmt.Errorf("show needs -id")
		}
		return auditShow(logPath, *id)
	case "policy":
		return auditPolicy(logPath, *id)
	case "view":
		// The rate card comes from the same file as everything else, so the
		// page's money is the deployment's own declared rates rather than a
		// price list baked into this binary. Without one it shows tokens and
		// says nothing about cost.
		prices, err := viewerPrices(*cfgPath)
		if err != nil {
			return err
		}
		return auditView(logPath, *addr, prices, *allowRemote, *out)
	case "recover":
		if *keyPath == "" {
			return fmt.Errorf("recover needs -key: the gateway is never given the " +
				"private half, so recovery is an out-of-band act by whoever holds it")
		}
		vp := *vaultPath
		if vp == "" {
			cfg, err := loadConfig(*cfgPath, os.Stderr)
			if err != nil {
				return err
			}
			if cfg.Vault.Path == "" {
				return fmt.Errorf("no vault configured: set vault.path, or pass -vault")
			}
			vp = config.ExpandPath(cfg.Vault.Path)
		}
		return auditRecover(vp, *keyPath, *token)
	default:
		fmt.Fprint(os.Stderr, auditUsage)
		return fmt.Errorf("unknown audit command %q", sub)
	}
}

func auditVerify(path string) error {
	rep, err := audit.VerifyAll(path, audit.KeyFromEnv())
	if err != nil {
		return err
	}

	how := "unsigned — set " + audit.KeyEnv + " to make edits require the key"
	if rep.Keyed {
		how = "signed"
	}

	if rep.Break != nil {
		fmt.Printf("BROKEN  %s (%s)\n\n", path, how)
		fmt.Printf("  %d entries verify, then line %d (seq %d):\n    %s\n\n",
			rep.Entries, rep.Break.Line, rep.Break.Seq, rep.Break.Reason)
		fmt.Println("  Everything before that line is intact. The break is where")
		fmt.Println("  the recorded history stops matching what was written.")
		return errBroken
	}

	fmt.Printf("ok  %s (%s)\n", path, how)
	seg := ""
	if rep.Segments > 1 {
		seg = fmt.Sprintf(" across %d segments", rep.Segments)
	}
	fmt.Printf("  %d entries%s, chain intact\n", rep.Entries, seg)
	if rep.Head != "" {
		fmt.Printf("  head %s\n", rep.Head)
		fmt.Println("\n  Record the head somewhere this log is not. An intact prefix is")
		fmt.Println("  an intact chain, so only an external anchor proves nothing was")
		fmt.Println("  removed from the end.")
	}
	return nil
}

func auditShow(path, id string) error {
	recs, err := audit.Find(path, id)
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		return fmt.Errorf("no entry for %q in %s", id, path)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

type brokenError struct{}

func (brokenError) Error() string { return "audit chain does not verify" }

var errBroken = brokenError{}

// auditRecover decrypts sealed values. This runs wherever the private key is,
// which is deliberately not where the gateway runs.
func auditRecover(vaultPath, keyPath, token string) error {
	priv, err := vault.LoadPrivateKey(config.ExpandPath(keyPath))
	if err != nil {
		return err
	}
	var tokens []string
	if token != "" {
		tokens = []string{token}
	}
	found, err := vault.Recover(config.ExpandPath(vaultPath), priv, tokens...)
	if err != nil {
		return err
	}
	if len(found) == 0 {
		return fmt.Errorf("nothing to recover in %s", vaultPath)
	}
	for _, r := range found {
		fmt.Printf("%-14s %-18s %s\n", r.Token, r.Rule, r.Value)
	}
	fmt.Fprintf(os.Stderr, "\n%d value(s) recovered. This is the plaintext redaction removed; handle accordingly.\n", len(found))
	return nil
}

// viewerPrices reads the rate card out of the config, tolerating the absence of
// a config file entirely — pointing this at a log downloaded from an archive is
// a supported thing to do, and it should not require the deployment's config to
// be present on the machine doing the reading.
func viewerPrices(cfgPath string) (viewer.Prices, error) {
	cfg, found, err := config.LoadForReport(config.ExpandPath(cfgPath))
	if err != nil || !found {
		return viewer.Prices{}, err
	}
	p := viewer.Prices{Currency: cfg.Pricing.Currency}
	if len(cfg.Pricing.Models) > 0 {
		p.Model = make(map[string]viewer.Price, len(cfg.Pricing.Models))
		for name, r := range cfg.Pricing.Models {
			p.Model[name] = viewer.Price{
				InPerMTok: r.InputPerMTok, OutPerMTok: r.OutputPerMTok,
				CacheWrite: r.CacheWritePerMTok, CacheReadPer: r.CacheReadPerMTok,
			}
		}
	}
	return p, nil
}

// auditView serves the log as a page, or writes it to a file.
//
// The file form exists because the useful thing to do with a view of an
// incident is attach it to the incident. It is one self-contained page with no
// script and no external reference, so it survives being mailed to someone who
// cannot reach the host it came from.
func auditView(logPath, addr string, prices viewer.Prices, allowRemote bool, out string) error {
	if out != "" {
		n, err := viewer.WriteFile(out, logPath, audit.KeyFromEnv(), prices)
		if err != nil {
			return err
		}
		fmt.Printf("wrote %s (%d bytes) from %s\n", out, n, logPath)
		fmt.Println("\nSelf-contained: no script, no external reference. It shows the whole")
		fmt.Println("log; to capture one slice, serve it and save the filtered URL.")
		return nil
	}
	srv, ln, err := viewer.Serve(addr, logPath, audit.KeyFromEnv(), prices, allowRemote)
	if err != nil {
		return err
	}
	fmt.Printf("reading  %s\n", logPath)
	fmt.Printf("serving  http://%s\n\n", ln.Addr())
	fmt.Println("Read-only. Nothing here is written back, and the vault is not opened.")
	fmt.Println("Ctrl-C to stop.")
	return srv.Serve(ln)
}

// auditPolicy resolves the fingerprint an entry cites to the configuration
// behind it.
//
// A digest on every entry says the rules changed and cannot say what they were.
// This is the other half: with no argument it reports which of the policies the
// log cites are recoverable, and with one it prints that policy.
//
// The check that the document hashes to its own name is not decoration. Without
// it the archive is a folder somebody could edit afterwards, and an archived
// policy would evidence nothing beyond the good intentions of whoever kept it.
func auditPolicy(logPath, fingerprint string) error {
	dir := policy.DirFor(logPath)

	if fingerprint != "" {
		doc, err := policy.Load(dir, fingerprint)
		if errors.Is(err, policy.ErrNotArchived) {
			return fmt.Errorf("policy %s is cited by the log and not archived in %s. "+
				"Entries from that period name rules that were never captured, and no "+
				"change made now recovers them", fingerprint, dir)
		}
		if err != nil {
			return err
		}
		// Verified as stored, then indented for reading. Formatting after the
		// check cannot affect whether it passed.
		var v any
		if err := json.Unmarshal(doc, &v); err != nil {
			os.Stdout.Write(doc)
			return nil
		}
		pretty, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			os.Stdout.Write(doc)
			return nil
		}
		fmt.Printf("%s\n", pretty)
		return nil
	}

	// No fingerprint: report coverage. Which periods of this log can have their
	// rules recovered, and which cannot.
	seen := map[string]bool{}
	var order []string
	if err := audit.Walk(logPath, func(r audit.Record) error {
		if r.Policy != "" && !seen[r.Policy] {
			seen[r.Policy] = true
			order = append(order, r.Policy)
		}
		return nil
	}); err != nil {
		return err
	}
	if len(order) == 0 {
		fmt.Printf("No entry in %s cites a policy fingerprint.\n", logPath)
		return nil
	}
	cov := policy.Check(dir, order)
	fmt.Printf("%s cited by %s\n\n", plural(len(order), "policy", "policies"), logPath)
	for _, fp := range order {
		mark, note := "OK", "archived"
		if !contains(cov.Archived, fp) {
			mark, note = "!!", "NOT archived — the rules for these entries cannot be recovered"
		}
		fmt.Printf("  %s %s  %s\n", mark, fp, note)
	}
	fmt.Println()
	if len(cov.Missing) > 0 {
		for _, line := range wrap(fmt.Sprintf("%s cited and not archived. Those entries name "+
			"rules nobody kept, so a decision from that period cannot be read against the "+
			"configuration that produced it. Archiving begins when the server next starts "+
			"and is not retroactive.", plural(len(cov.Missing), "policy is", "policies are")), 74) {
			fmt.Printf("  %s\n", line)
		}
		return nil
	}
	for _, line := range wrap("Every policy this log cites is archived, and each stored "+
		"document hashes to the fingerprint naming it — so the entries and the rules they "+
		"were served under can be checked against each other by anyone holding both.", 74) {
		fmt.Printf("  %s\n", line)
	}
	return nil
}

func contains(all []string, s string) bool {
	for _, v := range all {
		if v == s {
			return true
		}
	}
	return false
}
