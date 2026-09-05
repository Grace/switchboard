package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/config"
	"github.com/Grace/switchboard/internal/vault"
	"github.com/Grace/switchboard/internal/viewer"
)

const auditUsage = `usage: switchboard audit <verify|show> [flags]

  verify   walk the chain and report the first entry that does not hold
  show     print every entry for one completion id
  recover  decrypt sealed values, given the private key
  view     serve a read-only page of this log on loopback

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
	case "view":
		return auditView(logPath, *addr, *allowRemote)
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

// auditView serves the log as a page. Read-only, loopback, no state.
func auditView(logPath, addr string, allowRemote bool) error {
	srv, ln, err := viewer.Serve(addr, logPath, audit.KeyFromEnv(), allowRemote)
	if err != nil {
		return err
	}
	fmt.Printf("reading  %s\n", logPath)
	fmt.Printf("serving  http://%s\n\n", ln.Addr())
	fmt.Println("Read-only. Nothing here is written back, and the vault is not opened.")
	fmt.Println("Ctrl-C to stop.")
	return srv.Serve(ln)
}
