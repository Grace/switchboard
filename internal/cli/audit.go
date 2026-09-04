package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/config"
)

const auditUsage = `usage: switchboard audit <verify|show> [flags]

  verify   walk the chain and report the first entry that does not hold
  show     print every entry for one completion id

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
	if err := parse(fs, rest); err != nil {
		return err
	}

	logPath := *path
	if logPath == "" {
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
	default:
		fmt.Fprint(os.Stderr, auditUsage)
		return fmt.Errorf("unknown audit command %q", sub)
	}
}

func auditVerify(path string) error {
	rep, err := audit.Verify(path, audit.KeyFromEnv())
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
	fmt.Printf("  %d entries, chain intact\n", rep.Entries)
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
