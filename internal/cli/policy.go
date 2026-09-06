package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/Grace/switchboard/internal/approval"
	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/config"
	"github.com/Grace/switchboard/internal/policy"
)

const policyUsage = `usage: switchboard policy <command> [flags]

Who authorised the configuration this gateway runs.

commands:
  show      the fingerprint in force, and whether anything approved it
  key       generate an approver keypair, and print the line for the config
  approve   sign the current configuration as a named approver
  history   every policy the log cites, and what authorised each one

A model roster, a prompt, a tool grant and a redaction rule all change what this
system does in production, and almost nowhere are they under the change control
that covers application code. This puts them under it, at the only place that
can enforce it — the thing that reads the configuration.

An approval is an Ed25519 signature over a policy fingerprint, and the
fingerprint is the digest of the policy document, so a signature binds to the
exact bytes and cannot be moved onto a configuration nobody read. The gateway
holds public keys only. A signature the serving process could produce would not
be evidence that anybody else agreed to anything.

`

func runPolicy(_ context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, policyUsage)
		return fmt.Errorf("policy needs a command")
	}
	sub, rest := args[0], args[1:]

	fs := flag.NewFlagSet("policy "+sub, flag.ContinueOnError)
	cfgPath := configFlag(fs)
	logPath := fs.String("path", "", "audit log to read (default: audit.path from config)")
	keyPath := fs.String("key", "", "approver's private key (approve)")
	as := fs.String("as", "", "the approver's name, matching change_control.approvers (approve)")
	note := fs.String("note", "", "why this configuration was approved (approve)")
	out := fs.String("out", "", "where to write the private key (key)")
	asJSON := fs.Bool("json", false, "emit as JSON")
	strict := fs.Bool("strict", false, "exit non-zero if any policy the log cites was not approved before it served")
	fs.Usage = func() { fmt.Fprint(os.Stderr, policyUsage); fs.PrintDefaults() }
	if err := parse(fs, rest); err != nil {
		return err
	}

	switch sub {
	case "key":
		return policyKey(*as, *out)
	case "show":
		return policyShow(*cfgPath, *logPath, *asJSON)
	case "approve":
		return policyApprove(*cfgPath, *logPath, *keyPath, *as, *note)
	case "history":
		return policyHistory(*cfgPath, *logPath, *asJSON, *strict)
	default:
		fmt.Fprint(os.Stderr, policyUsage)
		return fmt.Errorf("unknown policy command %q", sub)
	}
}

// policyKey generates an approver keypair.
//
// The private half is written to a file and never mentioned again by anything
// else in this binary. It belongs with the person who approves changes, not on
// the machine whose changes they are approving.
func policyKey(name, out string) error {
	if name == "" {
		return fmt.Errorf("policy key needs -as: a key belongs to a person, and the name " +
			"is what an approval is checked against")
	}
	if out == "" {
		out = name + ".approver.key"
	}
	if _, err := os.Stat(out); err == nil {
		return fmt.Errorf("%s already exists. Overwriting it would invalidate every "+
			"approval that key has already signed", out)
	}
	pub, priv, err := approval.GenerateKey()
	if err != nil {
		return err
	}
	if err := approval.WritePrivateKey(out, priv); err != nil {
		return err
	}
	line, err := approval.EncodePublic(pub)
	if err != nil {
		return err
	}

	fmt.Printf("Private key written to %s (mode 0600).\n\n", out)
	for _, l := range wrap("Keep it off the gateway. The whole value of an approval is that "+
		"the serving process could not have produced it, and a private key sitting beside the "+
		"configuration it approves is a system that approves its own changes.", 74) {
		fmt.Printf("  %s\n", l)
	}
	fmt.Printf("\nAdd this to switchboard.json:\n\n")
	snippet := map[string]any{"change_control": map[string]any{
		"enabled":   true,
		"required":  true,
		"approvers": []map[string]string{{"name": name, "public_key": line}},
	}}
	b, _ := json.MarshalIndent(snippet, "  ", "  ")
	fmt.Printf("  %s\n\n", b)
	for _, l := range wrap("Adding an approver changes the policy fingerprint, so this "+
		"edit itself needs an approval from whoever could already sign. On the first "+
		"approver there is nobody, which is the one unavoidable bootstrap: approve it, and "+
		"from then on the roster is under the same control as everything else.", 74) {
		fmt.Printf("  %s\n", l)
	}
	return nil
}

// resolveLog finds the audit log, which is where the policy archive lives.
func resolveLog(cfg *config.Config, override string) (string, error) {
	if override != "" {
		return config.ExpandPath(override), nil
	}
	if cfg.Audit.Path == "" {
		return "", fmt.Errorf("no audit log configured: set audit.path, or pass -path. " +
			"Approvals are stored beside the log, because that is what they are about")
	}
	return config.ExpandPath(cfg.Audit.Path), nil
}

func policyShow(cfgPath, logOverride string, asJSON bool) error {
	cfg, found, err := config.LoadForReport(config.ExpandPath(cfgPath))
	if err != nil {
		return err
	}
	if !found {
		fmt.Fprintf(os.Stderr, "switchboard: no config at %s — reading defaults\n", cfgPath)
	}
	logPath, err := resolveLog(cfg, logOverride)
	if err != nil {
		return err
	}
	fp := cfg.PolicyFingerprint()
	roster, err := cfg.ChangeControl.Roster()
	if err != nil {
		return err
	}
	// The configuration in hand has not served anything yet, so there is no
	// serving time to be late against.
	st, err := approval.Check(policy.DirFor(logPath), fp, roster, cfg.ChangeControl.Threshold(), time.Time{})
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}

	fmt.Printf("policy %s\n", fp)
	fmt.Printf("archive %s\n\n", policy.DirFor(logPath))
	switch st.State {
	case approval.NotInForce:
		for _, l := range wrap("Change control is not enabled, so nothing here says whether "+
			"this configuration was authorised. Run 'switchboard policy key' to start.", 74) {
			fmt.Printf("  %s\n", l)
		}
	case approval.Approved:
		fmt.Printf("  OK approved by %s (%d of %d required)\n",
			join(st.Approvers), st.Valid, st.Minimum)
	default:
		fmt.Printf("  !! %s — %d valid signature(s), %d required\n", st.State, st.Valid, st.Minimum)
		for _, p := range st.Problems {
			for _, l := range wrap(p, 70) {
				fmt.Printf("     %s\n", l)
			}
		}
		fmt.Printf("\n     Approve it with:  switchboard policy approve -key KEY -as NAME\n")
	}
	return nil
}

// policyApprove signs the configuration currently on disk.
func policyApprove(cfgPath, logOverride, keyPath, as, note string) error {
	if keyPath == "" {
		return fmt.Errorf("approve needs -key: the gateway is never given a private key, " +
			"so signing is an act by whoever holds one")
	}
	if as == "" {
		return fmt.Errorf("approve needs -as: an approval names a person, and the name is " +
			"what the signature is checked against")
	}
	cfg, found, err := config.LoadForReport(config.ExpandPath(cfgPath))
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("no config at %s: there is nothing to approve", cfgPath)
	}
	logPath, err := resolveLog(cfg, logOverride)
	if err != nil {
		return err
	}
	priv, err := approval.LoadPrivateKey(config.ExpandPath(keyPath))
	if err != nil {
		return err
	}

	// Refuse to sign as somebody the configuration does not list, or with a key
	// that is not theirs. Both would produce a signature nothing can verify,
	// discovered later by whoever was relying on it.
	roster, err := cfg.ChangeControl.Roster()
	if err != nil {
		return err
	}
	pub, listed := roster[as]
	if !listed {
		return fmt.Errorf("change_control.approvers does not list %q, so this signature "+
			"would verify against nothing. Add the approver first — which is itself a "+
			"configuration change, and needs its own approval", as)
	}
	if !pub.Equal(priv.Public()) {
		return fmt.Errorf("the key in %s is not the one configured for %q. Signing anyway "+
			"would store an approval that fails verification, and the failure would surface "+
			"during an audit rather than now", keyPath, as)
	}

	fp := cfg.PolicyFingerprint()
	dir := policy.DirFor(logPath)
	// Archive the document alongside, so the approval and the bytes it covers
	// travel together. Idempotent: the name is the digest of the content.
	if _, err := policy.Record(dir, cfg); err != nil {
		return fmt.Errorf("could not archive the policy being approved: %w", err)
	}
	a, err := approval.Sign(fp, as, note, priv, time.Now())
	if err != nil {
		return err
	}
	if err := approval.Record(dir, a); err != nil {
		return err
	}

	st, err := approval.Check(dir, fp, roster, cfg.ChangeControl.Threshold(), time.Time{})
	if err != nil {
		return err
	}
	fmt.Printf("policy %s approved by %s\n", fp, as)
	fmt.Printf("  %d of %d required signature(s): %s\n", st.Valid, st.Minimum, join(st.Approvers))
	if st.Valid < st.Minimum {
		fmt.Println()
		for _, l := range wrap(fmt.Sprintf("Still %d short. A minimum above one exists because "+
			"one person who can both edit the configuration and sign for it is approving their "+
			"own change.", st.Minimum-st.Valid), 74) {
			fmt.Printf("  %s\n", l)
		}
	}
	return nil
}

// policyHistory is the control's test over a period.
//
// Not "is change control switched on today" but "was every configuration this
// log ran under authorised, and authorised before it ran". That question is
// answerable only by setting the approvals against the log, which is why it
// lives here and not in a status endpoint.
func policyHistory(cfgPath, logOverride string, asJSON, strict bool) error {
	cfg, found, err := config.LoadForReport(config.ExpandPath(cfgPath))
	if err != nil {
		return err
	}
	if !found {
		fmt.Fprintf(os.Stderr, "switchboard: no config at %s — reading defaults\n", cfgPath)
	}
	logPath, err := resolveLog(cfg, logOverride)
	if err != nil {
		return err
	}
	roster, err := cfg.ChangeControl.Roster()
	if err != nil {
		return err
	}

	// Earliest and latest entry under each policy. The earliest is what a late
	// approval is late against.
	first := map[string]time.Time{}
	last := map[string]time.Time{}
	var order []string
	if err := audit.Walk(logPath, func(r audit.Record) error {
		if r.Policy == "" || r.Time.IsZero() {
			return nil
		}
		if _, seen := first[r.Policy]; !seen {
			first[r.Policy] = r.Time
			order = append(order, r.Policy)
		}
		if r.Time.Before(first[r.Policy]) {
			first[r.Policy] = r.Time
		}
		if r.Time.After(last[r.Policy]) {
			last[r.Policy] = r.Time
		}
		return nil
	}); err != nil {
		return err
	}
	sort.SliceStable(order, func(i, j int) bool { return first[order[i]].Before(first[order[j]]) })

	dir := policy.DirFor(logPath)
	states := make([]approval.Status, 0, len(order))
	for _, fp := range order {
		st, err := approval.Check(dir, fp, roster, cfg.ChangeControl.Threshold(), first[fp])
		if err != nil {
			return err
		}
		states = append(states, st)
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(states); err != nil {
			return err
		}
	} else {
		writePolicyHistory(os.Stdout, states, first, last, logPath, cfg.ChangeControl.Enabled)
	}

	if strict {
		var bad []string
		for _, st := range states {
			if !st.Met() {
				bad = append(bad, st.Fingerprint)
			}
		}
		if len(bad) > 0 {
			return fmt.Errorf("%s served under a configuration nobody approved before it ran: %s",
				plural(len(bad), "policy was", "policies were"), join(bad))
		}
	}
	return nil
}

func writePolicyHistory(w io.Writer, states []approval.Status, first, last map[string]time.Time, logPath string, enabled bool) {
	fmt.Fprintf(w, "%s cited by %s\n\n", plural(len(states), "policy", "policies"), logPath)
	if len(states) == 0 {
		fmt.Fprintln(w, "No entry cites a policy fingerprint, so there is nothing to authorise.")
		return
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "POLICY\tIN FORCE\tSTATE\tAPPROVED BY")
	for _, st := range states {
		by := join(st.Approvers)
		if by == "" {
			by = "—"
		}
		fmt.Fprintf(tw, "%s\t%s → %s\t%s\t%s\n",
			st.Fingerprint,
			first[st.Fingerprint].Format("2006-01-02"),
			last[st.Fingerprint].Format("2006-01-02"),
			st.State, by)
	}
	tw.Flush()
	fmt.Fprintln(w)

	if !enabled {
		for _, l := range wrap("Change control is not enabled in this configuration, so no "+
			"signature could be checked against anything. That is not evidence these policies "+
			"were unapproved — it is the absence of a mechanism that could say either way, and "+
			"switching it on now begins covering the policies that come after.", 74) {
			fmt.Fprintf(w, "  %s\n", l)
		}
		return
	}

	var late, unapproved, unverifiable int
	for _, st := range states {
		switch st.State {
		case approval.Late:
			late++
		case approval.Unapproved:
			unapproved++
		case approval.Unverifiable:
			unverifiable++
		}
	}
	if unapproved > 0 {
		for i, l := range wrap(fmt.Sprintf("%s served with no valid signature. Those periods "+
			"ran under rules nobody authorised, and the exception is dated to the day each "+
			"policy first served — not to today.",
			plural(unapproved, "policy", "policies")), 70) {
			fmt.Fprintf(w, "  %s %s\n", mark(i, "!!"), l)
		}
	}
	if late > 0 {
		for i, l := range wrap(fmt.Sprintf("%s approved after it was already serving. Somebody "+
			"reviewed it, which is worth having; nobody authorised it in advance, which is what "+
			"the control asks for. The exception runs from first use to the signature.",
			plural(late, "policy was", "policies were")), 70) {
			fmt.Fprintf(w, "  %s %s\n", mark(i, "! "), l)
		}
	}
	if unverifiable > 0 {
		for i, l := range wrap(fmt.Sprintf("%s carries signatures that check against no "+
			"configured key. An approver removed from the roster stops verifying their own past "+
			"approvals, so record removals rather than making them silently.",
			plural(unverifiable, "policy", "policies")), 70) {
			fmt.Fprintf(w, "  %s %s\n", mark(i, "? "), l)
		}
	}
	if unapproved == 0 && late == 0 && unverifiable == 0 {
		for _, l := range wrap("Every configuration this log ran under was signed by a "+
			"configured approver before it served its first request.", 74) {
			fmt.Fprintf(w, "  %s\n", l)
		}
	}

	fmt.Fprintln(w)
	for _, l := range wrap("What this cannot show: signatures are checked against the roster "+
		"in the configuration you are holding now. Because the roster is inside the policy "+
		"fingerprint, changing it is itself a change needing approval — but somebody who can "+
		"both edit the configuration and hold a key approves their own work, and only a "+
		"minimum above one addresses that.", 74) {
		fmt.Fprintf(w, "  %s\n", l)
	}
}

// mark indents continuation lines under a leading marker.
func mark(i int, m string) string {
	if i == 0 {
		return m
	}
	return "  "
}

// join renders a name list for prose.
func join(xs []string) string {
	switch len(xs) {
	case 0:
		return ""
	case 1:
		return xs[0]
	case 2:
		return xs[0] + " and " + xs[1]
	}
	return fmt.Sprintf("%s and %s", joinComma(xs[:len(xs)-1]), xs[len(xs)-1])
}

func joinComma(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}

// checkApproval gates startup on somebody having authorised this configuration.
//
// The refusal is deliberately at startup and not per request. A gateway that
// served some requests and refused others under one configuration would produce
// a log nobody can reason about; either these rules were authorised or they
// were not, and that is a property of the configuration rather than of a call.
func checkApproval(logger *log.Logger, cfg *config.Config, policyDir string) error {
	if !cfg.ChangeControl.Enabled {
		return nil
	}
	roster, err := cfg.ChangeControl.Roster()
	if err != nil {
		return err
	}
	fp := cfg.PolicyFingerprint()
	// No serving time: this configuration has not served anything yet, so
	// nothing here can be late.
	st, err := approval.Check(policyDir, fp, roster, cfg.ChangeControl.Threshold(), time.Time{})
	if err != nil {
		return err
	}

	if st.Met() {
		logger.Printf("policy %s approved by %s (%d of %d)", fp, join(st.Approvers), st.Valid, st.Minimum)
		return nil
	}
	msg := fmt.Sprintf("policy %s is %s — %d valid signature(s), %d required",
		fp, st.State, st.Valid, st.Minimum)
	for _, p := range st.Problems {
		logger.Printf("approval problem: %s", p)
	}
	if !cfg.ChangeControl.Required {
		// Detective rather than preventive, which is a real choice and not a
		// lesser one — but the report has to be able to say which periods ran
		// unapproved, so this is a warning and never silence.
		logger.Printf("warning: %s. Serving anyway because change_control.required is off; "+
			"'switchboard policy history' will show this period as unapproved", msg)
		return nil
	}
	return fmt.Errorf("%s.\n"+
		"  Approve it:  switchboard policy approve -key KEY -as NAME\n"+
		"  Or set change_control.required to false to serve unapproved configurations "+
		"and have the report say so", msg)
}
