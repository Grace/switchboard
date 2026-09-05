// Package evidence assembles a period of the audit log into something you can
// hand to somebody who does not trust you.
//
// The distinction from the viewer is the audience. A page is for the person who
// runs the deployment; a package is for the person auditing it, and that person
// has a different question. Not "what happened" but "why should I believe this
// is what happened" — which is answerable only if the artefact carries the
// original bytes, the digests over them, the verification result, and an honest
// statement of what it still does not prove.
//
// So a package is deliberately not a rendering. It carries the log lines
// verbatim, because the MAC covers those bytes and a re-encoded entry is a
// different entry. It carries a manifest whose own digest is the one thing you
// record somewhere else. And it carries VERIFY.md, which tells the recipient how
// to check all of it without running switchboard and without asking you.
//
// The limit is stated rather than hidden. An intact chain proves no entry was
// altered; it cannot prove none was removed from the end, because a truncated
// prefix is itself an intact chain. Closing that needs an anchor held by someone
// who is not the author of the log. Until there is one, VERIFY.md says so.
package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Grace/switchboard/internal/assess"
	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/policy"
	"github.com/Grace/switchboard/internal/viewer"
)

// Options is everything Build needs.
type Options struct {
	// LogPath is the audit log, including its rotated segments.
	LogPath string
	// Out is the directory to create. It must not already exist: overwriting
	// part of an evidence package would leave a directory whose manifest
	// describes files that are no longer there.
	Out string
	// Key verifies the chain. Without it the package still builds and says
	// plainly that the entries are digested rather than signed.
	Key    []byte
	Period Period
	Prices viewer.Prices
	// Deployment and Report describe the configuration in force. They come from
	// the caller because reading a config is config's job, and because a package
	// built for a foreign gateway would supply its own adapter.
	Deployment assess.Deployment
	Report     assess.ControlReport
	// Tool identifies what produced this, for the manifest.
	Tool string
	// Now is injectable so a test can produce a stable manifest.
	Now func() time.Time
}

// File is one member of the package.
type File struct {
	Name   string `json:"name"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
	What   string `json:"what"`
}

// Extract describes the slice of the chain the package carries.
type Extract struct {
	Entries int `json:"entries"`
	// Traced counts entries carrying a W3C trace id. Those are the ones whose
	// fuller story — retries, intermediate steps, the model's own reasoning —
	// exists in the caller's tracing system and deliberately not here.
	Traced   int    `json:"traced,omitempty"`
	FirstSeq uint64 `json:"first_seq,omitempty"`
	LastSeq  uint64 `json:"last_seq,omitempty"`
	// FirstPrev is the MAC of the entry immediately before this slice, taken
	// from the first extracted entry's own prev field. It is what ties the
	// extract to the log it came out of: a recipient holding the full log can
	// find that entry and confirm this slice starts where it claims to.
	FirstPrev string `json:"first_prev,omitempty"`
	// LastMAC is the last extracted entry's MAC, which is where a recipient
	// holding the full log resumes.
	LastMAC string `json:"last_mac,omitempty"`
}

// Chain is the verification result over the whole log, not the extract.
//
// Over the whole log deliberately: a break anywhere means every entry after it
// is in a file somebody may have edited, including the ones inside this period.
type Chain struct {
	Entries  int    `json:"entries"`
	Segments int    `json:"segments"`
	Signed   bool   `json:"signed"`
	Verified bool   `json:"verified"`
	Head     string `json:"head,omitempty"`
	Break    string `json:"break,omitempty"`
}

// Manifest is the index of the package, and the only file whose digest you have
// to record somewhere this package is not.
type Manifest struct {
	Tool      string    `json:"tool"`
	Generated time.Time `json:"generated"`
	Period    struct {
		Label string    `json:"label"`
		From  time.Time `json:"from"`
		To    time.Time `json:"to"`
	} `json:"period"`
	Log struct {
		Path     string `json:"path"`
		Segments int    `json:"segments"`
	} `json:"log"`
	Chain    Chain    `json:"chain"`
	Extract  Extract  `json:"extract"`
	Policies []string `json:"policies"`
	// PoliciesArchived are the fingerprints whose configuration is included
	// here; PoliciesMissing are the ones cited by entries and never captured.
	// The second list is the useful one: it names the stretch of this period
	// whose rules cannot be recovered, and no change made later recovers them.
	PoliciesArchived []string `json:"policies_archived,omitempty"`
	PoliciesMissing  []string `json:"policies_missing,omitempty"`
	Controls         struct {
		Profile string         `json:"profile,omitempty"`
		Regime  string         `json:"regime,omitempty"`
		Counts  map[string]int `json:"counts"`
	} `json:"controls"`
	Files []File `json:"files"`
	// Note is addressed to whoever opens this in two years.
	Note string `json:"note"`
}

// Result is what Build produced.
type Result struct {
	Dir      string
	Manifest Manifest
	// Digest is the SHA-256 of manifest.json. Every other file's digest is
	// inside the manifest, so this one value covers the package — which is
	// exactly why it is the value to record somewhere else.
	Digest string
	// Unanchored is true while nothing outside this package attests to the
	// digest. It is the honest state of a package built by the same party that
	// wrote the log, and it is what an anchor would change.
	Unanchored bool
}

const (
	fileEntries  = "audit.jsonl"
	fileReport   = "report.html"
	fileControls = "controls.json"
	fileManifest = "manifest.json"
	fileVerify   = "VERIFY.md"
	dirPolicies  = "policies"
)

// member is one file in the package, and its line in the manifest.
type member struct {
	name, what string
	data       []byte
}

// Build assembles the package.
func Build(o Options) (*Result, error) {
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if o.Tool == "" {
		o.Tool = "switchboard"
	}
	if o.Period.To.IsZero() {
		return nil, fmt.Errorf("no period: an evidence package covers a stated window")
	}
	// Refuse to write into an existing directory. A half-overwritten package is
	// one whose manifest describes files that are no longer beside it, which is
	// worse than no package at all.
	if _, err := os.Stat(o.Out); err == nil {
		return nil, fmt.Errorf("%s already exists: an evidence package is written once, "+
			"to somewhere new, so a manifest always describes the files beside it", o.Out)
	}
	segs, err := audit.Segments(o.LogPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(o.Out, 0o700); err != nil {
		return nil, err
	}

	// The entries, byte for byte as they were written.
	var entries bytes.Buffer
	var ex Extract
	policies := map[string]bool{}
	err = audit.WalkRaw(o.LogPath, func(r audit.Record, raw []byte) error {
		if !o.Period.Contains(r.Time) {
			return nil
		}
		if ex.Entries == 0 {
			ex.FirstSeq, ex.FirstPrev = r.Seq, r.Prev
		}
		ex.Entries++
		ex.LastSeq, ex.LastMAC = r.Seq, r.MAC
		if r.TraceID != "" {
			ex.Traced++
		}
		if r.Policy != "" {
			policies[r.Policy] = true
		}
		entries.Write(raw)
		entries.WriteByte('\n')
		return nil
	})
	if err != nil {
		return nil, err
	}

	rep, verr := audit.VerifyAll(o.LogPath, o.Key)
	chain := Chain{Segments: len(segs)}
	switch {
	case verr != nil:
		chain.Break = verr.Error()
	default:
		chain.Entries, chain.Signed, chain.Head = rep.Entries, rep.Keyed, rep.Head
		chain.Verified = rep.Break == nil
		if rep.Break != nil {
			chain.Break = rep.Break.Error()
		}
	}

	// The page, filtered to the period, rendered by the same code that serves it.
	var report bytes.Buffer
	q := viewer.Query{}.Between(o.Period.From, o.Period.To)
	// Static: this page goes in a package, and a package has no server.
	if _, err := viewer.RenderStatic(&report, o.LogPath, o.Key, q, o.Prices); err != nil {
		return nil, err
	}

	controls, err := json.MarshalIndent(o.Report, "", "  ")
	if err != nil {
		return nil, err
	}
	controls = append(controls, '\n')

	m := Manifest{Tool: o.Tool, Generated: o.Now()}
	m.Period.Label, m.Period.From, m.Period.To = o.Period.Label, o.Period.From, o.Period.To
	m.Log.Path, m.Log.Segments = o.LogPath, len(segs)
	m.Chain, m.Extract = chain, ex
	m.Controls.Profile = string(o.Report.Profile)
	m.Controls.Regime = o.Report.Regime
	m.Controls.Counts = map[string]int{}
	for status, n := range o.Report.Counts() {
		m.Controls.Counts[string(status)] = n
	}
	for p := range policies {
		m.Policies = append(m.Policies, p)
	}
	sort.Strings(m.Policies)
	// The documents behind those fingerprints, where they were archived. A
	// manifest naming a policy the recipient cannot read is a citation to a
	// source they do not have — and this package exists precisely so the
	// recipient does not have to come back and ask.
	//
	// Each is copied byte for byte and lands in the manifest like any other
	// member, so its digest is covered by the package digest. It also still
	// hashes to its own filename, which means a reader can tie a policy to the
	// entries citing it without trusting this package at all.
	cov := policy.Check(policy.DirFor(o.LogPath), m.Policies)
	m.PoliciesArchived, m.PoliciesMissing = cov.Archived, cov.Missing
	m.Note = "The digest of this file covers the package. Record it somewhere this " +
		"package is not; see " + fileVerify + "."

	verify := verifyDoc(o, m)

	// Write the members, then the manifest over their digests, so the manifest
	// always describes what is actually on disk.
	var members []member
	for _, f := range []member{
		{fileEntries, "the audit entries for this period, byte for byte as they were written", entries.Bytes()},
		{fileReport, "a self-contained page of the same period, for reading", report.Bytes()},
		{fileControls, "the control assessment of the configuration in force", controls},
		{fileVerify, "how to check all of this without running switchboard", []byte(verify)},
	} {
		members = append(members, f)
	}
	// The archived configurations, one file each under policies/, byte for byte
	// as stored. They keep their fingerprint filenames on purpose: each still
	// hashes to its own name, so a recipient can bind a policy to the entries
	// citing it without trusting this package or its author.
	policyDir := policy.DirFor(o.LogPath)
	for _, fp := range cov.Archived {
		doc, err := policy.Load(policyDir, fp)
		if err != nil {
			// Readable a moment ago during Check and not now. Report it rather
			// than shipping a manifest that promises a file which is not there.
			return nil, fmt.Errorf("policy %s: %w", fp, err)
		}
		members = append(members, member{
			name: filepath.Join(dirPolicies, fp+".json"),
			what: "the configuration in force for the entries citing " + fp,
			data: doc,
		})
	}
	if len(cov.Archived) > 0 {
		if err := os.MkdirAll(filepath.Join(o.Out, dirPolicies), 0o700); err != nil {
			return nil, err
		}
	}

	for _, f := range members {
		if err := os.WriteFile(filepath.Join(o.Out, f.name), f.data, 0o600); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(f.data)
		m.Files = append(m.Files, File{
			Name: f.name, Bytes: len(f.data),
			SHA256: hex.EncodeToString(sum[:]), What: f.what,
		})
	}

	manifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	manifest = append(manifest, '\n')
	if err := os.WriteFile(filepath.Join(o.Out, fileManifest), manifest, 0o600); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(manifest)

	return &Result{
		Dir: o.Out, Manifest: m,
		Digest:     hex.EncodeToString(sum[:]),
		Unanchored: true,
	}, nil
}
