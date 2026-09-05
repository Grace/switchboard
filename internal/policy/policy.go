// Package policy archives the configuration each audit entry cites.
//
// Every entry carries a policy fingerprint, which answers "did the rules
// change" and cannot answer "what were they". A digest naming a document nobody
// kept is a citation to a missing source: it proves a change happened and
// leaves the reader no way to see what changed, which is precisely the question
// asked when a decision is disputed months later.
//
// The archive is content-addressed and self-verifying. A stored document hashes
// to the fingerprint that names it, so anyone holding the log and the archive
// can confirm the two belong together without trusting whoever wrote either.
// That is the difference between an archive and a folder of assertions.
//
// It is deliberately not part of the audit chain. The chain is a sequence of
// events and this is a set of documents; binding them would mean a policy write
// could break a chain, and refusing to serve because a configuration could not
// be archived is a worse failure than serving with the archive one file short.
package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Grace/switchboard/internal/config"
)

// DirName is the directory written beside the audit log.
const DirName = "policies"

// DirFor returns the archive directory for a log path.
//
// Derived rather than configured, so an evidence package can find it without
// being told and a deployment cannot end up with entries citing an archive
// nobody knows the location of.
func DirFor(logPath string) string {
	return filepath.Join(filepath.Dir(logPath), DirName)
}

// Record writes the configuration under its own fingerprint.
//
// Writing is idempotent: the name is the digest of the content, so a restart
// under unchanged configuration rewrites the same bytes to the same path. It
// returns the fingerprint so a caller can log what it archived.
func Record(dir string, cfg *config.Config) (string, error) {
	doc, fp := cfg.PolicyDocument()
	if fp == "" {
		return "", errors.New("policy: configuration could not be serialised")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	// Stored byte for byte as the fingerprint was taken over. An earlier
	// version indented this for readability, which silently broke every
	// document it wrote: Go marshals struct fields in declaration order and map
	// keys sorted, so round-tripping through a map re-sorts the keys and the
	// digest no longer matches. Formatting is a concern at print time, where it
	// costs nothing; here it destroys the only property that matters.
	path := filepath.Join(dir, fp+".json")
	if err := os.WriteFile(path, doc, 0o644); err != nil {
		return "", err
	}
	return fp, nil
}

// ErrNotArchived means no document was stored for this fingerprint.
//
// Its own error because it is the common and least alarming case: entries
// written before archiving was switched on cite a policy that was never
// captured, and that is a gap in coverage rather than a corrupted archive.
var ErrNotArchived = errors.New("policy: not archived")

// Load reads the document for a fingerprint and checks it against its name.
func Load(dir, fingerprint string) ([]byte, error) {
	if fingerprint == "" {
		return nil, ErrNotArchived
	}
	path := filepath.Join(dir, filepath.Base(fingerprint)+".json")
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, ErrNotArchived
	}
	if err != nil {
		return nil, err
	}
	// Hashed exactly as stored. There is no normalisation step here on purpose:
	// any transformation between the file and the digest is a place where a
	// document that was edited could still be made to verify.
	if !config.VerifyPolicyDocument(raw, fingerprint) {
		return nil, fmt.Errorf("policy %s: stored document does not hash to its own name, "+
			"so it is not the configuration the entries citing it were served under", fingerprint)
	}
	return raw, nil
}

// List returns the fingerprints held in the archive, sorted.
func List(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		out = append(out, strings.TrimSuffix(e.Name(), ".json"))
	}
	sort.Strings(out)
	return out, nil
}

// Coverage reports which of the fingerprints a log cites are archived.
//
// The missing list is the useful half. It names the periods of the log whose
// rules cannot be recovered, which is a finding with a knowable start date
// rather than a vague gap.
type Coverage struct {
	Archived []string `json:"archived,omitempty"`
	Missing  []string `json:"missing,omitempty"`
}

// Check compares the fingerprints seen in a log against the archive.
func Check(dir string, seen []string) Coverage {
	var c Coverage
	for _, fp := range seen {
		if fp == "" {
			continue
		}
		if _, err := Load(dir, fp); err != nil {
			c.Missing = append(c.Missing, fp)
			continue
		}
		c.Archived = append(c.Archived, fp)
	}
	sort.Strings(c.Archived)
	sort.Strings(c.Missing)
	return c
}
