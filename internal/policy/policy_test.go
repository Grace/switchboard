package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Grace/switchboard/internal/config"
)

func cfg(t *testing.T) *config.Config {
	t.Helper()
	c := config.Default()
	c.Models = []config.Line{
		{Name: "claude", Backend: config.BackendBedrock, ModelID: "anthropic.claude-v2"},
	}
	c.Audit.Enabled = true
	return c
}

// The property that makes an archive evidence rather than a folder: a stored
// document hashes to the fingerprint naming it, so the log and the archive can
// be checked against each other by anyone holding both.
func TestArchivedDocumentHashesToItsOwnName(t *testing.T) {
	dir := t.TempDir()
	fp, err := Record(dir, cfg(t))
	if err != nil {
		t.Fatal(err)
	}
	if fp == "" {
		t.Fatal("no fingerprint returned")
	}
	doc, err := Load(dir, fp)
	if err != nil {
		t.Fatalf("a document this package just wrote does not verify: %v", err)
	}
	if len(doc) == 0 {
		t.Fatal("empty document")
	}
	// And the fingerprint has to be the one entries will actually cite.
	if got := cfg(t).PolicyFingerprint(); got != fp {
		t.Errorf("archived under %q, entries will cite %q", fp, got)
	}
}

// A regression with a specific cause. An earlier version indented the document
// on write; Go marshals struct fields in declaration order and map keys sorted,
// so round-tripping through a map re-sorted the keys and every document it
// wrote failed its own check. Storage must not transform the bytes.
func TestStorageDoesNotReformatTheDocument(t *testing.T) {
	dir := t.TempDir()
	fp, err := Record(dir, cfg(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, fp+".json"))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := cfg(t).PolicyDocument()
	if string(raw) != string(want) {
		t.Fatalf("stored bytes differ from the bytes the fingerprint covers\nstored: %s\nwant:   %s",
			raw, want)
	}
}

// An edited archive must stop verifying, or the whole mechanism is decorative.
func TestEditedDocumentIsRefused(t *testing.T) {
	dir := t.TempDir()
	fp, err := Record(dir, cfg(t))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, fp+".json")
	raw, _ := os.ReadFile(path)
	// Change one byte inside the document.
	edited := append([]byte(nil), raw...)
	for i, b := range edited {
		if b == 'a' {
			edited[i] = 'b'
			break
		}
	}
	if err := os.WriteFile(path, edited, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, fp); err == nil {
		t.Fatal("an edited policy document still verified")
	} else if errors.Is(err, ErrNotArchived) {
		t.Fatal("an edited document should be refused, not reported missing")
	}
}

// Missing and corrupt are different findings. Entries written before archiving
// was switched on cite a policy nobody captured, which is a coverage gap and
// not a tampered archive.
func TestMissingIsDistinctFromCorrupt(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir, "deadbeef0000"); !errors.Is(err, ErrNotArchived) {
		t.Fatalf("want ErrNotArchived, got %v", err)
	}
}

// Writing is idempotent: the name is the digest of the content, so a restart
// under unchanged configuration is a no-op rather than a second copy.
func TestRecordIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	first, err := Record(dir, cfg(t))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Record(dir, cfg(t))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("same config archived under two names: %q, %q", first, second)
	}
	all, err := List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("want 1 archived document, got %v", all)
	}
}

// A changed rule is a changed document under a different name, so both remain
// recoverable. An archive that overwrote the old one would lose exactly the
// history it exists to keep.
func TestChangedConfigArchivesSeparately(t *testing.T) {
	dir := t.TempDir()
	before, _ := Record(dir, cfg(t))

	c := cfg(t)
	c.Redaction.Rules = []string{"email"}
	after, err := Record(dir, c)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("a changed policy produced the same fingerprint")
	}
	for _, fp := range []string{before, after} {
		if _, err := Load(dir, fp); err != nil {
			t.Errorf("%s no longer recoverable: %v", fp, err)
		}
	}
}

// Coverage names the periods whose rules cannot be recovered, which is the
// half of the answer a reader can act on.
func TestCheckSeparatesArchivedFromMissing(t *testing.T) {
	dir := t.TempDir()
	fp, _ := Record(dir, cfg(t))

	cov := Check(dir, []string{fp, "deadbeef0000", ""})
	if len(cov.Archived) != 1 || cov.Archived[0] != fp {
		t.Errorf("archived = %v", cov.Archived)
	}
	if len(cov.Missing) != 1 || cov.Missing[0] != "deadbeef0000" {
		t.Errorf("missing = %v", cov.Missing)
	}
}
