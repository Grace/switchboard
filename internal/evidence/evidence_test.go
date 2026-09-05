package evidence

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Grace/switchboard/internal/assess"
	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/redact"
)

const testKey = "test-audit-key"

func demoLog(t *testing.T, n int, start time.Time, step time.Duration) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv("SWITCHBOARD_AUDIT_KEY", testKey)
	red, err := redact.New([]string{"email"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := audit.Open(path, red, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := l.Write(audit.Record{
			Time: start.Add(time.Duration(i) * step),
			ID:   "chatcmpl-" + string(rune('a'+i%26)), Policy: "fingerprint01",
			Team: "search", Subject: "dana@corp", Model: "claude-opus", Backend: "bedrock",
			PromptTokens: 100, CompletionTokens: 10, StopReason: "end_turn",
		}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	return path
}

func build(t *testing.T, path string, p Period, key []byte) *Result {
	t.Helper()
	dep := assess.Deployment{Source: "test", Profile: assess.ProfileEUAIAct}
	res, err := Build(Options{
		LogPath: path, Out: filepath.Join(t.TempDir(), "pkg"), Key: key, Period: p,
		Deployment: dep, Report: assess.Assess(dep), Tool: "switchboard test",
		Now: func() time.Time { return time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// The load-bearing claim of the whole package: the extracted entries are the
// bytes that were written, so they still verify. Re-encoding them would produce
// a file that looks right and verifies against nothing.
//
// This checks them the way VERIFY.md tells a recipient to — textual
// substitution of the mac field, then HMAC — so the test also proves the
// instructions in that document actually work.
func TestExtractedEntriesStillVerifyByTheDocumentedRecipe(t *testing.T) {
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	path := demoLog(t, 40, start, 36*time.Hour) // spans August into September
	p, err := ParsePeriod("2026-08")
	if err != nil {
		t.Fatal(err)
	}
	res := build(t, path, p, []byte(testKey))

	data, err := os.ReadFile(filepath.Join(res.Dir, fileEntries))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != res.Manifest.Extract.Entries {
		t.Fatalf("%d lines, manifest says %d", len(lines), res.Manifest.Extract.Entries)
	}
	if len(lines) == 0 {
		t.Fatal("the period is empty; the test proves nothing")
	}

	macTail := regexp.MustCompile(`"mac":"[^"]*"\}$`)
	var prev string
	var seq uint64
	for i, line := range lines {
		var rec audit.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		canonical := macTail.ReplaceAll([]byte(line), []byte(`"mac":""}`))
		m := hmac.New(sha256.New, []byte(testKey))
		m.Write(canonical)
		want := "h:" + hex.EncodeToString(m.Sum(nil))
		if want != rec.MAC {
			t.Fatalf("entry %d (seq %d) does not verify by the documented recipe", i, rec.Seq)
		}
		if i > 0 {
			if rec.Seq != seq+1 {
				t.Errorf("entry %d: seq jumped %d -> %d", i, seq, rec.Seq)
			}
			if rec.Prev != prev {
				t.Errorf("entry %d does not follow the previous one", i)
			}
		}
		seq, prev = rec.Seq, rec.MAC
		if !p.Contains(rec.Time) {
			t.Errorf("entry %d at %s is outside %s", i, rec.Time, p.Label)
		}
	}
	if res.Manifest.Extract.LastMAC != prev {
		t.Error("the manifest's last MAC is not the last entry's")
	}
}

// The manifest is the index, so every digest in it has to describe the file
// actually sitting beside it.
func TestManifestDigestsMatchTheFilesOnDisk(t *testing.T) {
	path := demoLog(t, 12, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), time.Hour)
	p, _ := ParsePeriod("2026-09")
	res := build(t, path, p, []byte(testKey))

	if len(res.Manifest.Files) < 4 {
		t.Fatalf("manifest lists %d files", len(res.Manifest.Files))
	}
	for _, f := range res.Manifest.Files {
		data, err := os.ReadFile(filepath.Join(res.Dir, f.Name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != f.SHA256 {
			t.Errorf("%s: digest %s, manifest says %s", f.Name, got, f.SHA256)
		}
		if len(data) != f.Bytes {
			t.Errorf("%s: %d bytes, manifest says %d", f.Name, len(data), f.Bytes)
		}
	}

	// And the package digest is the manifest's own, which is what makes one
	// value enough to record.
	raw, err := os.ReadFile(filepath.Join(res.Dir, fileManifest))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != res.Digest {
		t.Errorf("package digest %s, manifest file digests to %s", res.Digest, got)
	}
}

// Half-open, and the boundary is the reason the type exists: an entry at
// exactly the end belongs to the next period, or two quarterly reports both
// claim it.
func TestThePeriodBoundaryIsHalfOpen(t *testing.T) {
	q3End := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	path := demoLog(t, 3, q3End.Add(-time.Hour), time.Hour) // 23:00, 00:00, 01:00
	p, err := ParsePeriod("2026-Q3")
	if err != nil {
		t.Fatal(err)
	}
	res := build(t, path, p, []byte(testKey))
	if res.Manifest.Extract.Entries != 1 {
		t.Errorf("Q3 took %d of 3 entries; the one at exactly %s belongs to Q4",
			res.Manifest.Extract.Entries, q3End.Format(time.RFC3339))
	}
	if !p.From.Equal(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)) || !p.To.Equal(q3End) {
		t.Errorf("Q3 = %s to %s", p.From, p.To)
	}
}

func TestPeriodFormsAndRejections(t *testing.T) {
	for _, c := range []struct{ in, from, to string }{
		{"2026", "2026-01-01", "2027-01-01"},
		{"2026-Q1", "2026-01-01", "2026-04-01"},
		{"2026-q4", "2026-10-01", "2027-01-01"},
		{"2026-02", "2026-02-01", "2026-03-01"},
		{"2026-09-04", "2026-09-04", "2026-09-05"},
		{"2026-07-01..2026-10-01", "2026-07-01", "2026-10-01"},
	} {
		p, err := ParsePeriod(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if p.From.Format("2006-01-02") != c.from || p.To.Format("2006-01-02") != c.to {
			t.Errorf("%s = %s..%s, want %s..%s", c.in,
				p.From.Format("2006-01-02"), p.To.Format("2006-01-02"), c.from, c.to)
		}
	}
	for _, bad := range []string{"", "2026-Q5", "last quarter", "2026-13", "2026-10-01..2026-07-01"} {
		if _, err := ParsePeriod(bad); err == nil {
			t.Errorf("%q should not parse", bad)
		}
	}
}

// A manifest describing files that are no longer beside it is worse than no
// package, so the directory has to be new.
func TestBuildRefusesToWriteIntoAnExistingDirectory(t *testing.T) {
	path := demoLog(t, 2, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), time.Hour)
	dir := t.TempDir() // exists
	p, _ := ParsePeriod("2026-09")
	_, err := Build(Options{LogPath: path, Out: dir, Period: p, Key: []byte(testKey)})
	if err == nil {
		t.Fatal("writing into an existing directory should be refused")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// A package built over a broken chain must say so on its face. Shipping one
// that reads as clean would be the single worst failure this code could have.
func TestABrokenChainIsOnTheFaceOfThePackage(t *testing.T) {
	path := demoLog(t, 10, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), time.Hour)
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	lines[4] = strings.Replace(lines[4], `"team":"search"`, `"team":"nobody"`, 1)
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)

	p, _ := ParsePeriod("2026-09")
	res := build(t, path, p, []byte(testKey))
	if res.Manifest.Chain.Verified {
		t.Fatal("an edited log reported as verified")
	}
	if res.Manifest.Chain.Break == "" {
		t.Fatal("the break is not in the manifest")
	}
	verify := read(t, filepath.Join(res.Dir, fileVerify))
	if !strings.Contains(verify, "The chain did not verify") {
		t.Error("VERIFY.md does not lead with the break")
	}
}

// Unsigned is a materially weaker claim than signed, and the document has to
// make that difference visible rather than saying "verified" either way.
func TestAnUnsignedLogSaysSoInTheInstructions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv("SWITCHBOARD_AUDIT_KEY", "")
	l, err := audit.Open(path, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(audit.Record{Time: time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC),
		ID: "x", Model: "m", Backend: "local", PromptTokens: 1})
	l.Close()

	p, _ := ParsePeriod("2026-09")
	res := build(t, path, p, nil)
	if res.Manifest.Chain.Signed {
		t.Fatal("a keyless log reported as signed")
	}
	verify := read(t, filepath.Join(res.Dir, fileVerify))
	for _, want := range []string{"not signed", "s:", "removed from the end"} {
		if !strings.Contains(verify, want) {
			t.Errorf("VERIFY.md missing %q", want)
		}
	}
}

// The limit that sells the next thing, and the one most tempting to leave
// implied. It has to be in the package unconditionally.
func TestTheTruncationLimitIsAlwaysStated(t *testing.T) {
	path := demoLog(t, 5, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), time.Hour)
	p, _ := ParsePeriod("2026-09")
	res := build(t, path, p, []byte(testKey))
	verify := read(t, filepath.Join(res.Dir, fileVerify))
	for _, want := range []string{
		"removed from the end",
		"somewhere the author of the log does not control",
	} {
		if !strings.Contains(verify, want) {
			t.Errorf("VERIFY.md does not state the truncation limit: missing %q", want)
		}
	}
	if !res.Unanchored {
		t.Error("a self-produced package is unanchored by definition")
	}
	// The report inside is the same page the viewer serves, and stays scriptless.
	report := read(t, filepath.Join(res.Dir, fileReport))
	if strings.Contains(report, "<script") {
		t.Error("the packaged report carries script")
	}
	if !strings.Contains(report, "<svg class=\"flow\"") {
		t.Error("the packaged report has no diagram")
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
