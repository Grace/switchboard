package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func rotatingLog(t *testing.T, path, key string, max int64, retention time.Duration) *Log {
	t.Helper()
	t.Setenv(keyEnv, key)
	l, err := Open(path, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	return l.WithRotation(Rotation{MaxBytes: max, Retention: retention})
}

// The property rotation exists to protect: segments are separate files but one
// chain, and verification sees a single continuous history.
func TestChainContinuesAcrossSegments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := rotatingLog(t, path, "k", 300, 0)

	for i := 0; i < 30; i++ {
		if err := l.Write(Record{ID: "c", Model: "m", PromptTokens: i}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	segs, err := Segments(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) < 2 {
		t.Fatalf("expected rotation, got %d file(s)", len(segs))
	}

	rep, err := VerifyAll(path, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Break != nil {
		t.Fatalf("the chain must survive rotation: %v", rep.Break)
	}
	if rep.Entries != 30 {
		t.Errorf("entries = %d across %d segments, want 30", rep.Entries, rep.Segments)
	}
	if rep.Segments != len(segs) {
		t.Errorf("report says %d segments, found %d", rep.Segments, len(segs))
	}
}

// Removing a whole segment is the tidy version of deleting history, and it is
// exactly what a retention script or a nervous administrator would do.
func TestRemovingASegmentBreaksTheChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := rotatingLog(t, path, "k", 300, 0)
	for i := 0; i < 30; i++ {
		l.Write(Record{ID: "c", Model: "m", PromptTokens: i})
	}
	l.Close()

	segs, _ := Segments(path)
	if len(segs) < 3 {
		t.Skipf("need at least 3 segments, got %d", len(segs))
	}
	if err := os.Remove(segs[1]); err != nil {
		t.Fatal(err)
	}

	rep, err := VerifyAll(path, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Break == nil {
		t.Fatal("deleting a whole segment must break verification")
	}
	if !strings.Contains(rep.Break.Reason, "removed or reordered") {
		t.Errorf("reason = %q", rep.Break.Reason)
	}
}

// Segments sort chronologically, which is what makes reading them in order
// correct rather than lucky.
func TestSegmentsAreOrderedOldestFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := rotatingLog(t, path, "k", 200, 0)
	for i := 0; i < 20; i++ {
		l.Write(Record{ID: "c", Model: "m", PromptTokens: i})
	}
	l.Close()

	segs, _ := Segments(path)
	if len(segs) < 2 {
		t.Skip("no rotation happened")
	}
	if segs[len(segs)-1] != path {
		t.Errorf("the active file must be last, got %v", segs)
	}
	for i := 1; i < len(segs)-1; i++ {
		if segs[i-1] >= segs[i] {
			t.Errorf("segments out of order: %s then %s", segs[i-1], segs[i])
		}
	}
}

func TestRetentionDeletesOldSegmentsAndNeverTheActiveOne(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l := rotatingLog(t, path, "k", 200, 0)
	for i := 0; i < 20; i++ {
		l.Write(Record{ID: "c", Model: "m", PromptTokens: i})
	}
	l.Close()

	segs, _ := Segments(path)
	if len(segs) < 2 {
		t.Skip("no rotation happened")
	}
	// Age every closed segment.
	old := time.Now().Add(-48 * time.Hour)
	for _, s := range segs {
		if s != path {
			os.Chtimes(s, old, old)
		}
	}

	l2 := rotatingLog(t, path, "k", 200, 24*time.Hour)
	if err := l2.prune(); err != nil {
		t.Fatal(err)
	}
	l2.Close()

	after, _ := Segments(path)
	if len(after) != 1 || after[0] != path {
		t.Errorf("retention should have left only the active file, got %v", after)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the active file must never be pruned: %v", err)
	}
}

func TestRetentionOfZeroKeepsEverything(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := rotatingLog(t, path, "k", 200, 0)
	for i := 0; i < 20; i++ {
		l.Write(Record{ID: "c", Model: "m", PromptTokens: i})
	}
	before, _ := Segments(path)
	l.prune()
	after, _ := Segments(path)
	l.Close()

	if len(after) != len(before) {
		t.Errorf("zero retention must delete nothing: %d then %d", len(before), len(after))
	}
}

func TestReopeningAfterRotationStillContinues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	l := rotatingLog(t, path, "k", 250, 0)
	for i := 0; i < 15; i++ {
		l.Write(Record{ID: "c", Model: "m", PromptTokens: i})
	}
	l.Close()

	// A restart reads the active segment's tail and carries on.
	l2 := rotatingLog(t, path, "k", 250, 0)
	for i := 0; i < 15; i++ {
		l2.Write(Record{ID: "c", Model: "m", PromptTokens: 100 + i})
	}
	l2.Close()

	rep, err := VerifyAll(path, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Break != nil {
		t.Fatalf("restart across a rotation broke the chain: %v", rep.Break)
	}
	if rep.Entries != 30 {
		t.Errorf("entries = %d, want 30", rep.Entries)
	}
}

func TestSegmentNamesDoNotCollide(t *testing.T) {
	base := "/tmp/audit.jsonl"
	at := time.Date(2026, 9, 4, 21, 26, 0, 123456789, time.UTC)
	got := segmentPath(base, at)
	if got != "/tmp/audit-20260904T212600.123456789Z.jsonl" {
		t.Errorf("segmentPath = %q", got)
	}

	// Names must sort chronologically, since that is how they are read back.
	earlier := segmentPath(base, at.Add(-time.Nanosecond))
	if !(earlier < got) {
		t.Errorf("%q should sort before %q", earlier, got)
	}
}

// Rotation must not stall. The earlier second-precision naming walked forward a
// second per collision, so a burst of rotations blocked writes for seconds.
func TestRapidRotationDoesNotStall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := rotatingLog(t, path, "k", 200, 0)

	start := time.Now()
	for i := 0; i < 40; i++ {
		if err := l.Write(Record{ID: "c", Model: "m", PromptTokens: i}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()

	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("40 writes with rotation took %s; rotation is stalling", elapsed)
	}
	if rep, err := VerifyAll(path, []byte("k")); err != nil || rep.Break != nil {
		t.Errorf("chain broken: %v %v", err, rep.Break)
	}
}

func TestNoRotationConfiguredMeansOneFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := rotatingLog(t, path, "k", 0, 0)
	for i := 0; i < 50; i++ {
		l.Write(Record{ID: "c", Model: "m", PromptTokens: i})
	}
	l.Close()

	segs, _ := Segments(path)
	if len(segs) != 1 {
		t.Errorf("without MaxBytes there should be one file, got %v", segs)
	}
}
