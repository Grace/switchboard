package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeLog(t *testing.T, path string, key string, n int) {
	t.Helper()
	if key != "" {
		t.Setenv(keyEnv, key)
	} else {
		t.Setenv(keyEnv, "")
	}
	l, err := Open(path, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := l.Write(Record{ID: "c", Model: "m", PromptTokens: i}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func lines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func rewrite(t *testing.T, path string, ls []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(ls, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func verifyFile(t *testing.T, path, key string) *Report {
	t.Helper()
	var k []byte
	if key != "" {
		k = []byte(key)
	}
	rep, err := Verify(path, k)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestIntactLogVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	writeLog(t, path, "secret-key", 5)

	rep := verifyFile(t, path, "secret-key")
	if rep.Break != nil {
		t.Fatalf("unexpected break: %v", rep.Break)
	}
	if rep.Entries != 5 {
		t.Errorf("entries = %d, want 5", rep.Entries)
	}
	if !rep.Keyed || rep.Head == "" {
		t.Errorf("report = %+v", rep)
	}
}

// The point of the whole thing: an edited entry is found, and the report says
// which one.
func TestAlteredEntryIsCaught(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	writeLog(t, path, "secret-key", 5)

	ls := lines(t, path)
	var rec Record
	if err := json.Unmarshal([]byte(ls[2]), &rec); err != nil {
		t.Fatal(err)
	}
	rec.Model = "a-cheaper-model" // someone rewrites what was actually called
	edited, _ := json.Marshal(rec)
	ls[2] = string(edited)
	rewrite(t, path, ls)

	rep := verifyFile(t, path, "secret-key")
	if rep.Break == nil {
		t.Fatal("an altered entry must break verification")
	}
	if rep.Break.Line != 3 {
		t.Errorf("break at line %d, want 3", rep.Break.Line)
	}
	if rep.Entries != 2 {
		t.Errorf("entries verified before the break = %d, want 2", rep.Entries)
	}
	if !strings.Contains(rep.Break.Reason, "altered") {
		t.Errorf("reason = %q", rep.Break.Reason)
	}
}

// Deleting a record is the edit someone actually wants to make.
func TestDeletedEntryIsCaught(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	writeLog(t, path, "secret-key", 5)

	ls := lines(t, path)
	rewrite(t, path, append(ls[:2:2], ls[3:]...)) // drop the third

	rep := verifyFile(t, path, "secret-key")
	if rep.Break == nil {
		t.Fatal("a deleted entry must break verification")
	}
	if !strings.Contains(rep.Break.Reason, "removed or reordered") {
		t.Errorf("reason should name the cause, got %q", rep.Break.Reason)
	}
}

func TestReorderedEntriesAreCaught(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	writeLog(t, path, "secret-key", 5)

	ls := lines(t, path)
	ls[1], ls[2] = ls[2], ls[1]
	rewrite(t, path, ls)

	if rep := verifyFile(t, path, "secret-key"); rep.Break == nil {
		t.Fatal("reordering must break verification")
	}
}

// Someone with write access but not the key cannot forge a replacement.
func TestForgeryWithoutTheKeyFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	writeLog(t, path, "the-real-key", 3)

	// The attacker recomputes the chain with their own key.
	ls := lines(t, path)
	var rec Record
	json.Unmarshal([]byte(ls[1]), &rec)
	rec.Model = "forged"
	s := newSigner([]byte("attacker-guess"))
	forged, err := s.sign(rec, rec.Seq, rec.Prev)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(forged)
	ls[1] = string(b)
	rewrite(t, path, ls)

	rep := verifyFile(t, path, "the-real-key")
	if rep.Break == nil {
		t.Fatal("a forgery signed with the wrong key must not verify")
	}
	if rep.Break.Line != 2 {
		t.Errorf("break at line %d, want 2", rep.Break.Line)
	}
}

// The verifier must not imply the stronger claim when the log was unsigned.
func TestUnsignedLogsAreVerifiableAndSaySo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	writeLog(t, path, "", 3)

	rep := verifyFile(t, path, "")
	if rep.Break != nil {
		t.Fatalf("unsigned chain should still verify: %v", rep.Break)
	}
	if rep.Keyed {
		t.Error("report must not claim the log was keyed")
	}

	// And it still catches an edit, just not a determined one.
	ls := lines(t, path)
	ls[1] = strings.Replace(ls[1], `"model":"m"`, `"model":"x"`, 1)
	rewrite(t, path, ls)
	if rep := verifyFile(t, path, ""); rep.Break == nil {
		t.Error("an unsigned chain should still catch a casual edit")
	}
}

func TestMismatchedKeyIsExplained(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	writeLog(t, path, "real-key", 2)

	rep := verifyFile(t, path, "")
	if rep.Break == nil {
		t.Fatal("verifying a signed log without the key must not silently pass")
	}
	if !strings.Contains(rep.Break.Reason, keyEnv) {
		t.Errorf("reason should tell the operator to set the key, got %q", rep.Break.Reason)
	}
}

// A restart must continue the chain, not start a second one inside the file.
func TestChainSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	writeLog(t, path, "secret-key", 3)
	writeLog(t, path, "secret-key", 2)

	rep := verifyFile(t, path, "secret-key")
	if rep.Break != nil {
		t.Fatalf("reopened log broke the chain: %v", rep.Break)
	}
	if rep.Entries != 5 {
		t.Errorf("entries = %d, want 5 across two sessions", rep.Entries)
	}
}

// Stated in the docs and asserted here so nobody discovers it during an audit:
// an intact prefix is an intact chain, so tail truncation cannot be detected
// from the file alone.
func TestTailTruncationIsNotDetectable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	writeLog(t, path, "secret-key", 5)

	ls := lines(t, path)
	rewrite(t, path, ls[:3])

	rep := verifyFile(t, path, "secret-key")
	if rep.Break != nil {
		t.Fatalf("a truncated prefix still verifies by design: %v", rep.Break)
	}
	if rep.Entries != 3 {
		t.Errorf("entries = %d", rep.Entries)
	}
}

func TestCorruptJSONIsReportedWithItsLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	writeLog(t, path, "secret-key", 3)

	ls := lines(t, path)
	ls[1] = `{"seq":2,"model":`
	rewrite(t, path, ls)

	rep := verifyFile(t, path, "secret-key")
	if rep.Break == nil || rep.Break.Line != 2 {
		t.Fatalf("break = %+v, want line 2", rep.Break)
	}
}

// A log written before the cache-token fields existed must still verify.
//
// The MAC covers the entry's canonical JSON, so adding a field to Record is a
// change to that JSON — unless the field is omitempty and zero, in which case
// absent and unset produce identical bytes. This is the test that keeps a
// schema addition from silently invalidating every log already on disk, which
// is a failure that would only be discovered by an auditor.
func TestEntriesWrittenBeforeTheCacheFieldsExistedStillVerify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	t.Setenv(keyEnv, "k")

	// Written by hand in the pre-change shape: no cache_write_tokens or
	// cache_read_tokens anywhere, MACed over exactly those bytes.
	l, err := Open(path, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Write(Record{
			Time:  time.Date(2026, 9, 1, 12, i, 0, 0, time.UTC),
			ID:    "chatcmpl-old",
			Model: "claude-opus", Backend: "bedrock",
			PromptTokens: 100, CompletionTokens: 10, StopReason: "end_turn",
		}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "cache_") {
		t.Fatal("zero cache fields were written to the wire; absent and zero " +
			"must be the same bytes or every existing log stops verifying")
	}

	rep, err := VerifyAll(path, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Break != nil {
		t.Fatalf("a log with no cache fields no longer verifies: %v", rep.Break)
	}
	if rep.Entries != 3 {
		t.Errorf("entries = %d, want 3", rep.Entries)
	}
}

// And an entry that does carry cache counts verifies on its own terms.
func TestCacheCountsAreCoveredByTheMAC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	t.Setenv(keyEnv, "k")

	l, err := Open(path, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Record{
		Time: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC), ID: "c",
		Model: "claude-opus", Backend: "bedrock",
		PromptTokens: 3, CompletionTokens: 8, CacheReadTokens: 187361,
	}); err != nil {
		t.Fatal(err)
	}
	l.Close()

	if rep, err := VerifyAll(path, []byte("k")); err != nil || rep.Break != nil {
		t.Fatalf("fresh log does not verify: %v %v", err, rep.Break)
	}

	// Editing the cache count has to break the chain, or the field is recorded
	// without being protected — which would be worse than not recording it.
	raw, _ := os.ReadFile(path)
	edited := strings.Replace(string(raw), `"cache_read_tokens":187361`, `"cache_read_tokens":1`, 1)
	if edited == string(raw) {
		t.Fatal("the cache count is not on the wire")
	}
	os.WriteFile(path, []byte(edited), 0o600)

	rep, err := VerifyAll(path, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Break == nil {
		t.Error("altering a cache count went undetected")
	}
}
