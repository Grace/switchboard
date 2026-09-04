package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Grace/switchboard/internal/redact"
)

type buf struct{ bytes.Buffer }

func (b *buf) Close() error { return nil }

func redactor(t *testing.T, names ...string) *redact.Redactor {
	t.Helper()
	r, err := redact.New(names, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func decode(t *testing.T, b *buf) Record {
	t.Helper()
	var r Record
	if err := json.Unmarshal(b.Bytes(), &r); err != nil {
		t.Fatalf("decode %q: %v", b.String(), err)
	}
	return r
}

// The default: metadata is recorded, content is not, and the counts still say
// what crossed the boundary.
func TestMetadataOnlyByDefault(t *testing.T) {
	b := &buf{}
	l := newLog(b, redactor(t, "email"), false)
	err := l.Write(Record{
		ID: "c1", Team: "search", Model: "m",
		Prompt: "mail grace@example.com now", Completion: "ok",
		PromptTokens: 10, CompletionTokens: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := decode(t, b)

	if got.Prompt != "" || got.Completion != "" {
		t.Errorf("content stored with log_content off: %+v", got)
	}
	if strings.Contains(b.String(), "grace@example.com") {
		t.Errorf("raw address reached the file: %s", b.String())
	}
	if got.Redactions["email"] != 1 {
		t.Errorf("redaction counts should survive without content: %v", got.Redactions)
	}
	if got.Team != "search" || got.PromptTokens != 10 {
		t.Errorf("metadata lost: %+v", got)
	}
	if got.Time.IsZero() {
		t.Error("time should be filled in")
	}
}

func TestContentIsRedactedWhenStored(t *testing.T) {
	b := &buf{}
	l := newLog(b, redactor(t, "email"), true)
	if err := l.Write(Record{ID: "c1", Model: "m", Prompt: "to grace@example.com"}); err != nil {
		t.Fatal(err)
	}
	got := decode(t, b)
	if got.Prompt != "to [redacted:email]" {
		t.Errorf("prompt = %q", got.Prompt)
	}
	if strings.Contains(b.String(), "grace@example.com") {
		t.Error("raw address reached the file")
	}
}

// The design decision worth protecting: you cannot log content without a
// redactor, and it is refused at open rather than silently downgraded.
func TestContentWithoutRedactionIsRefused(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "a.jsonl"), nil, true)
	if err == nil {
		t.Fatal("content logging with no redactor must be refused")
	}
	if !strings.Contains(err.Error(), "refusing") {
		t.Errorf("error should say what it refused: %v", err)
	}
}

func TestOpenAppendsAndClosesCleanly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for i := 0; i < 2; i++ {
		l, err := Open(path, redactor(t), false)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Write(Record{ID: "c", Model: "m"}); err != nil {
			t.Fatal(err)
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// two opens, two records, appended not truncated
	data := readFile(t, path)
	if n := strings.Count(strings.TrimSpace(data), "\n") + 1; n != 2 {
		t.Errorf("want 2 records, got %d: %s", n, data)
	}
}

func TestNilLogIsSafe(t *testing.T) {
	var l *Log
	if err := l.Write(Record{}); err != nil {
		t.Errorf("writing to a nil log should be a no-op, got %v", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("closing a nil log should be a no-op, got %v", err)
	}
}

func TestConcurrentWritesProduceWholeLines(t *testing.T) {
	b := &buf{}
	l := newLog(b, redactor(t, "email"), true)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = l.Write(Record{ID: "c", Model: "m", Prompt: "x grace@example.com"})
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 50 {
		t.Fatalf("want 50 lines, got %d", len(lines))
	}
	for i, ln := range lines {
		var r Record
		if err := json.Unmarshal([]byte(ln), &r); err != nil {
			t.Fatalf("line %d is not whole JSON: %q", i, ln)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
