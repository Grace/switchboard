package audit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeSome(t *testing.T, path, key string, n int) *Log {
	t.Helper()
	t.Setenv(keyEnv, key)
	l, err := Open(path, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := l.Write(Record{ID: "c", Model: "m", PromptTokens: i}); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

func TestVerifyReportsAnIntactChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := writeSome(t, path, "k", 5)
	defer l.Close()

	st, err := l.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if st.Break != nil {
		t.Fatalf("unexpected break: %v", st.Break)
	}
	if st.Entries != 5 {
		t.Errorf("entries = %d", st.Entries)
	}
	if st.At.IsZero() {
		t.Error("the result should be timestamped")
	}
	if _, err := l.Health(); err != nil {
		t.Errorf("an intact chain should be healthy, got %v", err)
	}
}

// The case this exists for: the file was edited, and nothing else would have
// noticed until an auditor asked.
func TestVerifyDetectsAnEditAndMakesItUnhealthy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := writeSome(t, path, "k", 5)
	l.Close()

	raw, _ := os.ReadFile(path)
	ls := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var rec Record
	json.Unmarshal([]byte(ls[2]), &rec)
	rec.Model = "something-cheaper"
	edited, _ := json.Marshal(rec)
	ls[2] = string(edited)
	os.WriteFile(path, []byte(strings.Join(ls, "\n")+"\n"), 0o600)

	// Reopening is the restart case: the edit happened while we were down.
	l2 := writeSome(t, path, "k", 0)
	defer l2.Close()

	st, err := l2.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if st.Break == nil {
		t.Fatal("an edit made while the process was down must be found at startup")
	}
	if st.Break.Line != 3 {
		t.Errorf("break at line %d, want 3", st.Break.Line)
	}

	_, hErr := l2.Health()
	if hErr == nil {
		t.Fatal("a broken chain must make the log unhealthy")
	}
	if !strings.Contains(hErr.Error(), "chain broken") {
		t.Errorf("health error should name the problem: %v", hErr)
	}
}

// A broken chain outranks a stalled shipper: one is a lost copy, the other is a
// record that no longer says what it said.
func TestBrokenChainOutranksArchiveFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := writeSome(t, path, "k", 3)
	defer l.Close()

	l.mu.Lock()
	l.archiveErr = errors.New("archiving failed")
	l.chain = &ChainState{Break: &Break{Line: 2, Seq: 2, Reason: "altered"}}
	l.mu.Unlock()

	_, err := l.Health()
	if err == nil || !strings.Contains(err.Error(), "chain broken") {
		t.Errorf("health = %v, want the chain break", err)
	}
}

func TestWatchReverifiesOnItsInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := writeSome(t, path, "k", 3)
	defer l.Close()

	var mu sync.Mutex
	var lines []string
	logf := func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, f)
	}

	// Break the chain, then let the watcher find it.
	raw, _ := os.ReadFile(path)
	ls := strings.Split(strings.TrimSpace(string(raw)), "\n")
	ls[1] = strings.Replace(ls[1], `"model":"m"`, `"model":"x"`, 1)
	os.WriteFile(path, []byte(strings.Join(ls, "\n")+"\n"), 0o600)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Watch(ctx, 20*time.Millisecond, logf)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(lines)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(lines) == 0 {
		t.Fatal("the watcher never reported the break")
	}
	if !strings.Contains(lines[0], "CHAIN BROKEN") {
		t.Errorf("report = %q", lines[0])
	}
}

func TestWatchStopsWithItsContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := writeSome(t, path, "k", 2)
	defer l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { l.Watch(ctx, 10*time.Millisecond, func(string, ...any) {}); close(done) }()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Watch did not stop when its context ended")
	}
}

func TestWatchAndVerifyAreSafeOnNothing(t *testing.T) {
	var l *Log
	if st, err := l.Verify(); st != nil || err != nil {
		t.Errorf("nil log: %v %v", st, err)
	}
	if l.Chain() != nil {
		t.Error("nil log should have no chain state")
	}
	l.Watch(context.Background(), time.Second, func(string, ...any) {})
}
