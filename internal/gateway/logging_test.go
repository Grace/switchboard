package gateway

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

// syncWriter records writes under a lock, standing in for stdout without the
// data race a bare bytes.Buffer would have against the drain goroutine.
type syncWriter struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}
func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// Logging is best effort while serving, but a process about to exit has no later
// chance to explain itself. Before Close existed, os.Exit raced the drain
// goroutine and roughly a third of startup failures printed nothing at all,
// which is the worst possible outcome for someone configuring this for the first
// time. The loop is what makes a race visible; a single pass passes by luck.
func TestCloseFlushesEverythingQueued(t *testing.T) {
	for range 200 {
		out := &syncWriter{}
		w := NewAsyncLogWriter(out)
		w.Write([]byte("invalid configuration: max_attempts is 9\n"))
		w.Close()
		if !strings.Contains(out.String(), "max_attempts") {
			t.Fatal("a message queued before Close was lost; a fatal error would print nothing")
		}
	}
}

// Close is reached from several fatal paths and must not panic if two of them
// run, nor turn a later write into a send on a closed channel.
func TestCloseIsIdempotentAndWritesAfterAreDropped(t *testing.T) {
	out := &syncWriter{}
	w := NewAsyncLogWriter(out)
	w.Close()
	w.Close()
	if _, err := w.Write([]byte("after close\n")); err != nil {
		t.Fatalf("write after close returned an error: %v", err)
	}
	if strings.Contains(out.String(), "after close") {
		t.Error("a write after Close was emitted")
	}
	if w.Dropped.Load() != 1 {
		t.Errorf("Dropped = %d, want 1", w.Dropped.Load())
	}
}
