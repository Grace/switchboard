package gateway

import (
	"io"
	"sync/atomic"
)

// AsyncLogWriter isolates a slow stdout/log driver from inference. Logging is
// intentionally best effort: saturated queues discard whole records.
type AsyncLogWriter struct {
	queue   chan []byte
	drained chan struct{}
	closed  atomic.Bool
	Dropped atomic.Int64
}

func NewAsyncLogWriter(out io.Writer) *AsyncLogWriter {
	w := &AsyncLogWriter{queue: make(chan []byte, 1024), drained: make(chan struct{})}
	go func() {
		defer close(w.drained)
		for b := range w.queue {
			if _, e := out.Write(b); e != nil {
				w.Dropped.Add(1)
			}
		}
	}()
	return w
}

// Close drains everything queued and blocks until it is written.
//
// Logging is best effort while serving, and deliberately so. A process about to
// exit is the exception: it has no later chance to explain itself, and a
// configuration error that prints nothing is the worst possible failure for
// someone setting this up for the first time. Measured before this existed,
// roughly a third of startup failures exited with no output at all, because
// os.Exit does not wait for the writer goroutine.
//
// Safe to call more than once, and writes after it are dropped rather than
// panicking on a closed channel.
func (w *AsyncLogWriter) Close() {
	if w.closed.CompareAndSwap(false, true) {
		close(w.queue)
	}
	<-w.drained
}

func (w *AsyncLogWriter) Write(b []byte) (int, error) {
	if w.closed.Load() {
		w.Dropped.Add(1)
		return len(b), nil
	}
	select {
	case w.queue <- append([]byte(nil), b...):
	default:
		w.Dropped.Add(1)
	}
	return len(b), nil
}
