package gateway

import (
	"io"
	"sync/atomic"
)

// AsyncLogWriter isolates a slow stdout/log driver from inference. Logging is
// intentionally best effort: saturated queues discard whole records.
type AsyncLogWriter struct {
	queue   chan []byte
	Dropped atomic.Int64
}

func NewAsyncLogWriter(out io.Writer) *AsyncLogWriter {
	w := &AsyncLogWriter{queue: make(chan []byte, 1024)}
	go func() {
		for b := range w.queue {
			if _, e := out.Write(b); e != nil {
				w.Dropped.Add(1)
			}
		}
	}()
	return w
}
func (w *AsyncLogWriter) Write(b []byte) (int, error) {
	select {
	case w.queue <- append([]byte(nil), b...):
	default:
		w.Dropped.Add(1)
	}
	return len(b), nil
}
