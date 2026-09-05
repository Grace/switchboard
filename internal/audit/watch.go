package audit

import (
	"context"
	"fmt"
	"time"
)

// A chain nobody walks proves nothing.
//
// Verification is cheap to run and easy to forget, and the gap between an entry
// being altered and someone noticing is the whole value of the property. So the
// log checks itself: once at startup, and then on an interval.
//
// Startup is the more important of the two. The window when this process is not
// running is exactly when a file would be edited, and it is the only moment
// where "the chain was intact when we stopped, and is not now" can be observed
// at all.

// ChainState is the result of the last verification.
type ChainState struct {
	At       time.Time
	Entries  int
	Segments int
	Break    *Break
}

// Verify walks the log's own segments and records the outcome.
func (l *Log) Verify() (*ChainState, error) {
	if l == nil || l.path == "" {
		return nil, nil
	}
	rep, err := VerifyAll(l.path, l.signer.key)
	if err != nil {
		return nil, err
	}
	st := &ChainState{
		At: time.Now(), Entries: rep.Entries,
		Segments: rep.Segments, Break: rep.Break,
	}

	l.mu.Lock()
	l.chain = st
	l.mu.Unlock()
	return st, nil
}

// Chain returns the last verification result, if any.
func (l *Log) Chain() *ChainState {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.chain
}

// Watch re-verifies on an interval until the context ends.
//
// Verification reads every segment, so on a large log this is real I/O. That is
// the argument for an hour rather than a minute, and for archiving segments off
// the box so the local buffer stays small — not for skipping it.
func (l *Log) Watch(ctx context.Context, every time.Duration, logf func(string, ...any)) {
	if l == nil || every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			st, err := l.Verify()
			switch {
			case err != nil:
				logf("audit: could not verify the chain: %v", err)
			case st != nil && st.Break != nil:
				logf("audit: CHAIN BROKEN at line %d (seq %d): %s — %d entries verify before it",
					st.Break.Line, st.Break.Seq, st.Break.Reason, st.Entries)
			}
		}
	}
}

// chainError renders a broken chain as an error for Health.
func (st *ChainState) chainError() error {
	if st == nil || st.Break == nil {
		return nil
	}
	return fmt.Errorf("audit chain broken at line %d (seq %d): %s",
		st.Break.Line, st.Break.Seq, st.Break.Reason)
}
