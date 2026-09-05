package audit

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Rotation exists for a reason more specific than "files get big".
//
// The chain assumes append-only. The ordinary operational response to a file
// that grows forever is logrotate, which truncates or renames underneath a
// running process — and that silently severs the chain, so verification starts
// failing for a reason nobody connects to the cron job that caused it. Owning
// rotation is how the chain survives it.
//
// A segment continues the chain rather than starting a new one: the first entry
// of a new segment carries the sequence and digest that follow the last entry of
// the previous. Verification walks the segments in order and sees one history.

// segmentSuffix is the timestamp appended when a segment is closed.
//
// Fixed-width and nanosecond-precision, so sorting these lexically sorts them
// chronologically — which is what makes reading segments in order correct
// rather than lucky — and so two rotations in the same second do not collide.
// An earlier version used second precision and walked forward a second at a
// time on collision, which turned a burst of rotations into seconds of stalled
// writes.
const segmentSuffix = "20060102T150405.000000000Z"

// segmentPath renames base to a closed segment: audit.jsonl becomes
// audit-20260904T212600Z.jsonl.
func segmentPath(base string, at time.Time) string {
	dir, file := filepath.Split(base)
	ext := filepath.Ext(file)
	stem := strings.TrimSuffix(file, ext)
	return filepath.Join(dir, stem+"-"+at.UTC().Format(segmentSuffix)+ext)
}

// archivedSuffix marks a segment that has been copied somewhere durable and is
// therefore safe to delete locally. It is a rename rather than a sidecar file
// or in-memory state so it survives a restart and is obvious on disk.
const archivedSuffix = ".archived"

// Segments lists every file belonging to one log, oldest first, with the
// active file last.
func Segments(base string) ([]string, error) {
	dir, file := filepath.Split(base)
	if dir == "" {
		dir = "."
	}
	ext := filepath.Ext(file)
	stem := strings.TrimSuffix(file, ext)

	matches, err := filepath.Glob(filepath.Join(dir, stem+"-*"+ext))
	if err != nil {
		return nil, err
	}
	archived, err := filepath.Glob(filepath.Join(dir, stem+"-*"+ext+archivedSuffix))
	if err != nil {
		return nil, err
	}
	matches = append(matches, archived...)
	// Sort on the timestamp, so an archived segment keeps its place in history
	// rather than sorting after every unarchived one.
	sort.Slice(matches, func(i, j int) bool {
		return strings.TrimSuffix(matches[i], archivedSuffix) <
			strings.TrimSuffix(matches[j], archivedSuffix)
	})

	if _, err := os.Stat(base); err == nil {
		matches = append(matches, base)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return matches, nil
}

// rotate closes the active file, renames it to a timestamped segment, and opens
// a fresh one. The caller holds the lock.
func (l *Log) rotate() error {
	if l.path == "" {
		return nil
	}
	if err := l.w.Close(); err != nil {
		return err
	}

	// Nanosecond names make collision effectively impossible, but never
	// overwrite a segment if one somehow occurs: losing a segment is losing
	// history, and the chain would report it as tampering forever after.
	seg := segmentPath(l.path, time.Now())
	for i := 1; i < 1000; i++ {
		if _, err := os.Stat(seg); os.IsNotExist(err) {
			break
		}
		seg = segmentPath(l.path, time.Now().Add(time.Duration(i)))
	}
	if err := os.Rename(l.path, seg); err != nil {
		return err
	}

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	l.w, l.enc, l.bytes = f, newEncoder(f), 0

	// Sequence and digest carry over, so the new segment continues the chain
	// rather than beginning a second one beside it.
	l.archive(seg)
	return l.prune()
}

// archive hands a closed segment to whatever ships it somewhere durable, and
// marks it only if that succeeded.
//
// The gateway's disk is a buffer, not an archive. Retention alone forces a
// choice between running out of space and deleting evidence; copying segments
// off the box removes the choice, and this is the hook that does it — a command
// rather than an integration, so it works with S3, rsync, a SIEM shipper or
// anything else already in place.
func (l *Log) archive(seg string) {
	if l.archiveCmd == "" {
		return
	}
	// Archiving must never block a completion, and a slow or wedged shipper
	// must not become a slow gateway.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), archiveTimeout)
		defer cancel()

		cmd := exec.CommandContext(ctx, "sh", "-c", l.archiveCmd)
		cmd.Env = append(os.Environ(), "SEGMENT="+seg)
		out, err := cmd.CombinedOutput()
		if err != nil {
			l.mu.Lock()
			l.archiveErr = fmt.Errorf("archiving %s: %w: %s", filepath.Base(seg), err,
				strings.TrimSpace(string(out)))
			l.mu.Unlock()
			return
		}
		if err := os.Rename(seg, seg+archivedSuffix); err != nil {
			l.mu.Lock()
			l.archiveErr = err
			l.mu.Unlock()
			return
		}
		l.mu.Lock()
		l.archiveErr = nil
		l.mu.Unlock()
	}()
}

const archiveTimeout = 10 * time.Minute

// prune deletes segments older than the retention period.
//
// Retention is a floor someone else sets: EU AI Act Article 26 asks deployers to
// keep logs at least six months, and other regimes ask for longer. switchboard
// does not know which applies, so it deletes only what it was told to and warns
// when the configured period is shorter than that six months.
func (l *Log) prune() error {
	if l.retention <= 0 {
		return nil
	}
	segs, err := Segments(l.path)
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-l.retention)

	for _, s := range segs {
		if s == l.path {
			continue // never the active file
		}
		// The invariant: a segment that has not been copied somewhere durable
		// is not deleted, however old it is. Retention bounds the buffer, and
		// deleting an unarchived segment would bound the evidence instead.
		if l.archiveCmd != "" && !strings.HasSuffix(s, archivedSuffix) {
			continue
		}
		info, err := os.Stat(s)
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(s); err != nil {
				return fmt.Errorf("pruning %s: %w", s, err)
			}
		}
	}
	return nil
}

// VerifyAll walks every segment of a log as one chain.
//
// Segments are read oldest first, and the sequence and digest must run
// continuously across the boundaries — which is what proves a segment was not
// removed from the middle.
func VerifyAll(base string, key []byte) (*Report, error) {
	segs, err := Segments(base)
	if err != nil {
		return nil, err
	}
	if len(segs) == 0 {
		return nil, fmt.Errorf("no log at %s", base)
	}

	readers := make([]io.Reader, 0, len(segs))
	files := make([]*os.File, 0, len(segs))
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	for _, s := range segs {
		f, err := os.Open(s)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
		readers = append(readers, f)
	}

	rep, err := verify(io.MultiReader(readers...), key)
	if rep != nil {
		rep.Segments = len(segs)
	}
	return rep, err
}
