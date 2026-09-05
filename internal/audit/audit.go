// Package audit records what was sent to which provider.
//
// A gateway earns its place in a regulated network by being able to answer
// "what left, when, on whose behalf" — which means writing it down. Writing it
// down is also the moment content stops being transient and starts being
// something with a retention policy, so this package will not record content
// unless a redactor is present to clean it first.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/Grace/switchboard/internal/redact"
	"github.com/Grace/switchboard/internal/vault"
)

// Record is one completion, as the log sees it.
//
// Seq, Prev and MAC are the chain. They come first so a reader sees the
// position of an entry before its contents, and they are what Verify walks.
type Record struct {
	Seq  uint64 `json:"seq"`
	Prev string `json:"prev,omitempty"`

	Time         time.Time `json:"time"`
	ID           string    `json:"id"`
	Conversation string    `json:"conversation,omitempty"`
	Team         string    `json:"team,omitempty"`
	Subject      string    `json:"subject,omitempty"`
	Model        string    `json:"model"`
	Backend      string    `json:"backend,omitempty"`

	PromptTokens     int    `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens"`
	StopReason       string `json:"stop_reason,omitempty"`
	Streamed         bool   `json:"streamed,omitempty"`
	Error            string `json:"error,omitempty"`

	// Redactions counts what was removed, by rule. It is recorded whether or
	// not content is — knowing that three email addresses crossed the boundary
	// is useful even when you deliberately kept none of them.
	Redactions map[string]int `json:"redactions,omitempty"`

	// Prompt and Completion are present only when content logging is on, and
	// are redacted before they get here.
	Prompt     string `json:"prompt,omitempty"`
	Completion string `json:"completion,omitempty"`

	// MAC covers every field above, including Prev, which is what binds one
	// entry to the last. It is written last and excluded from its own input.
	MAC string `json:"mac"`
}

// Log is an append-only, hash-chained JSONL audit log.
type Log struct {
	mu  sync.Mutex
	w   io.WriteCloser
	enc *json.Encoder

	red     *redact.Redactor
	content bool
	vault   *vault.Writer

	signer signer
	seq    uint64
	prev   string

	// Rotation state. path is empty for a Log writing somewhere that is not a
	// file, in which case rotation is a no-op.
	path      string
	bytes     int64
	maxBytes  int64
	retention time.Duration
}

// Rotation configures when a segment is closed and how long closed segments
// are kept. Zero values disable each independently.
type Rotation struct {
	MaxBytes  int64
	Retention time.Duration
}

// Open opens or creates the log at path.
//
// content requires a redactor. Content logging without one is refused here
// rather than defaulting to off, because the two are not the same thing: one is
// a configuration someone chose, the other is a surprise they discover during
// an incident review.
func Open(path string, red *redact.Redactor, content bool) (*Log, error) {
	if content && red == nil {
		return nil, errContentWithoutRedaction
	}
	// Recover the chain before opening for append, so a restart continues the
	// existing log rather than starting a second one inside the same file.
	seq, prev, err := tailState(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l := newLog(f, red, content)
	l.signer = newSigner(keyFromEnv())
	l.seq, l.prev = seq, prev
	l.path = path
	if info, err := f.Stat(); err == nil {
		l.bytes = info.Size()
	}
	return l, nil
}

// WithRotation closes a segment once it exceeds MaxBytes and deletes segments
// older than Retention. See rotate.go for why owning this matters.
func (l *Log) WithRotation(r Rotation) *Log {
	if l != nil {
		l.maxBytes, l.retention = r.MaxBytes, r.Retention
	}
	return l
}

func newEncoder(w io.Writer) *json.Encoder { return json.NewEncoder(w) }

func newLog(w io.WriteCloser, red *redact.Redactor, content bool) *Log {
	return &Log{w: w, enc: json.NewEncoder(w), red: red, content: content}
}

// WithVault seals redacted values to a key this process cannot read back, so an
// investigation can recover them out of band. See internal/vault.
func (l *Log) WithVault(w *vault.Writer) *Log {
	if l != nil {
		l.vault = w
	}
	return l
}

// Signed reports whether entries are being MACed with a key rather than only
// digested. Callers surface this at startup: "auditing" and "auditing in a way
// that survives someone editing the file" are different claims.
func (l *Log) Signed() bool { return l != nil && l.signer.keyed }

// Write redacts and appends one record.
//
// Redaction happens here, at the boundary, rather than at every call site. A
// caller cannot forget to redact, and cannot opt out — which is the difference
// between a control and a convention.
func (l *Log) Write(r Record) error {
	if l == nil {
		return nil
	}
	prompt, completion := r.Prompt, r.Completion
	counts := map[string]int{}

	if l.red != nil {
		var c1, c2 map[string]int
		var h1, h2 []redact.Hit
		prompt, c1, h1 = l.red.ApplyDetailed(prompt)
		completion, c2, h2 = l.red.ApplyDetailed(completion)
		for k, v := range c1 {
			counts[k] += v
		}
		for k, v := range c2 {
			counts[k] += v
		}
		// Values are sealed to a key this process cannot read. If sealing
		// fails, the entry is still written: losing the audit record because
		// recovery was unavailable would be the worse outcome.
		for _, h := range append(h1, h2...) {
			if err := l.vault.Seal(h.Token, h.Rule, h.Value); err != nil {
				return fmt.Errorf("sealing %s: %w", h.Rule, err)
			}
		}
	}
	if len(counts) > 0 {
		r.Redactions = counts
	}

	if l.content {
		r.Prompt, r.Completion = prompt, completion
	} else {
		r.Prompt, r.Completion = "", ""
	}
	if r.Time.IsZero() {
		r.Time = time.Now().UTC()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	signed, err := l.signer.sign(r, l.seq, l.prev)
	if err != nil {
		l.seq--
		return err
	}
	line, err := json.Marshal(signed)
	if err != nil {
		l.seq--
		return err
	}
	line = append(line, '\n')
	if _, err := l.w.Write(line); err != nil {
		l.seq--
		return err
	}
	l.prev = signed.MAC
	l.bytes += int64(len(line))

	// Rotate after writing, so an entry is never split across segments.
	if l.maxBytes > 0 && l.bytes >= l.maxBytes {
		if err := l.rotate(); err != nil {
			return fmt.Errorf("rotating the audit log: %w", err)
		}
	}
	return nil
}

// Close closes the underlying file.
func (l *Log) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Close()
}

type contentError struct{}

func (contentError) Error() string {
	return "audit.log_content is set but no redaction rules are configured: " +
		"refusing to write raw prompts and completions to disk"
}

var errContentWithoutRedaction = contentError{}
