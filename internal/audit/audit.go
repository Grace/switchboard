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
	"io"
	"os"
	"sync"
	"time"

	"github.com/Grace/switchboard/internal/redact"
)

// Record is one completion, as the log sees it.
type Record struct {
	Time    time.Time `json:"time"`
	ID      string    `json:"id"`
	Team    string    `json:"team,omitempty"`
	Model   string    `json:"model"`
	Backend string    `json:"backend,omitempty"`

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
}

// Log is an append-only JSONL audit log.
type Log struct {
	mu  sync.Mutex
	w   io.WriteCloser
	enc *json.Encoder

	red     *redact.Redactor
	content bool
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
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return newLog(f, red, content), nil
}

func newLog(w io.WriteCloser, red *redact.Redactor, content bool) *Log {
	return &Log{w: w, enc: json.NewEncoder(w), red: red, content: content}
}

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
		prompt, c1 = l.red.Apply(prompt)
		completion, c2 = l.red.Apply(completion)
		for k, v := range c1 {
			counts[k] += v
		}
		for k, v := range c2 {
			counts[k] += v
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
	return l.enc.Encode(r)
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
