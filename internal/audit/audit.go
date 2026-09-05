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
	// TraceID and SpanID come from the caller's W3C trace context, when it sent
	// one. They are what joins this record to the caller's own traces: without
	// them the log is a system beside your observability rather than inside it.
	TraceID string `json:"trace_id,omitempty"`
	SpanID  string `json:"span_id,omitempty"`
	Team    string `json:"team,omitempty"`
	Subject string `json:"subject,omitempty"`
	Model   string `json:"model"`
	// Policy is the fingerprint of the configuration in force. Without it the
	// log says what happened but not what the rules were, and "was this allowed
	// under the policy at the time" is unanswerable.
	Policy  string `json:"policy,omitempty"`
	Backend string `json:"backend,omitempty"`

	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	// CacheWriteTokens and CacheReadTokens split the prompt by how the provider
	// billed it. They are omitted when zero, which is what lets a log written
	// before these fields existed still verify: an old entry decoded and
	// re-encoded produces the same bytes, because absent and zero are the same
	// thing on the wire.
	//
	// They are recorded rather than derived because they cannot be recovered
	// later. Rates change and can be reapplied to history; what the provider
	// said it served from cache at 09:14 on a Tuesday is observable once. An
	// append-only log that did not capture it has lost it permanently.
	CacheWriteTokens int    `json:"cache_write_tokens,omitempty"`
	CacheReadTokens  int    `json:"cache_read_tokens,omitempty"`
	StopReason       string `json:"stop_reason,omitempty"`
	Streamed         bool   `json:"streamed,omitempty"`
	Error            string `json:"error,omitempty"`

	// Redactions counts what was removed, by rule. It is recorded whether or
	// not content is — knowing that three email addresses crossed the boundary
	// is useful even when you deliberately kept none of them.
	Redactions map[string]int `json:"redactions,omitempty"`

	// ToolsOffered names the functions the caller made available on this
	// request. It is metadata, not content, and is recorded unconditionally:
	// what a model was *permitted* to do bounds what it could have done, and a
	// record of an agent's actions that omits its permissions cannot be read
	// afterwards. Names only — a schema is the caller's business.
	ToolsOffered []string `json:"tools_offered,omitempty"`
	// ToolCalls are the calls the model chose to make.
	//
	// These are the agent's actions, and they are the part a completion log
	// misses entirely: "asked X, replied Y" is not a record of a system that
	// then transferred funds. Names are always recorded; arguments follow the
	// same rule as prompts — present only where content logging was turned on,
	// and redacted before they get here.
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`

	// Prompt and Completion are present only when content logging is on, and
	// are redacted before they get here.
	Prompt     string `json:"prompt,omitempty"`
	Completion string `json:"completion,omitempty"`

	// MAC covers every field above, including Prev, which is what binds one
	// entry to the last. It is written last and excluded from its own input.
	MAC string `json:"mac"`
}

// ToolCall is one invocation the model asked for.
//
// Name and ID are metadata and are always kept. Arguments are content: a call
// to transfer_funds carries an account number, and a call to search_customer
// carries whatever the model decided to look up. They are redacted at the same
// chokepoint as prompts and dropped entirely when content logging is off.
type ToolCall struct {
	Name      string `json:"name"`
	ID        string `json:"id,omitempty"`
	Arguments string `json:"arguments,omitempty"`
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

	// Health of the last write. An audit log that has stopped working is the
	// one failure this system must not absorb quietly, so it is recorded
	// rather than only logged.
	failures uint64
	lastErr  error

	// archiveCmd ships a closed segment somewhere durable. A segment is pruned
	// only after it has run successfully.
	archiveCmd string
	archiveErr error

	// policy stamps every entry, so the rules in force are recorded alongside
	// what happened under them.
	policy string

	// observe receives redaction counts as they happen, so the aggregate view
	// can show what is being removed without anything reading the log.
	observe func(map[string]int)

	// chain is the last self-verification result. See watch.go.
	chain *ChainState
}

// Health reports whether writes are succeeding, and how many have failed since
// the last one that did.
//
// A log that quietly stopped recording is worse than one that was never
// configured: the first produces a gap nobody knows about, and the second at
// least produces no false confidence.
func (l *Log) Health() (failures uint64, err error) {
	if l == nil {
		return 0, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lastErr != nil {
		return l.failures, l.lastErr
	}
	// A broken chain outranks a stalled shipper: one is a lost copy, the other
	// is a record that no longer says what it said.
	if err := l.chain.chainError(); err != nil {
		return l.failures, err
	}
	// A shipper that has stopped working is not an outage yet — the segments
	// are still here — but it is the beginning of one, and it is silent unless
	// reported.
	return l.failures, l.archiveErr
}

// Rotation configures when a segment is closed and how long closed segments
// are kept. Zero values disable each independently.
type Rotation struct {
	MaxBytes  int64
	Retention time.Duration
	// ArchiveCommand runs for each closed segment with $SEGMENT set to its
	// path. A zero exit marks the segment archived and therefore prunable.
	ArchiveCommand string
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
		l.maxBytes, l.retention, l.archiveCmd = r.MaxBytes, r.Retention, r.ArchiveCommand
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

// WithObserver reports redaction counts as they happen.
func (l *Log) WithObserver(f func(map[string]int)) *Log {
	if l != nil {
		l.observe = f
	}
	return l
}

// WithPolicy stamps every entry with the fingerprint of the configuration that
// produced it.
func (l *Log) WithPolicy(fingerprint string) *Log {
	if l != nil {
		l.policy = fingerprint
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
	// Copy the calls before redacting: the caller handed us a slice it may
	// still be using, and rewriting arguments in place would edit the request
	// that produced them.
	calls := append([]ToolCall(nil), r.ToolCalls...)
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
		hits := append(h1, h2...)
		// Tool arguments go through the same redactor. A call is where the
		// structured identifiers actually live — an account number reaches the
		// log as an argument far more often than as prose.
		for i := range calls {
			args, c, h := l.red.ApplyDetailed(calls[i].Arguments)
			calls[i].Arguments = args
			for k, v := range c {
				counts[k] += v
			}
			hits = append(hits, h...)
		}
		// Values are sealed to a key this process cannot read. If sealing
		// fails, the entry is still written: losing the audit record because
		// recovery was unavailable would be the worse outcome.
		for _, h := range hits {
			if err := l.vault.Seal(h.Token, h.Rule, h.Value); err != nil {
				return fmt.Errorf("sealing %s: %w", h.Rule, err)
			}
		}
	}
	if len(counts) > 0 {
		r.Redactions = counts
		if l.observe != nil {
			l.observe(counts)
		}
	}

	if l.content {
		r.Prompt, r.Completion = prompt, completion
	} else {
		r.Prompt, r.Completion = "", ""
		// The names stay. That a model called transfer_funds is the fact worth
		// keeping; what it passed is the part that carries the customer.
		for i := range calls {
			calls[i].Arguments = ""
		}
	}
	r.ToolCalls = calls
	if r.Time.IsZero() {
		r.Time = time.Now().UTC()
	}
	if r.Policy == "" {
		r.Policy = l.policy
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
		l.fail(err)
		return err
	}
	line = append(line, '\n')
	if _, err := l.w.Write(line); err != nil {
		l.seq--
		l.fail(err)
		return err
	}
	l.failures, l.lastErr = 0, nil
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

// fail records a write failure. The caller holds the lock.
func (l *Log) fail(err error) {
	l.failures++
	l.lastErr = err
}

// SetWriterForTest replaces the underlying writer. It exists so a test can
// simulate a full disk, which is the failure this package most needs to handle
// and the one hardest to arrange honestly.
func (l *Log) SetWriterForTest(w io.WriteCloser) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.w, l.enc, l.path = w, newEncoder(w), ""
}
