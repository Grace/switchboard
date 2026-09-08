package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newCapture(t *testing.T, ttl time.Duration, limit int64) (*captureStore, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "capture")
	s, err := NewCaptureStore(dir, ttl, limit, &Metrics{})
	if err != nil {
		t.Fatalf("NewCaptureStore: %v", err)
	}
	return s, dir
}

func record(id string) *captureRecord {
	return &captureRecord{
		RequestID: id, Status: 200, Stored: time.Now().Unix(),
		Prompt:     json.RawMessage(`{"messages":[{"role":"user","content":"hello"}]}`),
		Completion: json.RawMessage(`{"choices":[{"message":{"content":"hi"}}]}`),
	}
}

// The claim a deployment relies on without checking. Capture is the only thing
// in this gateway that writes a prompt to a disk, so "off unless you asked" has
// to be true of the filesystem, not just of the write path: no store, no
// directory, nothing to find later.
func TestCaptureIsOffByDefault(t *testing.T) {
	var c Config
	if c.CaptureTTLSeconds != 0 {
		t.Fatalf("zero-value config has capture_ttl_seconds = %d, want 0", c.CaptureTTLSeconds)
	}

	dir := t.TempDir()
	srv := &Server{C: Config{DataDir: dir}, Metrics: &Metrics{}}
	if srv.Capture != nil {
		t.Error("a Server built without a capture store has one anyway")
	}
	if _, err := os.Stat(filepath.Join(dir, "capture")); !os.IsNotExist(err) {
		t.Errorf("capture directory exists with capture disabled: %v", err)
	}
}

// Round trip, and the fields that make a record worth keeping: without the
// policy version a capture says what was asked and answered but not why it went
// where it did, which is half the question.
func TestCaptureRoundTrip(t *testing.T) {
	s, dir := newCapture(t, time.Hour, 1<<20)
	id := "0123456789abcdef0123456789abcdef"
	in := record(id)
	in.PolicyVersion, in.Provider, in.Model, in.Attempts, in.Fault =
		7, "anthropic", "claude-haiku-4-5-20251001", 2, faultRateLimit.String()
	if err := s.Write(in); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := s.Read(id)
	if got == nil {
		t.Fatal("Read returned nil for a record just written")
	}
	if got.PolicyVersion != 7 || got.Provider != "anthropic" || got.Attempts != 2 {
		t.Errorf("routing context lost: %+v", got)
	}
	if got.Fault != "rate_limit" {
		t.Errorf("fault = %q, want rate_limit", got.Fault)
	}
	if !strings.Contains(string(got.Prompt), "hello") ||
		!strings.Contains(string(got.Completion), "hi") {
		t.Errorf("content lost: prompt=%s completion=%s", got.Prompt, got.Completion)
	}

	// Prompts on a disk are the reason this feature needed a decision. The mode
	// is part of the deal.
	fi, err := os.Stat(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("record mode = %v, want 0600", fi.Mode().Perm())
	}
}

// A TTL on a store nothing reads is a statement about data at rest, not about
// queries. If expiry were only enforced on read, a capture nobody looked at
// would live forever, which is the opposite of what an operator agreed to.
func TestCaptureExpiryIsEnforcedOnDiskNotOnlyOnRead(t *testing.T) {
	s, dir := newCapture(t, 50*time.Millisecond, 1<<20)
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := s.Write(record(id)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	time.Sleep(80 * time.Millisecond)

	if got := s.Read(id); got != nil {
		t.Error("Read returned an expired record")
	}
	s.Sweep()
	if _, err := os.Stat(filepath.Join(dir, id+".json")); !os.IsNotExist(err) {
		t.Errorf("expired record still on disk after Sweep: %v", err)
	}
}

// A restart is also a compaction: the store recovers its byte count from disk
// and drops anything already expired, so an operator who stops a gateway for a
// week does not restart it holding a week-old prompt.
func TestCaptureRestartDropsExpiredRecords(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "capture")
	first, err := NewCaptureStore(dir, 50*time.Millisecond, 1<<20, &Metrics{})
	if err != nil {
		t.Fatal(err)
	}
	id := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := first.Write(record(id)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)

	second, err := NewCaptureStore(dir, 50*time.Millisecond, 1<<20, &Metrics{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, id+".json")); !os.IsNotExist(err) {
		t.Error("restart kept a record that was already expired")
	}
	if second.used != 0 || second.count != 0 {
		t.Errorf("restart accounting = %d bytes / %d records, want 0/0", second.used, second.count)
	}
}

// Refusing beats truncating. A half-written prompt reads as a complete one, and
// a replay built on it is confidently wrong -- worse than a replay that is
// plainly absent.
func TestCaptureRefusesRatherThanTruncates(t *testing.T) {
	s, dir := newCapture(t, time.Hour, 1<<30)
	id := "cccccccccccccccccccccccccccccccc"
	huge := record(id)
	huge.Prompt = json.RawMessage(`"` + strings.Repeat("x", captureRecordLimit+1) + `"`)

	m := &Metrics{}
	s.m = m
	if err := s.Write(huge); err == nil {
		t.Fatal("an oversized record was accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, id+".json")); !os.IsNotExist(err) {
		t.Error("a refused record left a partial file behind")
	}
	if m.DiskErrors.Load() == 0 {
		t.Error("a refused record did not increment telemetry_disk_errors_total")
	}
}

// Full means full, and it means refusing new writes rather than evicting old
// ones. Evicting would delete the oldest evidence at exactly the moment the most
// is being produced, which is the wrong instinct for a store that exists to
// answer questions about the past.
func TestCaptureStoreFullRefusesInsteadOfEvicting(t *testing.T) {
	s, _ := newCapture(t, time.Hour, 400)
	first := "dddddddddddddddddddddddddddddddd"
	if err := s.Write(record(first)); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := s.Write(record("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")); err == nil {
		t.Fatal("the store accepted a write past its limit")
	}
	if s.Read(first) == nil {
		t.Error("the earlier record was evicted to make room; it should have been kept")
	}
}

// The record id names a file. It is generated by the gateway rather than
// supplied by a caller, so this cannot currently be reached -- which is exactly
// why it is worth pinning, since the day it becomes reachable is the day nobody
// remembers it was not checked.
func TestCaptureRejectsIdsThatAreNotRequestIds(t *testing.T) {
	s, _ := newCapture(t, time.Hour, 1<<20)
	for _, bad := range []string{
		"../../etc/passwd",
		"0123456789abcdef0123456789abcde",   // 31
		"0123456789abcdef0123456789abcdeff", // 33
		"0123456789ABCDEF0123456789abcdef",  // uppercase
		"",
	} {
		r := record(bad)
		if err := s.Write(r); err == nil {
			t.Errorf("Write accepted id %q", bad)
		}
		if s.Read(bad) != nil {
			t.Errorf("Read accepted id %q", bad)
		}
	}
}

// Capture is an operator convenience; telemetry and the response are the
// product. A capture store that cannot write must not cost a caller their
// answer, so the write is best effort and happens after the event is emitted.
func TestCaptureFailureDoesNotAffectTheResponse(t *testing.T) {
	s, dir := newCapture(t, time.Hour, 1<<20)
	// Make writes fail for a reason the store cannot anticipate.
	if err := os.Chmod(dir, 0500); err != nil {
		t.Skipf("cannot make the directory read-only: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })

	srv := &Server{C: Config{}, Metrics: &Metrics{}, Capture: s}
	rec := httptest.NewRecorder()
	// A request that fails auth never reaches a provider, and still exercises the
	// deferred capture write on the way out.
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`))
	srv.chat(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; a failing capture store changed the response",
			rec.Code)
	}
}
