package viewer

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/redact"
)

// testPrices is a rate card for the demo log's one model. It is invented for
// the test and says so — switchboard ships no price list, so a test that wants
// money has to declare what it costs, exactly as a deployment does.
var testPrices = Prices{Currency: "USD", Model: map[string]Price{
	"claude-opus": {InPerMTok: 15, OutPerMTok: 75},
}}

func demoLog(t *testing.T, withContent bool) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	t.Setenv("SWITCHBOARD_AUDIT_KEY", "k")

	red, err := redact.New([]string{"email"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := audit.Open(path, red, withContent)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		policy := "aaaaaaaaaaaa"
		if i >= 12 {
			policy = "bbbbbbbbbbbb"
		}
		team, subject := "search", "dana@corp"
		if i%3 == 0 {
			team, subject = "billing", "lee@corp"
		}
		rec := audit.Record{
			Time: base.Add(time.Duration(i) * time.Hour), ID: "c", Policy: policy,
			Team: team, Subject: subject, Model: "claude-opus", Backend: "bedrock",
			PromptTokens: 100, CompletionTokens: 10,
			Prompt: "mail grace@example.com", StopReason: "end_turn",
		}
		if i == 5 {
			rec.Error = "upstream exploded"
		}
		if err := l.Write(rec); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	return path
}

func TestSummariseCountsWhatThePageShows(t *testing.T) {
	path := demoLog(t, false)
	s, err := Summarise(path, []byte("k"), Query{}, testPrices)
	if err != nil {
		t.Fatal(err)
	}
	if s.Entries != 20 {
		t.Errorf("entries = %d", s.Entries)
	}
	if !s.Verified() {
		t.Error("a freshly written log should verify")
	}
	if s.Errors != 1 {
		t.Errorf("errors = %d, want 1", s.Errors)
	}
	if s.TotalPromptTokens != 2000 || s.TotalReplyTokens != 200 {
		t.Errorf("tokens = %d/%d", s.TotalPromptTokens, s.TotalReplyTokens)
	}
	if len(s.Teams) != 2 {
		t.Fatalf("teams = %+v", s.Teams)
	}
	// Ordered by spend, and shares should account for everything.
	if s.Teams[0].PromptTokens < s.Teams[1].PromptTokens {
		t.Error("teams should be ordered by spend")
	}
	var share int
	for _, tm := range s.Teams {
		share += tm.ShareOfTokensPercent
	}
	if share < 98 || share > 100 {
		t.Errorf("shares sum to %d%%", share)
	}
}

// The panel no time-series tool has: the rules changed here.
func TestPolicyChangesAppearAsSeparateWindows(t *testing.T) {
	s, err := Summarise(demoLog(t, false), []byte("k"), Query{}, testPrices)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Policies) != 2 {
		t.Fatalf("policies = %+v, want two windows", s.Policies)
	}
	if s.Policies[0].Entries != 12 || s.Policies[1].Entries != 8 {
		t.Errorf("entries per policy = %d, %d", s.Policies[0].Entries, s.Policies[1].Entries)
	}
	if !s.Policies[0].To.Before(s.Policies[1].From) {
		t.Error("policy windows should not overlap")
	}
}

// Distinct people are only knowable where callers presented an identity.
func TestSubjectsAreCountedDistinctly(t *testing.T) {
	s, _ := Summarise(demoLog(t, false), []byte("k"), Query{}, testPrices)
	for _, tm := range s.Teams {
		if tm.Subjects != 1 {
			t.Errorf("team %s: subjects = %d, want 1", tm.Team, tm.Subjects)
		}
	}
}

// A page reporting spend from a log that does not verify would be reporting
// numbers nobody should trust, so the break has to reach the summary.
func TestABrokenChainIsSurfaced(t *testing.T) {
	path := demoLog(t, false)
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	lines[3] = strings.Replace(lines[3], `"model":"claude-opus"`, `"model":"something-else"`, 1)
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)

	s, err := Summarise(path, []byte("k"), Query{}, testPrices)
	if err != nil {
		t.Fatal(err)
	}
	if s.Verified() {
		t.Fatal("an edited log must not report as verified")
	}
	if s.Chain == nil || s.Chain.Break == nil {
		t.Fatal("the break should be on the summary")
	}
}

// Redaction counts belong on the page; values never do.
func TestPageShowsCountsAndNeverValues(t *testing.T) {
	path := demoLog(t, true)
	srv, ln, err := Serve("127.0.0.1:0", path, []byte("k"), testPrices, false)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	resp, err := http.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	if strings.Contains(html, "grace@example.com") {
		t.Error("a redacted address reached the page")
	}
	for _, want := range []string{"chain intact", "Spend by team", "Policy in force", "email", "proof of concept"} {
		if !strings.Contains(html, want) {
			t.Errorf("page missing %q", want)
		}
	}
	// Self-contained: nothing to fetch, which matters on an air-gapped host.
	for _, forbidden := range []string{"http://cdn", "https://cdn", "<script"} {
		if strings.Contains(html, forbidden) {
			t.Errorf("page pulls in %q", forbidden)
		}
	}
}

// This page has no authentication, so it must not be bound anywhere by accident.
func TestNonLoopbackIsRefusedUnlessDemanded(t *testing.T) {
	path := demoLog(t, false)
	for _, addr := range []string{"0.0.0.0:11436", "10.0.0.5:11436"} {
		if _, _, err := Serve(addr, path, nil, testPrices, false); err == nil {
			t.Errorf("%s should be refused without -allow-remote", addr)
		}
	}
	if _, ln, err := Serve("127.0.0.1:0", path, nil, testPrices, false); err != nil {
		t.Errorf("loopback should be allowed: %v", err)
	} else {
		ln.Close()
	}
}

func TestReadOnly(t *testing.T) {
	path := demoLog(t, false)
	srv, ln, err := Serve("127.0.0.1:0", path, []byte("k"), testPrices, false)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	before, _ := os.ReadFile(path)
	resp, err := http.Post("http://"+ln.Addr().String()+"/", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Error("POST should not be served")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("the log changed; this must never write")
	}
}

// A file has no server. Any element that looks clickable and does nothing is
// worse than one that never looked clickable, and an auditor clicking through
// an evidence package is exactly who would find out.
func TestStaticFileHasNothingThatNavigates(t *testing.T) {
	log := demoLog(t, true)
	out := t.TempDir() + "/report.html"
	if _, err := WriteFile(out, log, nil, Prices{}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(body, []byte(`href="?`)); n != 0 {
		t.Errorf("%d filter links survive in the static file", n)
	}
	// And it must stay self-contained: no script, no remote reference.
	for _, bad := range []string{"<script", "http://", "https://"} {
		if bytes.Contains(bytes.ToLower(body), []byte(bad)) {
			t.Errorf("static report contains %q", bad)
		}
	}
}
