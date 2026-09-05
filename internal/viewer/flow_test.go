package viewer

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/redact"
)

func rec(team, subject, model, backend, id string, in, out int) audit.Record {
	return audit.Record{
		Time: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
		ID:   id, Team: team, Subject: subject, Model: model, Backend: backend,
		PromptTokens: in, CompletionTokens: out, StopReason: "end_turn",
	}
}

// The diagram's whole claim is that a ribbon is a path. If the widths between
// two columns do not add up to the same total as every other pair, the picture
// is asserting something the log does not say.
func TestRibbonsConserveTokensBetweenEveryColumn(t *testing.T) {
	f := BuildFlow([]audit.Record{
		rec("search", "dana", "claude-opus", "bedrock", "a", 100, 10),
		rec("search", "lee", "qwen3-8b", "local", "b", 40, 5),
		rec("billing", "kim", "claude-opus", "bedrock", "c", 200, 20),
	}, Query{}, testPrices)

	total := 100 + 10 + 40 + 5 + 200 + 20
	for layer := 0; layer < layerCount-1; layer++ {
		sum := 0
		for _, l := range f.Links {
			if l.From.Layer == layer {
				sum += l.Tokens
			}
		}
		if sum != total {
			t.Errorf("between %s and %s the ribbons carry %d tokens, want %d",
				LayerNames[layer], LayerNames[layer+1], sum, total)
		}
	}
}

// Provider identity is the reason the ribbons are split. If it were lost at the
// first join, a person's row could not tell you which provider saw their
// prompts — only that one did.
func TestProviderColourReachesTheRequestColumn(t *testing.T) {
	f := BuildFlow([]audit.Record{
		rec("search", "dana", "claude-opus", "bedrock", "a", 100, 10),
		rec("search", "dana", "qwen3-8b", "local", "b", 100, 10),
	}, Query{}, testPrices)

	slots := map[string]int{}
	for _, l := range f.Links {
		if l.To.Layer == LayerRequest {
			slots[l.Provider] = l.Slot
		}
	}
	if len(slots) != 2 {
		t.Fatalf("requests reached by providers %v, want both", slots)
	}
	if slots["bedrock"] == slots["local"] {
		t.Error("two providers share a colour slot")
	}
	// One person, two providers: the person column must be a join, not a split.
	people := 0
	for _, n := range f.Nodes {
		if n.Layer == LayerSubject {
			people++
		}
	}
	if people != 1 {
		t.Errorf("person column has %d boxes, want 1", people)
	}
}

// A long tail is the interesting shape, not noise — but it cannot be drawn as
// hundreds of slivers. Folding it must not change what the diagram sums to.
func TestFoldingATailKeepsTheArithmetic(t *testing.T) {
	var recs []audit.Record
	total := 0
	for i := 0; i < 60; i++ {
		recs = append(recs, rec("search", fmt.Sprintf("p%d", i), "claude-opus", "bedrock",
			fmt.Sprintf("id%d", i), 10+i, 1))
		total += 10 + i + 1
	}
	f := BuildFlow(recs, Query{}, testPrices)

	for layer := 0; layer < layerCount; layer++ {
		n, sum, folds := 0, 0, 0
		for _, node := range f.Nodes {
			if node.Layer != layer {
				continue
			}
			n++
			sum += node.Tokens
			if node.Fold {
				folds++
			}
		}
		if n > perLayerCap[layer] {
			t.Errorf("%s column has %d boxes, cap is %d", LayerNames[layer], n, perLayerCap[layer])
		}
		if sum != total {
			t.Errorf("%s column sums to %d tokens, want %d", LayerNames[layer], sum, total)
		}
		if layer == LayerSubject && folds != 1 {
			t.Errorf("person column has %d fold boxes, want exactly 1", folds)
		}
	}
	// A fold is not a thing you can ask a question about, so it is not a link.
	for _, node := range f.Nodes {
		if node.Fold && node.Href != "" {
			t.Error("a folded box should not be clickable")
		}
	}
}

// Labels that overlap are unreadable at exactly the moment a long tail matters.
func TestLabelsAreNeverStackedOnTopOfEachOther(t *testing.T) {
	var recs []audit.Record
	// One caller dwarfing the rest is the shape that collapses a column's
	// boxes to slivers, which is where labels collide.
	recs = append(recs, rec("search", "whale", "claude-opus", "bedrock", "big", 500000, 1))
	for i := 0; i < 11; i++ {
		recs = append(recs, rec("search", fmt.Sprintf("p%d", i), "claude-opus", "bedrock",
			fmt.Sprintf("id%d", i), 1, 1))
	}
	f := BuildFlow(recs, Query{}, testPrices)

	byLayer := map[int][]*FlowNode{}
	for _, n := range f.Nodes {
		byLayer[n.Layer] = append(byLayer[n.Layer], n)
	}
	for layer, col := range byLayer {
		for i := 1; i < len(col); i++ {
			if gap := col[i].LabelY - col[i-1].LabelY; gap < labelPitch-0.01 {
				t.Errorf("%s column: labels %.1fpx apart, want >= %.0f",
					LayerNames[layer], gap, labelPitch)
			}
		}
		for _, n := range col {
			if n.LabelY < 0 || n.LabelY > f.Height {
				t.Errorf("%s column: label at y=%.1f is outside the diagram (height %.0f)",
					LayerNames[layer], n.LabelY, f.Height)
			}
		}
	}
}

// Nothing recorded a token count means every request failed before usage came
// back. Drawing that by request count says more than drawing nothing.
func TestASliceWithNoTokensIsDrawnByRequestCount(t *testing.T) {
	r := rec("search", "dana", "claude-opus", "bedrock", "a", 0, 0)
	r.Error = "upstream exploded"
	f := BuildFlow([]audit.Record{r, r}, Query{}, testPrices)
	if !f.ByRequests {
		t.Fatal("a token-less slice should fall back to request counts")
	}
	if f.Empty() {
		t.Fatal("nothing was drawn")
	}
	if f.Weighted() != "requests" {
		t.Errorf("caption says %q", f.Weighted())
	}
}

// Clicking a box that is already the filter has to let go of it, or the
// diagram becomes a place you can navigate into and not out of.
func TestClickingTheActiveBoxClearsIt(t *testing.T) {
	q := Query{Team: "search"}
	f := BuildFlow([]audit.Record{
		rec("search", "dana", "claude-opus", "bedrock", "a", 10, 1),
	}, q, testPrices)

	for _, n := range f.Nodes {
		if n.Layer != LayerTeam {
			continue
		}
		got := ParseQuery(mustParse(t, n.Href))
		if got.Team != "" {
			t.Errorf("clicking the active team gave %q, want it cleared", got.Team)
		}
	}
}

func mustParse(t *testing.T, href string) url.Values {
	t.Helper()
	u, err := url.Parse(href)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

// A request with nothing recorded about who made it is a request nobody is
// accountable for, and the page has to be able to ask for exactly those.
func TestUnattributedIsAValueYouCanFilterTo(t *testing.T) {
	recs := []audit.Record{
		rec("search", "dana", "claude-opus", "bedrock", "a", 10, 1),
		rec("", "", "claude-opus", "bedrock", "b", 20, 2),
	}
	q := Query{Team: unattributed}
	matched := 0
	for _, r := range recs {
		if q.Match(r) {
			matched++
		}
	}
	if matched != 1 {
		t.Fatalf("matched %d records, want the one with no team", matched)
	}
	f := BuildFlow([]audit.Record{recs[1]}, q, testPrices)
	if f.Records != 1 {
		t.Errorf("flow has %d records", f.Records)
	}
}

// A missing rate is not a rate of zero, and the difference is what stops a
// total from quietly understating.
func TestAnUnpricedModelIsReportedAsUnpricedNotFree(t *testing.T) {
	if _, ok := testPrices.Cost("no-such-model", Tokens{Input: 1000, Output: 1000}); ok {
		t.Fatal("an unknown model should not report a rate")
	}
	got, ok := testPrices.Cost("claude-opus", Tokens{Input: 1_000_000, Output: 1_000_000})
	if !ok {
		t.Fatal("a configured model should price")
	}
	if math.Abs(got-90) > 1e-9 {
		t.Errorf("cost = %v, want 90 (15 in + 75 out per Mtok)", got)
	}
}

// Sub-cent spend is most of what a token log holds. Rounding it to two places
// turns real rows into "$0.00", which reads as free.
func TestSmallAmountsAreNotRoundedIntoNothing(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"0", "$0"},
		{"0.0000123", "$0.00001"},
		{"0.4213", "$0.4213"},
		{"12.5", "$12.50"},
	} {
		var v float64
		fmt.Sscan(c.in, &v)
		if got := money(v, "USD"); got != c.want {
			t.Errorf("money(%s) = %s, want %s", c.in, got, c.want)
		}
	}
	if got := money(1.5, "EUR"); got != "EUR 1.50" {
		t.Errorf("non-dollar currency: %s", got)
	}
}

// The end-to-end claim: a filtered URL is a question, and the page answers that
// question rather than the unfiltered one.
func TestAFilteredPageShowsOneSliceAndSaysSo(t *testing.T) {
	path := demoLog(t, true)
	srv, ln, err := Serve("127.0.0.1:0", path, []byte("k"), testPrices, false)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	body := get(t, "http://"+ln.Addr().String()+"/?team=billing")
	if !strings.Contains(body, "7 of 20 entries") {
		t.Errorf("page does not say how much of the log it is showing")
	}
	if strings.Contains(body, ">search<") {
		t.Error("a filtered page still shows the excluded team")
	}
	// The diagram is server-rendered and stays that way.
	if !strings.Contains(body, "<svg class=\"flow\"") {
		t.Error("no diagram on the page")
	}
	for _, forbidden := range []string{"<script", "http://cdn", "https://"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("page reaches outside itself: %q", forbidden)
		}
	}
	// Money only where a rate was declared.
	if !strings.Contains(body, "$") {
		t.Error("a priced page should show cost")
	}
}

// Naming one request is the path view: five columns collapse to one line.
func TestNamingOneRequestShowsItsPath(t *testing.T) {
	path := demoLog(t, true)
	srv, ln, err := Serve("127.0.0.1:0", path, []byte("k"), testPrices, false)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	body := get(t, "http://"+ln.Addr().String()+"/?id=c")
	if !strings.Contains(body, "This request") {
		t.Fatal("no detail card for a named request")
	}
	for _, want := range []string{"bedrock", "claude-opus", "end_turn"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail card missing %q", want)
		}
	}
	// Redaction still holds on the path view, which is where content shows.
	if strings.Contains(body, "grace@example.com") {
		t.Error("a redacted address reached the detail card")
	}
}

// The file form is what gets attached to the incident, so it has to be the
// whole page and reach nothing.
func TestWriteFileIsSelfContained(t *testing.T) {
	path := demoLog(t, false)
	out := t.TempDir() + "/page.html"
	n, err := WriteFile(out, path, []byte("k"), testPrices)
	if err != nil {
		t.Fatal(err)
	}
	if n < 2000 {
		t.Fatalf("wrote %d bytes, that is not a page", n)
	}
	data, err := readFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"chain intact", "<svg class=\"flow\"", "Spend by team"} {
		if !strings.Contains(data, want) {
			t.Errorf("file missing %q", want)
		}
	}
	if strings.Contains(data, "<script") {
		t.Error("the file carries script")
	}
}

func readFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	return string(b), err
}

func get(t *testing.T, u string) string {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// Cached traffic is the case where a page can be confidently wrong, so it has
// to price correctly, show the split, and refuse when it cannot.
func TestCachedTrafficIsPricedAndShownSeparately(t *testing.T) {
	read, write := 1.5, 18.75
	prices := Prices{Currency: "USD", Model: map[string]Price{
		"claude-opus": {InPerMTok: 15, OutPerMTok: 75, CacheReadPer: &read, CacheWrite: &write},
		"claude-thin": {InPerMTok: 15, OutPerMTok: 75}, // no cache rates
	}}

	r := rec("search", "dana", "claude-opus", "bedrock", "cached", 3, 8)
	r.CacheReadTokens = 187_361
	cost, ok := prices.Cost(r.Model, tokensOf(r))
	if !ok {
		t.Fatal("cached traffic with cache rates should price")
	}
	want := 3*15/1e6 + 8*75/1e6 + 187_361*read/1e6
	if diff := cost - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("cost = %v, want %v", cost, want)
	}
	// The naive figure is the bug being prevented; keep the test honest about
	// how big the error is.
	naive := float64(tokensOf(r).Prompt())*15/1e6 + 8*75/1e6
	if naive/cost < 8 {
		t.Errorf("naive/correct = %.1fx; this no longer demonstrates the problem", naive/cost)
	}

	// A model with no cache rate must not guess.
	thin := r
	thin.Model = "claude-thin"
	if _, ok := prices.Cost(thin.Model, tokensOf(thin)); ok {
		t.Error("cached tokens with no cache rate should read as unpriced")
	}

	// And the width of the ribbon counts them: cheaper is not smaller.
	f := BuildFlow([]audit.Record{r}, Query{}, prices)
	for _, n := range f.Nodes {
		if n.Layer == LayerProvider && n.Tokens != 3+8+187_361 {
			t.Errorf("provider node has %d tokens, want the full consumption", n.Tokens)
		}
	}
}

// The page has to say what was cache traffic, or a reader cannot tell why one
// team's cost is a tenth of another's at the same token count.
func TestThePageShowsTheCacheSplit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv("SWITCHBOARD_AUDIT_KEY", "k")
	l, err := audit.Open(path, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	r := rec("search", "dana", "claude-opus", "bedrock", "cached", 3, 8)
	r.CacheReadTokens, r.CacheWriteTokens = 187_361, 512
	if err := l.Write(r); err != nil {
		t.Fatal(err)
	}
	l.Close()

	read, write := 1.5, 18.75
	prices := Prices{Currency: "USD", Model: map[string]Price{
		"claude-opus": {InPerMTok: 15, OutPerMTok: 75, CacheReadPer: &read, CacheWrite: &write},
	}}
	srv, ln, err := Serve("127.0.0.1:0", path, []byte("k"), prices, false)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	body := get(t, "http://"+ln.Addr().String()+"/?id=cached")
	for _, want := range []string{"187,361 cache-read", "512 cache-write", "read from cache", "cache-r"} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not surface the cache split: missing %q", want)
		}
	}
}

// The panel a completion log cannot produce: what the models were permitted to
// do, and what they actually did.
func TestToolsArePanelledSeparatelyFromCompletions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv("SWITCHBOARD_AUDIT_KEY", "k")
	l, err := audit.Open(path, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	offered := []string{"transfer_funds", "lookup_account", "close_account"}
	for i := 0; i < 5; i++ {
		r := rec("billing", "kim", "claude-opus", "bedrock", fmt.Sprintf("r%d", i), 100, 10)
		r.ToolsOffered = offered
		r.ToolCalls = []audit.ToolCall{{Name: "lookup_account", ID: "c1"}}
		if i == 0 {
			// One request that both looked up and moved money.
			r.ToolCalls = append(r.ToolCalls, audit.ToolCall{Name: "transfer_funds", ID: "c2"})
		}
		if err := l.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()

	s, err := Summarise(path, []byte("k"), Query{}, testPrices)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]ToolRow{}
	for _, tr := range s.Tools {
		byName[tr.Name] = tr
	}
	if len(byName) != 3 {
		t.Fatalf("tools = %+v, want all three offered", s.Tools)
	}
	if got := byName["lookup_account"]; got.Calls != 5 || got.Offered != 5 || got.Requests != 5 {
		t.Errorf("lookup_account = %+v", got)
	}
	if got := byName["transfer_funds"]; got.Calls != 1 || got.Requests != 1 {
		t.Errorf("transfer_funds = %+v", got)
	}
	// A tool offered on every request and never called is permission nobody
	// needed, and that is exactly the row worth seeing.
	if got := byName["close_account"]; got.Offered != 5 || got.Calls != 0 {
		t.Errorf("close_account = %+v, want offered and never called", got)
	}
	// Busiest first.
	if s.Tools[0].Name != "lookup_account" {
		t.Errorf("tools should be ordered by calls, got %s first", s.Tools[0].Name)
	}
}

func TestThePageShowsWhatTheAgentDid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv("SWITCHBOARD_AUDIT_KEY", "k")
	red, err := redact.New([]string{"email"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := audit.Open(path, red, true)
	if err != nil {
		t.Fatal(err)
	}
	r := rec("billing", "kim", "claude-opus", "bedrock", "agentic", 100, 10)
	r.ToolsOffered = []string{"transfer_funds", "email_customer"}
	r.ToolCalls = []audit.ToolCall{
		{Name: "transfer_funds", ID: "c1", Arguments: `{"amount":250}`},
		{Name: "email_customer", ID: "c2", Arguments: `{"to":"dana@example.com"}`},
	}
	if err := l.Write(r); err != nil {
		t.Fatal(err)
	}
	l.Close()

	srv, ln, err := Serve("127.0.0.1:0", path, []byte("k"), testPrices, false)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	body := get(t, "http://"+ln.Addr().String()+"/?id=agentic")
	for _, want := range []string{"transfer_funds", "email_customer", "tools offered", "tools called"} {
		if !strings.Contains(body, want) {
			t.Errorf("the request detail does not show %q", want)
		}
	}
	if !strings.Contains(body, "250") {
		t.Error("arguments should appear where content logging is on")
	}
	// Redaction still holds inside an argument.
	if strings.Contains(body, "dana@example.com") {
		t.Error("an address in a tool argument reached the page")
	}
}
