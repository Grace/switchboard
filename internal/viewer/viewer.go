// Package viewer renders an audit log as a page you can look at.
//
// This is a proof of concept and says so on the page. It exists because a
// governance property nobody can see is hard to believe, and because building
// the view is the test of whether the record is sufficient: if a useful page
// cannot be rendered from what the log holds, that is a finding about the log.
//
// The centre of the page is the flow graph — provider, model, team, person,
// prompt — because that is the shape of the question people actually arrive
// with. "Which of our providers saw this person's prompts, under what policy,
// and what did it cost" is one path through five columns, and every column is a
// field the log already carries. See flow.go.
//
// Three things it deliberately is not.
//
// It is not a service. It binds loopback, serves GET only, holds no state and
// has no database. Point it at a log — including one downloaded from an archive
// during an incident — and it reads. Filters are query parameters applied
// during that read; nothing is indexed and nothing is written back.
//
// It is not a prompt browser. It shows what the log contains, which is metadata
// unless content logging was deliberately enabled, and which has already passed
// through redaction. It never touches the vault: sealed values need the
// incident-response key, and that path is a command run by a person, not a page.
//
// It is not a dashboard. Aggregates over time belong in whatever already
// scrapes OTLP. What this shows is the part no time-series tool has: the chain,
// where policy changed underneath it, and the path a single request took.
package viewer

import (
	"fmt"
	"sort"
	"time"

	"github.com/Grace/switchboard/internal/audit"
)

// Summary is everything the page needs, computed in one pass.
type Summary struct {
	Path     string
	Segments int
	// Entries is the whole log; Matched is what survived the filter. Showing
	// both is what keeps a filtered page from being mistaken for the log.
	Entries int
	Matched int
	First   time.Time
	Last    time.Time

	Chain      *audit.Report
	ChainError string

	Query  Query
	Prices Prices
	Flow   *Flow
	// Timeline is the activity of the window with the policy changes marked.
	// Nil when there is too little to draw.
	Timeline *Timeline
	// Static is set when this is being written to a file rather than served.
	// A file has no server behind it, so anything that navigates has to be
	// suppressed: a link an auditor clicks and nothing happens is worse than
	// no link.
	Static bool

	Teams      []TeamRow
	Models     []ModelRow
	Redactions []CountRow
	Policies   []PolicyRow
	Recent     []Entry
	// Tools is what the models actually invoked, by name. This is the panel a
	// completion log cannot produce: "asked X, replied Y" is not a record of a
	// system that then called transfer_funds.
	Tools []ToolRow

	// Selected is the one request the filter names, when it names one. This is
	// the path view: five columns collapse to a single line, and the entry's
	// own fields fill in what the diagram cannot draw.
	Selected *Entry

	TotalPromptTokens int
	TotalReplyTokens  int
	// TotalCacheWriteTokens and TotalCacheReadTokens are the parts of the
	// prompt total that were cache traffic. They are shown separately because
	// they are billed separately, at rates that differ from the base input rate
	// by roughly an order of magnitude in both directions.
	TotalCacheWriteTokens int
	TotalCacheReadTokens  int
	TotalCost             float64
	// UnpricedRequests and UnpricedModels are why a total may be smaller than
	// reality. A model with no rate contributes tokens and no money, and the
	// page has to say which ones rather than quietly summing what it has.
	UnpricedRequests int
	UnpricedModels   []string

	Errors      int
	WithContent int
}

// Entry is a record plus what the rate card makes of it.
type Entry struct {
	audit.Record
	Cost   float64
	Priced bool
}

// Tokens is the entry's total, which is what the graph widths. A cache read is
// cheaper than a fresh input token, not smaller.
func (e Entry) Tokens() int { return tokensOf(e.Record).Total() }

// Cached reports whether any of this entry was cache traffic, which is what
// decides whether the detail card shows the split.
func (e Entry) Cached() bool { return tokensOf(e.Record).Cached() }

// Cached reports whether anything in this slice was cache traffic.
func (s *Summary) Cached() bool { return s.TotalCacheWriteTokens+s.TotalCacheReadTokens > 0 }

type TeamRow struct {
	Team                 string
	Requests             int
	PromptTokens         int
	ReplyTokens          int
	Cost                 float64
	Priced               bool
	Errors               int
	Subjects             int
	ShareOfTokensPercent int
}

type ModelRow struct {
	Model    string
	Backend  string
	Requests int
	Tokens   int
	Cost     float64
	Priced   bool
	Rate     string // per-million-token rate, as configured; empty when unpriced
}

type CountRow struct {
	Name  string
	Count int
}

// ToolRow is one tool and how it was used.
//
// Offered and Calls are separate columns because the gap between them is the
// interesting number. A tool offered on every request and never called is
// permission nobody needed; one called far more than expected is a question.
type ToolRow struct {
	Name     string
	Offered  int
	Calls    int
	Requests int // requests in which it was called at least once
}

// PolicyRow is a fingerprint and the window it was in force.
//
// This is the panel no time-series tool has: the rules changed here, and these
// are the entries made under each set.
type PolicyRow struct {
	Fingerprint string
	Entries     int
	From        time.Time
	To          time.Time
}

const recentCap = 50

// Summarise walks a log once and builds everything the page shows, restricted
// to the records the filter admits.
func Summarise(path string, key []byte, q Query, prices Prices) (*Summary, error) {
	s := &Summary{Path: path, Query: q, Prices: prices}

	segs, err := audit.Segments(path)
	if err != nil {
		return nil, err
	}
	s.Segments = len(segs)

	teams := map[string]*TeamRow{}
	subjects := map[string]map[string]bool{}
	models := map[string]*ModelRow{}
	redactions := map[string]int{}
	policies := map[string]*PolicyRow{}
	unpriced := map[string]bool{}
	tools := map[string]*ToolRow{}
	flow := NewFlow(q, prices)
	var tl timelineAcc

	err = audit.Walk(path, func(r audit.Record) error {
		s.Entries++
		if !q.Match(r) {
			return nil
		}
		s.Matched++
		flow.Add(r)
		tl.add(r.Time, r.Policy, r.Error != "")

		tk := tokensOf(r)
		cost, priced := prices.Cost(r.Model, tk)
		e := Entry{Record: r, Cost: cost, Priced: priced}
		if priced {
			s.TotalCost += cost
		} else {
			s.UnpricedRequests++
			unpriced[display(r.Model)] = true
		}

		if s.First.IsZero() || r.Time.Before(s.First) {
			s.First = r.Time
		}
		if r.Time.After(s.Last) {
			s.Last = r.Time
		}
		s.TotalPromptTokens += tk.Prompt()
		s.TotalReplyTokens += r.CompletionTokens
		s.TotalCacheWriteTokens += r.CacheWriteTokens
		s.TotalCacheReadTokens += r.CacheReadTokens
		if r.Error != "" {
			s.Errors++
		}
		if r.Prompt != "" || r.Completion != "" {
			s.WithContent++
		}

		team := display(r.Team)
		t := teams[team]
		if t == nil {
			t = &TeamRow{Team: team, Priced: true}
			teams[team] = t
			subjects[team] = map[string]bool{}
		}
		t.Requests++
		t.PromptTokens += tk.Prompt()
		t.ReplyTokens += r.CompletionTokens
		t.Cost += cost
		t.Priced = t.Priced && priced
		if r.Error != "" {
			t.Errors++
		}
		if r.Subject != "" {
			subjects[team][r.Subject] = true
		}

		if r.Model != "" {
			m := models[r.Model]
			if m == nil {
				m = &ModelRow{Model: r.Model, Backend: display(r.Backend), Priced: true,
					Rate: rateOf(prices, r.Model)}
				models[r.Model] = m
			}
			m.Requests++
			m.Tokens += tk.Total()
			m.Cost += cost
			m.Priced = m.Priced && priced
		}

		for rule, n := range r.Redactions {
			redactions[rule] += n
		}

		for _, name := range r.ToolsOffered {
			tools = touchTool(tools, name)
			tools[name].Offered++
		}
		seen := map[string]bool{}
		for _, c := range r.ToolCalls {
			tools = touchTool(tools, c.Name)
			tools[c.Name].Calls++
			if !seen[c.Name] {
				tools[c.Name].Requests++
				seen[c.Name] = true
			}
		}

		if r.Policy != "" {
			p := policies[r.Policy]
			if p == nil {
				p = &PolicyRow{Fingerprint: r.Policy, From: r.Time}
				policies[r.Policy] = p
			}
			p.Entries++
			if r.Time.Before(p.From) {
				p.From = r.Time
			}
			if r.Time.After(p.To) {
				p.To = r.Time
			}
		}

		// The last entry for a named request is the one that stands: a
		// completion that streamed and then failed writes twice, and the
		// second write is the one that says what happened.
		if q.ID != "" && display(r.ID) == q.ID {
			sel := e
			s.Selected = &sel
		}

		s.Recent = append(s.Recent, e)
		if len(s.Recent) > recentCap {
			s.Recent = s.Recent[1:]
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.Flow = flow.Build()

	total := s.TotalPromptTokens + s.TotalReplyTokens
	for name, t := range teams {
		t.Subjects = len(subjects[name])
		if total > 0 {
			t.ShareOfTokensPercent = (t.PromptTokens + t.ReplyTokens) * 100 / total
		}
		s.Teams = append(s.Teams, *t)
	}
	sort.Slice(s.Teams, func(i, j int) bool {
		return s.Teams[i].PromptTokens+s.Teams[i].ReplyTokens >
			s.Teams[j].PromptTokens+s.Teams[j].ReplyTokens
	})

	for _, m := range models {
		s.Models = append(s.Models, *m)
	}
	sort.Slice(s.Models, func(i, j int) bool { return s.Models[i].Tokens > s.Models[j].Tokens })

	for _, t := range tools {
		s.Tools = append(s.Tools, *t)
	}
	sort.Slice(s.Tools, func(i, j int) bool {
		if s.Tools[i].Calls != s.Tools[j].Calls {
			return s.Tools[i].Calls > s.Tools[j].Calls
		}
		return s.Tools[i].Name < s.Tools[j].Name
	})

	for rule, n := range redactions {
		s.Redactions = append(s.Redactions, CountRow{Name: rule, Count: n})
	}
	sort.Slice(s.Redactions, func(i, j int) bool { return s.Redactions[i].Count > s.Redactions[j].Count })

	for _, p := range policies {
		s.Policies = append(s.Policies, *p)
	}
	sort.Slice(s.Policies, func(i, j int) bool { return s.Policies[i].From.Before(s.Policies[j].From) })

	for m := range unpriced {
		s.UnpricedModels = append(s.UnpricedModels, m)
	}
	sort.Strings(s.UnpricedModels)

	// Verification is the point of the header, and it covers the whole log
	// rather than the filtered slice: a break anywhere means the entries that
	// survived a filter are entries from a file someone may have edited.
	rep, verr := audit.VerifyAll(path, key)
	if verr != nil {
		s.ChainError = verr.Error()
	} else {
		s.Chain = rep
	}

	// Newest first reads better than oldest first on a page.
	for i, j := 0, len(s.Recent)-1; i < j; i, j = i+1, j-1 {
		s.Recent[i], s.Recent[j] = s.Recent[j], s.Recent[i]
	}
	s.Timeline = tl.build()
	return s, nil
}

// touchTool makes sure a row exists. A tool that was offered and never called
// still gets a row: the permission is the fact.
func touchTool(m map[string]*ToolRow, name string) map[string]*ToolRow {
	if name == "" {
		name = "(unnamed)"
	}
	if m[name] == nil {
		m[name] = &ToolRow{Name: name}
	}
	return m
}

func rateOf(p Prices, model string) string {
	r, ok := p.Model[model]
	if !ok {
		return ""
	}
	out := fmt.Sprintf("%s in / %s out",
		money(r.InPerMTok, p.currency()), money(r.OutPerMTok, p.currency()))
	if r.CacheWrite != nil || r.CacheReadPer != nil {
		out += fmt.Sprintf(" / %s cache-w / %s cache-r",
			moneyOrDash(r.CacheWrite, p.currency()), moneyOrDash(r.CacheReadPer, p.currency()))
	}
	return out + " per Mtok"
}

func moneyOrDash(v *float64, currency string) string {
	if v == nil {
		return "—"
	}
	return money(*v, currency)
}

// Window renders the period the log covers.
func (s *Summary) Window() string {
	if s.Matched == 0 {
		return "no entries"
	}
	return fmt.Sprintf("%s — %s",
		s.First.UTC().Format("2006-01-02 15:04"),
		s.Last.UTC().Format("2006-01-02 15:04"))
}

// Verified reports whether the chain held.
func (s *Summary) Verified() bool {
	return s.Chain != nil && s.Chain.Break == nil
}

// Money formats a figure in the configured currency.
func (s *Summary) Money(v float64) string { return money(v, s.Prices.currency()) }

// Priced reports whether any rate card was configured at all. Without one the
// page shows tokens and says nothing about money, which is the right answer —
// switchboard ships no price list, deliberately. See config.Pricing.
func (s *Summary) Priced() bool { return len(s.Prices.Model) > 0 }

// Filtered reports whether the page is showing a slice rather than the log.
func (s *Summary) Filtered() bool { return !s.Query.Empty() }

// TotalTokens is what the filtered slice consumed.
func (s *Summary) TotalTokens() int { return s.TotalPromptTokens + s.TotalReplyTokens }
