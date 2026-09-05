// Package viewer renders an audit log as a page you can look at.
//
// This is a proof of concept and says so on the page. It exists because a
// governance property nobody can see is hard to believe, and because building
// the view is the test of whether the record is sufficient: if a useful page
// cannot be rendered from what the log holds, that is a finding about the log.
//
// Three things it deliberately is not.
//
// It is not a service. It binds loopback, serves GET only, holds no state and
// has no database. Point it at a log — including one downloaded from an archive
// during an incident — and it reads.
//
// It is not a prompt browser. It shows what the log contains, which is metadata
// unless content logging was deliberately enabled, and which has already passed
// through redaction. It never touches the vault: sealed values need the
// incident-response key, and that path is a command run by a person, not a page.
//
// It is not a dashboard. Aggregates over time belong in whatever already
// scrapes OTLP. What this shows is the part no time-series tool has: the chain,
// and where policy changed underneath it.
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
	Entries  int
	First    time.Time
	Last     time.Time

	Chain      *audit.Report
	ChainError string

	Teams      []TeamRow
	Models     []ModelRow
	Redactions []CountRow
	Policies   []PolicyRow
	Recent     []audit.Record

	TotalPromptTokens int
	TotalReplyTokens  int
	Errors            int
	WithContent       int
}

type TeamRow struct {
	Team                 string
	Requests             int
	PromptTokens         int
	ReplyTokens          int
	Errors               int
	Subjects             int
	ShareOfTokensPercent int
}

type ModelRow struct {
	Model    string
	Requests int
	Tokens   int
}

type CountRow struct {
	Name  string
	Count int
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

// Summarise walks a log once and builds everything the page shows.
func Summarise(path string, key []byte) (*Summary, error) {
	s := &Summary{Path: path}

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

	err = audit.Walk(path, func(r audit.Record) error {
		s.Entries++
		if s.First.IsZero() || r.Time.Before(s.First) {
			s.First = r.Time
		}
		if r.Time.After(s.Last) {
			s.Last = r.Time
		}
		s.TotalPromptTokens += r.PromptTokens
		s.TotalReplyTokens += r.CompletionTokens
		if r.Error != "" {
			s.Errors++
		}
		if r.Prompt != "" || r.Completion != "" {
			s.WithContent++
		}

		team := r.Team
		if team == "" {
			team = "unattributed"
		}
		t := teams[team]
		if t == nil {
			t = &TeamRow{Team: team}
			teams[team] = t
			subjects[team] = map[string]bool{}
		}
		t.Requests++
		t.PromptTokens += r.PromptTokens
		t.ReplyTokens += r.CompletionTokens
		if r.Error != "" {
			t.Errors++
		}
		if r.Subject != "" {
			subjects[team][r.Subject] = true
		}

		if r.Model != "" {
			m := models[r.Model]
			if m == nil {
				m = &ModelRow{Model: r.Model}
				models[r.Model] = m
			}
			m.Requests++
			m.Tokens += r.PromptTokens + r.CompletionTokens
		}

		for rule, n := range r.Redactions {
			redactions[rule] += n
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

		s.Recent = append(s.Recent, r)
		if len(s.Recent) > recentCap {
			s.Recent = s.Recent[1:]
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

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

	for rule, n := range redactions {
		s.Redactions = append(s.Redactions, CountRow{Name: rule, Count: n})
	}
	sort.Slice(s.Redactions, func(i, j int) bool { return s.Redactions[i].Count > s.Redactions[j].Count })

	for _, p := range policies {
		s.Policies = append(s.Policies, *p)
	}
	sort.Slice(s.Policies, func(i, j int) bool { return s.Policies[i].From.Before(s.Policies[j].From) })

	// Verification is the point of the header. A page reporting spend from a
	// log that does not verify would be reporting a number nobody should trust.
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
	return s, nil
}

// Window renders the period the log covers.
func (s *Summary) Window() string {
	if s.Entries == 0 {
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
