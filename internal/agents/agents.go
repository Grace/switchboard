// Package agents derives an inventory of the programs calling a gateway from
// the traffic they produced.
//
// Every AI inventory in the compliance market is a form. Somebody types their
// systems into a field once, and it is wrong the week after — which is exactly
// how it fails, because an auditor reaches for the inventory first and a stale
// one loses the scope question before any control is discussed.
//
// This is derived instead of declared. It cannot be stale for anything that
// actually ran, it cannot omit a system nobody registered, and it needs no new
// collection: every field it reads was already in the record.
//
// What it cannot do is see a program that never called. An inventory built from
// traffic is complete with respect to traffic and silent about everything else,
// and that limit is stated wherever it is rendered rather than left for a
// reader to assume otherwise.
package agents

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/config"
)

// Agent is one calling program, as the traffic reveals it.
//
// Identity is the set of tools the caller offered, not the team and not the
// person. A team key names who pays; a program is what runs, and one person
// running two agents under one key is two entries here. The set of tool names a
// caller puts in front of a model is remarkably distinctive — same names, same
// shape, request after request — so it serves as a fingerprint of the program
// without anyone having to label anything.
//
// It is a fingerprint and not an identifier. Two programs offering identical
// toolsets are one row here, and a program whose toolset changes becomes a new
// row. Both are stated where this is rendered, because the second is not a
// flaw: the day an agent's tools change is a day worth noticing.
type Agent struct {
	// ID is a short digest of the fingerprint, stable across runs.
	ID string `json:"id"`
	// Offered is the tool set that defines this agent, sorted.
	Offered []string `json:"offered,omitempty"`
	// Anonymous marks the one row that is not an agent: requests that offered
	// no tools at all, which cannot be told apart from the log.
	Anonymous bool `json:"anonymous,omitempty"`

	Teams    []string  `json:"teams,omitempty"`
	Models   []string  `json:"models,omitempty"`
	Subjects int       `json:"subjects"`
	Requests int       `json:"requests"`
	First    time.Time `json:"first_seen"`
	Last     time.Time `json:"last_seen"`

	// Cost is the spend attributed to this agent, and CostKnown reports whether
	// every request in it could be priced. A partial total presented as a whole
	// is the kind of number that gets repeated in a meeting.
	Cost      float64 `json:"cost"`
	CostKnown bool    `json:"cost_known"`

	// Called counts the calls the model actually made, by tool.
	Called map[string]int `json:"called,omitempty"`
	// Refused counts the calls enforcement turned away, by tool.
	Refused map[string]int `json:"refused,omitempty"`

	// Unused is offered minus called: authority this agent holds and has never
	// exercised. It is the least-privilege finding, measured rather than
	// asserted, and it is the one thing here an auditor can act on immediately.
	Unused []string `json:"unused,omitempty"`
	// Undeclared is what this agent offered that the configuration never
	// declared — a program that changed without anyone saying so.
	Undeclared []string `json:"undeclared,omitempty"`
}

// Inventory is what the traffic showed.
type Inventory struct {
	Agents  []Agent   `json:"agents"`
	Entries int       `json:"entries"`
	First   time.Time `json:"first_seen"`
	Last    time.Time `json:"last_seen"`
	// Declared is what the configuration knows about, for the diff. Empty means
	// nothing was declared, which is also why Undeclared is empty — telling
	// that apart from "everything is declared" is the reader's first question.
	Declared []string `json:"declared,omitempty"`
	// Unseen is declared but never offered by anybody: a tool the configuration
	// authorises that no program has asked for.
	Unseen []string `json:"unseen,omitempty"`
	// Policies are the configuration fingerprints seen in the window, in the
	// order they first appeared. A change here means the rules moved under the
	// traffic, which is the other half of "was this allowed at the time".
	Policies []PolicySpan `json:"policies,omitempty"`
}

// PolicySpan is one configuration fingerprint and the window it was seen in.
type PolicySpan struct {
	Fingerprint string    `json:"fingerprint"`
	First       time.Time `json:"first_seen"`
	Last        time.Time `json:"last_seen"`
	Requests    int       `json:"requests"`
}

type bucket struct {
	agent    Agent
	teams    map[string]bool
	models   map[string]bool
	subjects map[string]bool
	unpriced bool
}

// Builder accumulates records. Records are fed one at a time so the caller can
// stream a log of any size without holding it in memory.
type Builder struct {
	declared map[string]bool
	prices   config.Pricing
	seen     map[string]*bucket
	order    []string
	entries  int
	first    time.Time
	last     time.Time
	offered  map[string]bool
	policies map[string]*PolicySpan
	polOrder []string
}

// New starts an inventory. declared may be empty, in which case no undeclared
// finding is reported — an absent declaration list is not evidence that every
// tool is authorised.
func New(declared []string, prices config.Pricing) *Builder {
	d := make(map[string]bool, len(declared))
	for _, name := range declared {
		d[name] = true
	}
	return &Builder{
		declared: d,
		prices:   prices,
		seen:     make(map[string]*bucket),
		offered:  make(map[string]bool),
		policies: make(map[string]*PolicySpan),
	}
}

// fingerprint identifies an agent by what it offered. The names are sorted, so
// a caller listing the same tools in a different order is the same agent —
// order is a property of how a request was assembled, not of the program.
func fingerprint(tools []string) (string, []string) {
	if len(tools) == 0 {
		return "", nil
	}
	sorted := append([]string(nil), tools...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\x00")))
	return hex.EncodeToString(sum[:])[:6], sorted
}

// Add folds one record into the inventory.
func (b *Builder) Add(r audit.Record) {
	b.entries++
	if !r.Time.IsZero() {
		if b.first.IsZero() || r.Time.Before(b.first) {
			b.first = r.Time
		}
		if r.Time.After(b.last) {
			b.last = r.Time
		}
	}
	for _, name := range r.ToolsOffered {
		b.offered[name] = true
	}
	if r.Policy != "" {
		p, ok := b.policies[r.Policy]
		if !ok {
			p = &PolicySpan{Fingerprint: r.Policy, First: r.Time}
			b.policies[r.Policy] = p
			b.polOrder = append(b.polOrder, r.Policy)
		}
		p.Requests++
		if !r.Time.IsZero() {
			if p.First.IsZero() || r.Time.Before(p.First) {
				p.First = r.Time
			}
			if r.Time.After(p.Last) {
				p.Last = r.Time
			}
		}
	}

	id, sorted := fingerprint(r.ToolsOffered)
	key := id
	if id == "" {
		// Requests offering no tools share one row. They are not one program —
		// they are every program that did not use tools, and the log cannot
		// tell them apart. Splitting them by team would imply a distinction the
		// data does not support.
		key = "\x00anonymous"
	}
	bk, ok := b.seen[key]
	if !ok {
		bk = &bucket{
			agent: Agent{
				ID: id, Offered: sorted, Anonymous: id == "",
				Called: map[string]int{}, Refused: map[string]int{},
			},
			teams:    map[string]bool{},
			models:   map[string]bool{},
			subjects: map[string]bool{},
		}
		b.seen[key] = bk
		b.order = append(b.order, key)
	}

	a := &bk.agent
	a.Requests++
	if !r.Time.IsZero() {
		if a.First.IsZero() || r.Time.Before(a.First) {
			a.First = r.Time
		}
		if r.Time.After(a.Last) {
			a.Last = r.Time
		}
	}
	if r.Team != "" {
		bk.teams[r.Team] = true
	}
	if r.Model != "" {
		bk.models[r.Model] = true
	}
	if r.Subject != "" {
		bk.subjects[r.Subject] = true
	}
	for _, c := range r.ToolCalls {
		if c.Refused {
			a.Refused[c.Name]++
			continue
		}
		a.Called[c.Name]++
	}

	cost, ok := b.prices.Cost(r.Model, config.Tokens{
		Input:      r.PromptTokens,
		Output:     r.CompletionTokens,
		CacheWrite: r.CacheWriteTokens,
		CacheRead:  r.CacheReadTokens,
	})
	if !ok {
		bk.unpriced = true
		return
	}
	a.Cost += cost
}

// Build finishes the inventory, ordered by request count so the busiest
// programs are read first.
func (b *Builder) Build() Inventory {
	inv := Inventory{Entries: b.entries, First: b.first, Last: b.last}
	for name := range b.declared {
		inv.Declared = append(inv.Declared, name)
		if !b.offered[name] {
			inv.Unseen = append(inv.Unseen, name)
		}
	}
	sort.Strings(inv.Declared)
	sort.Strings(inv.Unseen)
	for _, fp := range b.polOrder {
		inv.Policies = append(inv.Policies, *b.policies[fp])
	}
	sort.SliceStable(inv.Policies, func(i, j int) bool {
		return inv.Policies[i].First.Before(inv.Policies[j].First)
	})

	for _, key := range b.order {
		bk := b.seen[key]
		a := bk.agent
		a.Teams = keys(bk.teams)
		a.Models = keys(bk.models)
		a.Subjects = len(bk.subjects)
		a.CostKnown = !bk.unpriced

		for _, name := range a.Offered {
			// A refused call counts as exercised. The agent asked; enforcement
			// said no. Listing it as unused authority would recommend removing
			// a grant the program is actively trying to use, which is the
			// opposite of the finding.
			if a.Called[name] == 0 && a.Refused[name] == 0 {
				a.Unused = append(a.Unused, name)
			}
			if len(b.declared) > 0 && !b.declared[name] {
				a.Undeclared = append(a.Undeclared, name)
			}
		}
		if len(a.Called) == 0 {
			a.Called = nil
		}
		if len(a.Refused) == 0 {
			a.Refused = nil
		}
		inv.Agents = append(inv.Agents, a)
	}
	sort.SliceStable(inv.Agents, func(i, j int) bool {
		// The anonymous row goes last regardless of size: it is context for the
		// others rather than a finding of its own, and it is often the largest.
		if inv.Agents[i].Anonymous != inv.Agents[j].Anonymous {
			return inv.Agents[j].Anonymous
		}
		return inv.Agents[i].Requests > inv.Agents[j].Requests
	})
	return inv
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
