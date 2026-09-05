// Package drift compares what the log shows against what the configuration
// approves.
//
// It is the same move as the agent inventory and the control report, applied to
// the model roster: a declaration is a statement of intent, traffic is what
// happened, and the gap between them is the finding. A deployment where those
// two agree has evidence; one where nobody has ever compared them has a
// document.
//
// The test this exists for is the one nobody runs — extract every distinct
// model identifier the log saw, and compare it to the approved list. It is
// cheap, it uses data already recorded, and it catches a model answering
// production traffic that no review ever passed.
package drift

import (
	"sort"
	"time"

	"github.com/Grace/switchboard/internal/audit"
)

// ModelUse is one model as the traffic saw it.
type ModelUse struct {
	Name     string    `json:"name"`
	Backends []string  `json:"backends,omitempty"`
	Teams    []string  `json:"teams,omitempty"`
	Requests int       `json:"requests"`
	First    time.Time `json:"first_seen"`
	Last     time.Time `json:"last_seen"`
	// Approved reports whether the configuration lists this name.
	Approved bool `json:"approved"`

	// IDs are the distinct provider-side identifiers this gateway sent under
	// this name, and ProviderIDs are the distinct identifiers providers
	// reported back. More than one of either means the name did not mean one
	// thing for the whole window.
	IDs         []string `json:"ids,omitempty"`
	ProviderIDs []string `json:"provider_ids,omitempty"`
}

// Repoint is one caller-facing name that resolved to something new.
//
// This is the finding a comparison of names cannot produce. The name is
// unchanged, the roster is unchanged, and a different thing answered.
type Repoint struct {
	Name string    `json:"name"`
	From string    `json:"from"`
	To   string    `json:"to"`
	At   time.Time `json:"at"`
	// Reported distinguishes a change the provider told us about from one this
	// deployment made to its own routing. The first is an observation about
	// somebody else's system; the second is a record of our own change, and an
	// auditor will treat them differently.
	Reported bool `json:"reported"`
}

// Models is the comparison.
type Models struct {
	Seen    []ModelUse `json:"seen"`
	Entries int        `json:"entries"`
	First   time.Time  `json:"first_seen"`
	Last    time.Time  `json:"last_seen"`

	// Unapproved are names that answered requests and are not on the roster.
	Unapproved []string `json:"unapproved,omitempty"`
	// Unused are roster entries nothing ever called. A model nobody uses is
	// still an approved route into a provider, and removing it is free.
	Unused []string `json:"unused,omitempty"`
	// RosterKnown reports whether there was a roster to compare against.
	// Without one, nothing is unapproved — an empty configuration is not
	// evidence that every model answering traffic was reviewed.
	RosterKnown bool `json:"roster_known"`

	// Repoints are names whose resolved identifier changed inside the window.
	Repoints []Repoint `json:"repoints,omitempty"`
	// Unevidenced counts entries carrying no resolved identifier at all.
	//
	// This is the number their test procedure turns on: a field added in month
	// seven leaves months one through six unevidenced, and a clean table over
	// a period that was never instrumented is not a pass. Evidenced reports
	// the earliest entry that did carry one.
	Unevidenced int       `json:"unevidenced"`
	Evidenced   time.Time `json:"evidenced_from,omitempty"`

	// Policies counts the distinct configuration fingerprints in force across
	// the window.
	//
	// This is here rather than in the changelog because it is what makes the
	// comparison above honest. The log records the name a caller asked for, not
	// the model id it resolved to, so a provider repointed underneath an
	// unchanged name is invisible to a comparison of names. The fingerprint
	// covers the model roster including its ids, so a repoint moves it — which
	// makes a fingerprint change the only signal this data can offer that a
	// name may no longer mean what it did.
	Policies int `json:"policies"`
}

type modelBucket struct {
	use      ModelUse
	backends map[string]bool
	teams    map[string]bool
	// First sighting of each resolved identifier, which is what dates a
	// repoint. An auditor's question is always when, not whether.
	ids      map[string]time.Time
	provider map[string]time.Time
}

// Builder accumulates records.
type Builder struct {
	approved    map[string]bool
	roster      []string
	seen        map[string]*modelBucket
	order       []string
	policies    map[string]bool
	entries     int
	first       time.Time
	last        time.Time
	unevidenced int
	evidenced   time.Time
}

// New starts a comparison against the approved roster.
func New(approved []string) *Builder {
	m := make(map[string]bool, len(approved))
	for _, name := range approved {
		m[name] = true
	}
	return &Builder{
		approved: m,
		roster:   append([]string(nil), approved...),
		seen:     make(map[string]*modelBucket),
		policies: make(map[string]bool),
	}
}

// Add folds one record in.
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
	if r.Policy != "" {
		b.policies[r.Policy] = true
	}
	if r.Model == "" {
		return
	}
	bk, ok := b.seen[r.Model]
	if !ok {
		bk = &modelBucket{
			use:      ModelUse{Name: r.Model},
			backends: map[string]bool{},
			teams:    map[string]bool{},
			ids:      map[string]time.Time{},
			provider: map[string]time.Time{},
		}
		b.seen[r.Model] = bk
		b.order = append(b.order, r.Model)
	}
	bk.use.Requests++
	if !r.Time.IsZero() {
		if bk.use.First.IsZero() || r.Time.Before(bk.use.First) {
			bk.use.First = r.Time
		}
		if r.Time.After(bk.use.Last) {
			bk.use.Last = r.Time
		}
	}
	if r.Backend != "" {
		bk.backends[r.Backend] = true
	}
	if r.Team != "" {
		bk.teams[r.Team] = true
	}

	// Whether anything at all evidences what actually served the request. A
	// clean comparison over a period nobody instrumented is not a pass, so the
	// entries that could not answer are counted rather than skipped.
	if r.ModelID == "" && r.ProviderModel == "" {
		b.unevidenced++
	} else if !r.Time.IsZero() && (b.evidenced.IsZero() || r.Time.Before(b.evidenced)) {
		b.evidenced = r.Time
	}
	noteFirst(bk.ids, r.ModelID, r.Time)
	noteFirst(bk.provider, r.ProviderModel, r.Time)
}

// noteFirst records the earliest sighting of an identifier.
func noteFirst(m map[string]time.Time, id string, t time.Time) {
	if id == "" {
		return
	}
	if prev, ok := m[id]; !ok || t.Before(prev) {
		m[id] = t
	}
}

// Build finishes the comparison, busiest model first.
func (b *Builder) Build() Models {
	out := Models{
		Entries: b.entries, First: b.first, Last: b.last,
		RosterKnown: len(b.approved) > 0,
		Policies:    len(b.policies),
		Unevidenced: b.unevidenced,
		Evidenced:   b.evidenced,
	}
	for _, name := range b.order {
		bk := b.seen[name]
		u := bk.use
		u.Backends = keys(bk.backends)
		u.Teams = keys(bk.teams)
		// With no roster nothing is unapproved, and calling everything approved
		// would be worse: it would report assurance nobody supplied. The flag
		// is only meaningful when RosterKnown, and the renderer says so.
		u.Approved = b.approved[name]
		if out.RosterKnown && !u.Approved {
			out.Unapproved = append(out.Unapproved, name)
		}
		u.IDs = sortedByFirst(bk.ids)
		u.ProviderIDs = sortedByFirst(bk.provider)
		// The finding a comparison of names cannot make. One name, more than
		// one thing behind it, and the date the second one appeared.
		out.Repoints = append(out.Repoints, repoints(name, bk.ids, false)...)
		out.Repoints = append(out.Repoints, repoints(name, bk.provider, true)...)
		out.Seen = append(out.Seen, u)
	}
	sort.SliceStable(out.Repoints, func(i, j int) bool {
		return out.Repoints[i].At.Before(out.Repoints[j].At)
	})
	for _, name := range b.roster {
		if _, ok := b.seen[name]; !ok {
			out.Unused = append(out.Unused, name)
		}
	}
	sort.Strings(out.Unapproved)
	sort.Strings(out.Unused)
	sort.SliceStable(out.Seen, func(i, j int) bool {
		return out.Seen[i].Requests > out.Seen[j].Requests
	})
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedByFirst orders identifiers by when each was first seen, so a reader
// follows the sequence rather than the alphabet.
func sortedByFirst(m map[string]time.Time) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !m[out[i]].Equal(m[out[j]]) {
			return m[out[i]].Before(m[out[j]])
		}
		return out[i] < out[j]
	})
	return out
}

// repoints turns a name's identifier history into transitions.
//
// Each successive identifier is reported as replacing the one before it. That
// is a statement about order of first appearance and not about causation: two
// identifiers can overlap during a rollout, and the log cannot distinguish a
// staged deployment from a replacement. What it can say — and what an auditor
// needs — is that on this date, under this unchanged name, something answered
// that had not answered before.
func repoints(name string, m map[string]time.Time, reported bool) []Repoint {
	if len(m) < 2 {
		return nil
	}
	order := sortedByFirst(m)
	out := make([]Repoint, 0, len(order)-1)
	for i := 1; i < len(order); i++ {
		out = append(out, Repoint{
			Name: name, From: order[i-1], To: order[i],
			At: m[order[i]], Reported: reported,
		})
	}
	return out
}
