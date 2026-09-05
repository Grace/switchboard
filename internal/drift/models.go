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
}

// Builder accumulates records.
type Builder struct {
	approved map[string]bool
	roster   []string
	seen     map[string]*modelBucket
	order    []string
	policies map[string]bool
	entries  int
	first    time.Time
	last     time.Time
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
}

// Build finishes the comparison, busiest model first.
func (b *Builder) Build() Models {
	out := Models{
		Entries: b.entries, First: b.first, Last: b.last,
		RosterKnown: len(b.approved) > 0,
		Policies:    len(b.policies),
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
		out.Seen = append(out.Seen, u)
	}
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
