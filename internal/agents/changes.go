package agents

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// An inventory says what is running. An examiner asks what changed, and when.
//
// Those are different questions and the second is the one with money attached,
// because a SOC 2 Type II or an ISO 42001 surveillance audit is entirely about
// whether a control operated *throughout a period*. A deployment whose agent
// quietly gained a payment tool in week three looks identical, in any snapshot,
// to one that never changed.
//
// Everything here is derived from fields already in the record. A tool
// fingerprint changing is a datable event; so is a policy fingerprint changing.
// Neither needs to be collected, which matters: an append-only log cannot be
// asked later for a history it never wrote down.

// EventKind names what happened.
type EventKind string

const (
	// Appeared is an agent seen for the first time in the window.
	Appeared EventKind = "appeared"
	// Changed is an agent whose toolset moved. Always inferred: see Event.Inferred.
	Changed EventKind = "changed"
	// Retired is an agent that stopped calling and has not returned.
	Retired EventKind = "retired"
	// PolicyChanged is the configuration fingerprint moving under the traffic.
	PolicyChanged EventKind = "policy_changed"
)

// Event is one dated thing that happened, phrased so it can be pasted into an
// audit response without rewriting.
type Event struct {
	Time time.Time `json:"time"`
	Kind EventKind `json:"kind"`
	// Agent is the fingerprint this concerns; From is its predecessor, for a
	// Changed event.
	Agent string `json:"agent,omitempty"`
	From  string `json:"from,omitempty"`

	Gained []string `json:"gained,omitempty"`
	Lost   []string `json:"lost,omitempty"`
	// Shadow marks an event involving tools the configuration never declared.
	Shadow bool `json:"shadow,omitempty"`
	// Inferred marks a claim this package reasoned to rather than read. A
	// Changed event is always inferred: the log records two fingerprints, and
	// that they are the same program is a conclusion, not an observation.
	Inferred bool   `json:"inferred,omitempty"`
	Detail   string `json:"detail"`
}

// Shadow is a capability nobody declared, grouped by what arrived together.
//
// Skills ship as bundles, and undeclared tools are reported as a bundle for the
// same reason: five undeclared names that always appear in the same requests
// are one thing somebody installed, not five separate mistakes. Reporting them
// individually would put five rows in front of a reviewer and hide the fact
// that they are one decision, made once, by one person who can be asked.
type Shadow struct {
	// ID is a digest of the tool group, so the same shadow skill keeps its name
	// between runs.
	ID    string   `json:"id"`
	Tools []string `json:"tools"`
	// Agents are the fingerprints carrying it.
	Agents   []string  `json:"agents"`
	First    time.Time `json:"first_seen"`
	Last     time.Time `json:"last_seen"`
	Requests int       `json:"requests"`
	// Refused counts calls enforcement turned away. A shadow skill with
	// refusals is one that is being used, not merely present.
	Refused int `json:"refused"`
}

// Changelog is the period view.
type Changelog struct {
	Events []Event   `json:"events"`
	Shadow []Shadow  `json:"shadow_skills,omitempty"`
	First  time.Time `json:"first_seen"`
	Last   time.Time `json:"last_seen"`
	// Quiet is how long an agent must be silent before it is called retired.
	Quiet time.Duration `json:"quiet_after"`
}

// DefaultQuiet is the silence after which an agent is reported as retired.
//
// Any threshold is arbitrary and this one is stated wherever it is rendered
// rather than hidden. Two weeks is short enough to notice a decommissioned
// program inside a quarterly review and long enough to survive a holiday.
const DefaultQuiet = 14 * 24 * time.Hour

// Changes derives the period view from a built inventory.
func (inv Inventory) Changes(quiet time.Duration) Changelog {
	if quiet <= 0 {
		quiet = DefaultQuiet
	}
	log := Changelog{First: inv.First, Last: inv.Last, Quiet: quiet}

	// Real agents only. The untooled row is every program that used no tools,
	// so "it appeared" and "it changed" are meaningless about it.
	var live []Agent
	for _, a := range inv.Agents {
		if !a.Anonymous {
			live = append(live, a)
		}
	}
	sort.SliceStable(live, func(i, j int) bool { return live[i].First.Before(live[j].First) })

	undeclared := map[string]bool{}
	for _, a := range live {
		for _, t := range a.Undeclared {
			undeclared[t] = true
		}
	}

	// Succession. Each agent may descend from at most one predecessor, and each
	// predecessor may be succeeded once — otherwise a widely-shared toolset
	// becomes the claimed ancestor of everything that followed it.
	succeeded := map[string]bool{}
	from := make(map[string]Agent, len(live))
	for i, b := range live {
		best, bestScore := -1, 0.0
		for j := 0; j < i; j++ {
			a := live[j]
			if succeeded[a.ID] || !sharesTeam(a, b) {
				continue
			}
			// The predecessor has to plausibly have stopped where this one
			// started. A program that is still running is not an ancestor.
			if a.Last.After(b.First.Add(quiet)) || b.First.Sub(a.Last) > 90*24*time.Hour {
				continue
			}
			score := jaccard(a.Offered, b.Offered)
			if score > bestScore {
				best, bestScore = j, score
			}
		}
		// Half the toolset in common. Below that the claim stops being an
		// inference and starts being a guess, and a wrong lineage is worse than
		// two honest rows: it invents a history somebody may act on.
		if best >= 0 && bestScore >= 0.5 {
			succeeded[live[best].ID] = true
			from[b.ID] = live[best]
		}
	}

	for _, b := range live {
		a, ok := from[b.ID]
		if !ok {
			e := Event{
				Time: b.First, Kind: Appeared, Agent: b.ID,
				Detail: fmt.Sprintf("A program offering %s first called, as %s.",
					plural(len(b.Offered), "tool", "tools"), strings.Join(b.Teams, ", ")),
			}
			if len(b.Undeclared) > 0 {
				e.Shadow = true
				e.Gained = b.Undeclared
				e.Detail = fmt.Sprintf("A program nothing declared first called, as %s. "+
					"It offers %s the configuration does not know about: %s.",
					strings.Join(b.Teams, ", "),
					plural(len(b.Undeclared), "tool", "tools"),
					strings.Join(b.Undeclared, ", "))
			}
			log.Events = append(log.Events, e)
			continue
		}
		gained, lost := diff(a.Offered, b.Offered)
		e := Event{
			Time: b.First, Kind: Changed, Agent: b.ID, From: a.ID,
			Gained: gained, Lost: lost, Inferred: true,
		}
		var parts []string
		if len(gained) > 0 {
			parts = append(parts, "gained "+strings.Join(gained, ", "))
		}
		if len(lost) > 0 {
			parts = append(parts, "lost "+strings.Join(lost, ", "))
		}
		e.Detail = fmt.Sprintf("%s %s, and is now %s.", a.ID, strings.Join(parts, "; "), b.ID)
		for _, g := range gained {
			if undeclared[g] {
				e.Shadow = true
			}
		}
		log.Events = append(log.Events, e)
	}

	// Retirement. Measured against the end of the log rather than now, so the
	// same window produces the same answer whenever it is run.
	for _, a := range live {
		if succeeded[a.ID] {
			// It did not stop; it became something else, and that is already
			// reported as the change.
			continue
		}
		gap := inv.Last.Sub(a.Last)
		if gap < quiet {
			continue
		}
		log.Events = append(log.Events, Event{
			Time: a.Last, Kind: Retired, Agent: a.ID,
			Detail: fmt.Sprintf("Last call. Nothing from %s in the %s since.",
				a.ID, roughly(gap)),
		})
	}

	for i, p := range inv.Policies {
		if i == 0 {
			continue
		}
		log.Events = append(log.Events, Event{
			Time: p.First, Kind: PolicyChanged,
			Detail: fmt.Sprintf("The configuration in force changed: %s replaced %s. "+
				"Entries before and after this were judged under different rules.",
				short(p.Fingerprint), short(inv.Policies[i-1].Fingerprint)),
		})
	}

	sort.SliceStable(log.Events, func(i, j int) bool {
		return log.Events[i].Time.Before(log.Events[j].Time)
	})
	log.Shadow = shadowSkills(live, undeclared)
	return log
}

// shadowSkills groups undeclared tools by the set of agents that offer them.
//
// Tools carried by exactly the same agents arrived together, which is what a
// bundle is. This is the whole inference, and it is deliberately not cleverer
// than that: a heuristic that merged groups on partial overlap would report one
// skill where two were installed, and the person being asked about it would
// correctly say the report is wrong.
func shadowSkills(live []Agent, undeclared map[string]bool) []Shadow {
	if len(undeclared) == 0 {
		return nil
	}
	carriers := map[string][]string{}
	for _, a := range live {
		for _, t := range a.Undeclared {
			carriers[t] = append(carriers[t], a.ID)
		}
	}
	groups := map[string][]string{}
	for tool, ids := range carriers {
		sort.Strings(ids)
		key := strings.Join(ids, "\x00")
		groups[key] = append(groups[key], tool)
	}

	byID := make(map[string]Agent, len(live))
	for _, a := range live {
		byID[a.ID] = a
	}

	var out []Shadow
	for key, tools := range groups {
		sort.Strings(tools)
		ids := strings.Split(key, "\x00")
		id, _ := fingerprint(tools)
		s := Shadow{ID: id, Tools: tools, Agents: ids}
		for _, aid := range ids {
			a := byID[aid]
			s.Requests += a.Requests
			if s.First.IsZero() || a.First.Before(s.First) {
				s.First = a.First
			}
			if a.Last.After(s.Last) {
				s.Last = a.Last
			}
			for _, t := range tools {
				s.Refused += a.Refused[t]
			}
		}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].First.Equal(out[j].First) {
			return out[i].First.Before(out[j].First)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func jaccard(a, b []string) float64 {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	inter := 0
	for _, x := range b {
		if set[x] {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func diff(before, after []string) (gained, lost []string) {
	was := map[string]bool{}
	for _, x := range before {
		was[x] = true
	}
	is := map[string]bool{}
	for _, x := range after {
		is[x] = true
		if !was[x] {
			gained = append(gained, x)
		}
	}
	for _, x := range before {
		if !is[x] {
			lost = append(lost, x)
		}
	}
	sort.Strings(gained)
	sort.Strings(lost)
	return gained, lost
}

func sharesTeam(a, b Agent) bool {
	// No team on either side is not evidence of a different owner. An
	// unattributed deployment would otherwise get no lineage at all.
	if len(a.Teams) == 0 || len(b.Teams) == 0 {
		return true
	}
	set := map[string]bool{}
	for _, t := range a.Teams {
		set[t] = true
	}
	for _, t := range b.Teams {
		if set[t] {
			return true
		}
	}
	return false
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// roughly renders a gap the way somebody would say it out loud, because these
// sentences end up pasted into an audit response.
func roughly(d time.Duration) string {
	days := int(d.Hours() / 24)
	switch {
	case days >= 60:
		return fmt.Sprintf("%d months", days/30)
	case days >= 14:
		return fmt.Sprintf("%d weeks", days/7)
	default:
		return plural(days, "day", "days")
	}
}

func short(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	return fp
}
