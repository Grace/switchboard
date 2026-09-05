package viewer

import (
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"
)

// Two drawings the page could not make before, both rendered as inline SVG
// with no script and no external reference — because the file they live in has
// to open from a USB stick in 2031 on a machine that never heard of us.
//
// A charting library would be easier and would defeat the purpose: a CDN
// reference is a dead page the day the CDN moves, and an evidence artifact that
// degrades is worse than a table.

// Bucket is one column of the activity histogram.
type Bucket struct {
	From, To time.Time
	Count    int
	Errors   int
	// Policy is the fingerprint in force for the last entry in this bucket,
	// which is what the change markers are derived from.
	Policy string
}

// Timeline is the activity of the window, bucketed, with the points where the
// rules changed underneath it.
type Timeline struct {
	Buckets []Bucket
	Peak    int
	// Changes are the buckets where the policy fingerprint differs from the
	// previous one. These are the marks nobody else can draw, because nobody
	// else records which rules were in force per entry.
	Changes []Change
	From    time.Time
	To      time.Time
}

// Change is one policy transition.
type Change struct {
	At     time.Time
	Bucket int
	From   string
	To     string
}

type timelineAcc struct {
	seen   []seenEntry
	errors int
}

type seenEntry struct {
	t      time.Time
	policy string
	failed bool
}

func (a *timelineAcc) add(t time.Time, policy string, failed bool) {
	a.seen = append(a.seen, seenEntry{t, policy, failed})
}

// build buckets what was seen. The bucket count is fixed rather than derived
// from the window so the drawing is the same width whether the period is a day
// or a year, and so a reader comparing two packages is comparing like with like.
const buckets = 72

func (a *timelineAcc) build() *Timeline {
	if len(a.seen) < 2 {
		return nil
	}
	sort.Slice(a.seen, func(i, j int) bool { return a.seen[i].t.Before(a.seen[j].t) })
	from, to := a.seen[0].t, a.seen[len(a.seen)-1].t
	span := to.Sub(from)
	if span <= 0 {
		return nil
	}

	tl := &Timeline{From: from, To: to, Buckets: make([]Bucket, buckets)}
	step := span / buckets
	for i := range tl.Buckets {
		tl.Buckets[i].From = from.Add(time.Duration(i) * step)
		tl.Buckets[i].To = from.Add(time.Duration(i+1) * step)
	}

	prev := ""
	for _, e := range a.seen {
		i := int(float64(e.t.Sub(from)) / float64(span) * float64(buckets))
		if i >= buckets {
			i = buckets - 1
		}
		if i < 0 {
			i = 0
		}
		tl.Buckets[i].Count++
		if e.failed {
			tl.Buckets[i].Errors++
		}
		tl.Buckets[i].Policy = e.policy
		if prev != "" && e.policy != "" && e.policy != prev {
			tl.Changes = append(tl.Changes, Change{At: e.t, Bucket: i, From: prev, To: e.policy})
		}
		if e.policy != "" {
			prev = e.policy
		}
		if tl.Buckets[i].Count > tl.Peak {
			tl.Peak = tl.Buckets[i].Count
		}
	}
	return tl
}

// SVG draws the histogram with the policy changes marked.
//
// Bars are the activity; a red cap is the failed share of that bucket; a
// vertical rule with a numbered flag is a point where the rules changed. That
// last one is the reason this drawing exists: "the rules changed on the 14th,
// here, and everything right of this line was decided under different ones" is
// a sentence an auditor asks and a table cannot answer.
func (t *Timeline) SVG() template.HTML {
	if t == nil || t.Peak == 0 {
		return ""
	}
	const (
		w, h    = 920.0, 132.0
		padL    = 4.0
		padB    = 26.0
		barGap  = 1.0
		flagTop = 8.0
	)
	bw := (w - padL*2) / float64(len(t.Buckets))
	plot := h - padB - flagTop

	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="tl" viewBox="0 0 %.0f %.0f" role="img" `+
		`aria-label="request volume over the period, with policy changes marked">`, w, h)

	for i, bk := range t.Buckets {
		if bk.Count == 0 {
			continue
		}
		x := padL + float64(i)*bw
		bh := float64(bk.Count) / float64(t.Peak) * plot
		y := flagTop + plot - bh
		fmt.Fprintf(&b, `<rect class="tlbar" x="%.2f" y="%.2f" width="%.2f" height="%.2f">`+
			`<title>%s — %d request(s)%s</title></rect>`,
			x, y, maxf(bw-barGap, 0.6), bh,
			bk.From.Format("2006-01-02 15:04"), bk.Count, errWord(bk.Errors))
		if bk.Errors > 0 {
			eh := float64(bk.Errors) / float64(t.Peak) * plot
			fmt.Fprintf(&b, `<rect class="tlerr" x="%.2f" y="%.2f" width="%.2f" height="%.2f"/>`,
				x, flagTop+plot-eh, maxf(bw-barGap, 0.6), eh)
		}
	}

	// Baseline, so an empty stretch reads as quiet rather than as missing.
	fmt.Fprintf(&b, `<line class="tlaxis" x1="%.0f" y1="%.2f" x2="%.0f" y2="%.2f"/>`,
		padL, flagTop+plot, w-padL, flagTop+plot)

	for n, c := range t.Changes {
		x := padL + (float64(c.Bucket)+0.5)*bw
		fmt.Fprintf(&b, `<line class="tlchange" x1="%.2f" y1="%.2f" x2="%.2f" y2="%.2f"/>`,
			x, flagTop, x, flagTop+plot)
		fmt.Fprintf(&b, `<circle class="tlflag" cx="%.2f" cy="%.2f" r="6"><title>`+
			`rules changed %s: %s to %s</title></circle>`,
			x, flagTop, c.At.Format("2006-01-02 15:04"), short(c.From), short(c.To))
		fmt.Fprintf(&b, `<text class="tlflagn" x="%.2f" y="%.2f">%d</text>`, x, flagTop+3.2, n+1)
	}

	fmt.Fprintf(&b, `<text class="tltick" x="%.0f" y="%.0f">%s</text>`,
		padL, h-8, t.From.Format("2006-01-02 15:04"))
	fmt.Fprintf(&b, `<text class="tltick tlright" x="%.0f" y="%.0f">%s</text>`,
		w-padL, h-8, t.To.Format("2006-01-02 15:04"))
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

func errWord(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(", %d failed", n)
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
