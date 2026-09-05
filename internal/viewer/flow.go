package viewer

import (
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Grace/switchboard/internal/audit"
)

// The flow graph answers a question the tables cannot: not "what did billing
// spend" but "which provider, under which policy, on whose behalf, for which
// prompt". It is one path per request, drawn all at once.
//
// It is rendered server-side as SVG and carries no script. That is not
// minimalism for its own sake — the page it belongs to has a
// `default-src 'none'` policy and is meant to open from a log file on a machine
// with no route to the internet, which is where the deployments that need this
// most tend to live. Hover is an SVG <title>; selection is a link.

// Layers, left to right. The order is the causal one: a provider serves a
// model, a model answers a team, a team is made of people, a person writes a
// prompt.
const (
	LayerProvider = iota
	LayerModel
	LayerTeam
	LayerSubject
	LayerRequest
	layerCount
)

// LayerNames label the columns.
var LayerNames = [layerCount]string{"provider", "model", "team", "person", "request"}

// Price is one model's rate per million tokens.
//
// The cache rates are pointers because absent and zero mean different things:
// absent is "this model has no cache rate configured", zero is "cached tokens
// are free here". Only the second is a claim.
type Price struct {
	InPerMTok, OutPerMTok    float64
	CacheWrite, CacheReadPer *float64
}

// Tokens is one completion's consumption, split the way it is billed.
type Tokens struct {
	Input      int
	Output     int
	CacheWrite int
	CacheRead  int
}

// Total is everything consumed, however it was billed. This is what the ribbon
// widths use: a cache read is cheaper, not smaller.
func (t Tokens) Total() int { return t.Input + t.Output + t.CacheWrite + t.CacheRead }

// Prompt is everything that went in.
func (t Tokens) Prompt() int { return t.Input + t.CacheWrite + t.CacheRead }

// Cached reports whether any of this was cache traffic.
func (t Tokens) Cached() bool { return t.CacheWrite > 0 || t.CacheRead > 0 }

// tokensOf reads the split off a record.
func tokensOf(r audit.Record) Tokens {
	return Tokens{
		Input: r.PromptTokens, Output: r.CompletionTokens,
		CacheWrite: r.CacheWriteTokens, CacheRead: r.CacheReadTokens,
	}
}

// Prices is the rate card, restated here so this package does not depend on
// config. Currency is a label, not a conversion.
type Prices struct {
	Currency string
	Model    map[string]Price
}

// Cost reports what one completion cost, and whether it could be priced at all.
//
// Two ways to be unpriced: no rate for the model, or cached tokens with no rate
// for them. The second is the one that bites — pricing a cache read at the
// input rate overstates it roughly tenfold, and a page that did so would be
// confidently wrong rather than honestly silent.
func (p Prices) Cost(model string, t Tokens) (float64, bool) {
	r, ok := p.Model[model]
	if !ok {
		return 0, false
	}
	cost := float64(t.Input)*r.InPerMTok/1e6 + float64(t.Output)*r.OutPerMTok/1e6
	if t.CacheWrite > 0 {
		if r.CacheWrite == nil {
			return 0, false
		}
		cost += float64(t.CacheWrite) * *r.CacheWrite / 1e6
	}
	if t.CacheRead > 0 {
		if r.CacheReadPer == nil {
			return 0, false
		}
		cost += float64(t.CacheRead) * *r.CacheReadPer / 1e6
	}
	return cost, true
}

func (p Prices) currency() string {
	if p.Currency == "" {
		return "USD"
	}
	return p.Currency
}

// Query narrows the whole page to one slice of the log.
//
// Every dimension is a field the log already records, so a filter is never a
// claim the record cannot support. Filtering happens on read: nothing is
// indexed, nothing is written back.
type Query struct {
	Backend string
	Model   string
	Team    string
	Subject string
	Policy  string
	ID      string

	// From and To bound the window, half-open: an entry at exactly To belongs to
	// the next period. Quarters that overlap at the boundary double-count one
	// entry in two reports, which is the kind of discrepancy an auditor finds
	// and you then have to explain.
	From time.Time
	To   time.Time
}

// PeriodKey is the dimension name for the window, for With and Without. It is
// not in dims because it is two fields and a comparison rather than a string.
const PeriodKey = "period"

const dateLayout = "2006-01-02"

// parseBound accepts a plain date or a full timestamp. A plain date is read as
// UTC midnight, because the log is written in UTC and a report whose boundary
// silently moved with the reader's timezone is not evidence.
func parseBound(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), true
	}
	if t, err := time.Parse(dateLayout, s); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

func formatBound(t time.Time) string {
	t = t.UTC()
	if t.Equal(t.Truncate(24 * time.Hour)) {
		return t.Format(dateLayout)
	}
	return t.Format(time.RFC3339)
}

// Window renders the bounds for a chip, as the half-open interval it is.
func (q Query) Window() string {
	switch {
	case q.From.IsZero() && q.To.IsZero():
		return ""
	case q.From.IsZero():
		return "before " + formatBound(q.To)
	case q.To.IsZero():
		return "from " + formatBound(q.From)
	}
	return formatBound(q.From) + " to " + formatBound(q.To)
}

// dims is the one place the dimension list lives — query parsing, links, chips
// and the graph's layers all read it, so adding a dimension is one entry.
var dims = []struct {
	Key   string
	Label string
	get   func(*Query) *string
	of    func(audit.Record) string
}{
	{"backend", "provider", func(q *Query) *string { return &q.Backend }, func(r audit.Record) string { return r.Backend }},
	{"model", "model", func(q *Query) *string { return &q.Model }, func(r audit.Record) string { return r.Model }},
	{"team", "team", func(q *Query) *string { return &q.Team }, func(r audit.Record) string { return r.Team }},
	{"subject", "person", func(q *Query) *string { return &q.Subject }, func(r audit.Record) string { return r.Subject }},
	{"policy", "policy", func(q *Query) *string { return &q.Policy }, func(r audit.Record) string { return r.Policy }},
	{"id", "request", func(q *Query) *string { return &q.ID }, func(r audit.Record) string { return r.ID }},
}

// ParseQuery reads the filter out of a URL query string.
func ParseQuery(v url.Values) Query {
	var q Query
	for _, d := range dims {
		*d.get(&q) = strings.TrimSpace(v.Get(d.Key))
	}
	// An unparseable bound is dropped rather than rejected: this is a page, and
	// a mistyped date should widen the view, not produce an error screen.
	q.From, _ = parseBound(v.Get("from"))
	q.To, _ = parseBound(v.Get("to"))
	return q
}

// unattributed is what an empty dimension is called on the page. A blank cell
// reads as missing data; this reads as what it is — a request nobody was
// recorded as having made.
const unattributed = "unattributed"

func display(s string) string {
	if s == "" {
		return unattributed
	}
	return s
}

// Match reports whether a record is inside the filter. An empty filter value
// matches everything; the sentinel matches records with nothing recorded, so
// "show me the unattributed traffic" is expressible.
func (q Query) Match(r audit.Record) bool {
	if !q.From.IsZero() && r.Time.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && !r.Time.Before(q.To) {
		return false
	}
	for _, d := range dims {
		want := *d.get(&q)
		if want == "" {
			continue
		}
		if want != display(d.of(r)) {
			return false
		}
	}
	return true
}

// With returns the filter plus one more constraint.
func (q Query) With(dim, val string) Query {
	if dim == PeriodKey {
		q.From, q.To = time.Time{}, time.Time{}
		return q
	}
	for _, d := range dims {
		if d.Key == dim {
			*d.get(&q) = val
		}
	}
	return q
}

// Between bounds the window, half-open.
func (q Query) Between(from, to time.Time) Query {
	q.From, q.To = from, to
	return q
}

// Without drops one constraint.
func (q Query) Without(dim string) Query { return q.With(dim, "") }

// Encode renders the filter as a query string, always with a leading "?" so it
// is safe to use as an href even when empty.
func (q Query) Encode() string {
	v := url.Values{}
	for _, d := range dims {
		if s := *d.get(&q); s != "" {
			v.Set(d.Key, s)
		}
	}
	if !q.From.IsZero() {
		v.Set("from", formatBound(q.From))
	}
	if !q.To.IsZero() {
		v.Set("to", formatBound(q.To))
	}
	if len(v) == 0 {
		return "?"
	}
	return "?" + v.Encode()
}

// Chip is one active constraint and the link that removes it.
type Chip struct {
	Label string
	Value string
	Clear string
}

// Chips lists what is currently filtering the page.
func (q Query) Chips() []Chip {
	var out []Chip
	if w := q.Window(); w != "" {
		out = append(out, Chip{Label: PeriodKey, Value: w, Clear: q.Without(PeriodKey).Encode()})
	}
	for _, d := range dims {
		if s := *d.get(&q); s != "" {
			out = append(out, Chip{Label: d.Label, Value: s, Clear: q.Without(d.Key).Encode()})
		}
	}
	return out
}

// Empty reports whether anything is filtered.
func (q Query) Empty() bool { return len(q.Chips()) == 0 }

// FlowNode is one box in one column.
type FlowNode struct {
	Key   string // layer-qualified, unique
	Layer int
	Dim   string // the query dimension this node filters on
	Value string // the value it filters to
	Label string
	// Sub is a second line under the label. A request labelled with its prompt
	// needs its id shown too: two people asking the same question are two
	// requests, and a column of identical labels is unreadable without it.
	Sub string

	Requests int
	Tokens   int
	Cost     float64
	Priced   bool // a rate existed for every request behind this node
	Errors   int

	// Fold nodes stand for the tail that did not fit. They keep the diagram's
	// arithmetic honest — the ribbons still sum — without pretending the tail
	// is one thing you can click on.
	Fold bool

	X, Y, W, H float64
	// LabelY is where the text sits, which is the box's middle until two thin
	// boxes are close enough that their labels would overlap. Then the labels
	// are pushed apart and a leader line is drawn, because a diagram whose
	// labels collide is one you cannot read at exactly the moment it matters —
	// a long tail of small callers is the interesting shape, not the noise.
	LabelY float64
	Leader bool

	Href  string
	Title string
}

// FlowLink is one ribbon. Links are split by provider, so provider identity
// survives all the way to the right-hand column rather than being lost at the
// first join.
type FlowLink struct {
	From, To *FlowNode
	Provider string
	Slot     int // colour slot, 1-based; 0 is the folded-provider grey

	Requests int
	Tokens   int

	Path  string
	Width float64
	Title string
}

// LegendRow is one provider and its colour.
type LegendRow struct {
	Provider string
	Slot     int
	Requests int
	Tokens   int
	Href     string
}

// FlowColumn is one column heading and where it sits.
type FlowColumn struct {
	Name string
	X    float64
}

// Flow is the whole diagram, laid out and ready to render.
type Flow struct {
	Nodes   []*FlowNode
	Links   []*FlowLink
	Legend  []LegendRow
	Columns []FlowColumn

	Width, Height float64
	// ByRequests records that the ribbons are widthed by request count because
	// the filtered slice recorded no tokens at all — every request failed
	// before a usage number came back. Saying so beats drawing nothing.
	ByRequests bool
	Records    int
	// Folded counts columns where a tail was folded, so the page can say so.
	Folded int
}

// Empty reports whether there is anything to draw.
func (f *Flow) Empty() bool { return f == nil || len(f.Nodes) == 0 }

// headroom is space above the diagram for the column headings.
const headroom = 30.0

// ViewBox sizes the SVG. The box is the diagram plus the headings above it; the
// page scales it to the available width and lets it scroll below a floor.
func (f *Flow) ViewBox() string {
	return fmt.Sprintf("0 %.0f %.0f %.0f", -headroom, f.Width, f.Height+headroom+8)
}

// Weighted names what the ribbon widths mean, for the caption.
func (f *Flow) Weighted() string {
	if f.ByRequests {
		return "requests"
	}
	return "tokens"
}

// Layout constants. The right gutter is label space for the request column,
// which holds the longest text on the diagram.
const (
	flowWidth   = 1120.0
	rightGutter = 262.0
	nodeW       = 11.0
	leftPad     = 3.0
	minHeight   = 340.0
	maxHeight   = 900.0
	rowPitch    = 34.0

	providerSlots = 3
)

// perLayerCap bounds how many boxes a column may show. Past the cap the tail
// folds. Requests get a smaller cap because their labels are the long ones.
var perLayerCap = [layerCount]int{6, 10, 10, 12, 9}

// FlowBuilder accumulates records into a diagram. It takes them one at a time
// so the page can build the graph during the same walk that fills the tables,
// and never holds the log in memory.
type FlowBuilder struct {
	q      Query
	prices Prices

	nodes map[string]*FlowNode
	links map[string]*FlowLink
	// order preserves first-seen order so a tie between equal-weight nodes is
	// resolved the same way on every render rather than by map iteration.
	order    []string
	linkOrd  []string
	provider map[string]*LegendRow
	records  int
}

// NewFlow starts a diagram over the given filter and rate card.
func NewFlow(q Query, prices Prices) *FlowBuilder {
	return &FlowBuilder{
		q: q, prices: prices,
		nodes:    map[string]*FlowNode{},
		links:    map[string]*FlowLink{},
		provider: map[string]*LegendRow{},
	}
}

// BuildFlow is NewFlow over a slice, for callers that already have one.
func BuildFlow(recs []audit.Record, q Query, prices Prices) *Flow {
	b := NewFlow(q, prices)
	for _, r := range recs {
		b.Add(r)
	}
	return b.Build()
}

// path returns the five values one record contributes, one per column.
func path(r audit.Record) [layerCount]string {
	return [layerCount]string{
		display(r.Backend),
		display(r.Model),
		display(r.Team),
		display(r.Subject),
		display(r.ID),
	}
}

// Add folds one record into the diagram.
func (b *FlowBuilder) Add(r audit.Record) {
	b.records++
	p := path(r)
	tk := tokensOf(r)
	tokens := tk.Total()
	cost, priced := b.prices.Cost(r.Model, tk)

	prov := p[LayerProvider]
	leg := b.provider[prov]
	if leg == nil {
		leg = &LegendRow{Provider: prov, Href: b.q.With("backend", prov).Encode()}
		b.provider[prov] = leg
	}
	leg.Requests++
	leg.Tokens += tokens

	for layer := 0; layer < layerCount; layer++ {
		n := b.node(layer, p[layer], r)
		n.Requests++
		n.Tokens += tokens
		n.Cost += cost
		n.Priced = n.Priced && priced
		if r.Error != "" {
			n.Errors++
		}
		if layer > 0 {
			b.link(b.node(layer-1, p[layer-1], r), n, prov, tokens)
		}
	}
}

func (b *FlowBuilder) node(layer int, val string, r audit.Record) *FlowNode {
	key := fmt.Sprintf("%d\x00%s", layer, val)
	n := b.nodes[key]
	if n != nil {
		return n
	}
	n = &FlowNode{
		Key: key, Layer: layer, Dim: dims[layerDim(layer)].Key, Value: val,
		Label: label(layer, val, r), Priced: true,
	}
	if layer == LayerRequest && n.Label != val {
		n.Sub = truncate(val, 20)
	}
	b.nodes[key] = n
	b.order = append(b.order, key)
	return n
}

// label is what the box says. A request is labelled with its prompt where
// content logging was deliberately turned on, and with its completion id
// otherwise — the log's own answer to "which request", either way.
func label(layer int, val string, r audit.Record) string {
	if layer != LayerRequest {
		return val
	}
	if s := strings.TrimSpace(r.Prompt); s != "" {
		return truncate(collapse(s), 34)
	}
	return truncate(val, 26)
}

func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-1]) + "…"
}

func (b *FlowBuilder) link(from, to *FlowNode, prov string, tokens int) {
	key := from.Key + "\x01" + to.Key + "\x01" + prov
	l := b.links[key]
	if l == nil {
		l = &FlowLink{From: from, To: to, Provider: prov}
		b.links[key] = l
		b.linkOrd = append(b.linkOrd, key)
	}
	l.Requests++
	l.Tokens += tokens
}

// Build lays the diagram out. It is safe to call once.
func (b *FlowBuilder) Build() *Flow {
	f := &Flow{Width: flowWidth, Records: b.records}
	if b.records == 0 {
		return f
	}

	// Provider colour slots are assigned by weight, not by map order, so the
	// busiest provider is always slot 1 and a redraw of the same log looks the
	// same. Past the third, providers share the folded grey rather than getting
	// a generated hue nothing can tell apart.
	for _, leg := range b.provider {
		f.Legend = append(f.Legend, *leg)
	}
	sort.Slice(f.Legend, func(i, j int) bool {
		if f.Legend[i].Tokens != f.Legend[j].Tokens {
			return f.Legend[i].Tokens > f.Legend[j].Tokens
		}
		return f.Legend[i].Provider < f.Legend[j].Provider
	})
	slot := map[string]int{}
	for i := range f.Legend {
		if i < providerSlots {
			f.Legend[i].Slot = i + 1
		}
		slot[f.Legend[i].Provider] = f.Legend[i].Slot
	}

	// Weight. Tokens are the honest width — that is what was bought. A slice
	// with no tokens at all is one where nothing succeeded, and drawing it by
	// request count says more than drawing nothing.
	total := 0
	for _, k := range b.order {
		if n := b.nodes[k]; n.Layer == LayerProvider {
			total += n.Tokens
		}
	}
	f.ByRequests = total == 0
	weight := func(tokens, requests int) float64 {
		if f.ByRequests {
			return float64(requests)
		}
		return float64(tokens)
	}

	cols := b.columns()
	// Fold each column's tail before laying anything out, so the geometry is
	// computed over what is actually drawn.
	for layer := range cols {
		cols[layer] = b.fold(layer, cols[layer], weight)
		if n := len(cols[layer]); n > 0 && cols[layer][n-1].Fold {
			f.Folded++
		}
	}

	// Order: column 0 by weight, then each column by where its heaviest parent
	// sits. That is a cheap, deterministic stand-in for crossing minimisation,
	// and on a five-column diagram of this shape it reads as nested rather than
	// as a knot.
	sort.SliceStable(cols[0], func(i, j int) bool {
		return weight(cols[0][i].Tokens, cols[0][i].Requests) >
			weight(cols[0][j].Tokens, cols[0][j].Requests)
	})
	links := b.linkList(cols)
	rank := map[string]int{}
	for i, n := range cols[0] {
		rank[n.Key] = i
	}
	for layer := 1; layer < layerCount; layer++ {
		parent := map[string]float64{}
		best := map[string]int{}
		for _, l := range links {
			if l.To.Layer != layer {
				continue
			}
			w := weight(l.Tokens, l.Requests)
			if cur, seen := parent[l.To.Key]; !seen || w > cur {
				parent[l.To.Key], best[l.To.Key] = w, rank[l.From.Key]
			}
		}
		sort.SliceStable(cols[layer], func(i, j int) bool {
			a, bb := cols[layer][i], cols[layer][j]
			if best[a.Key] != best[bb.Key] {
				return best[a.Key] < best[bb.Key]
			}
			return weight(a.Tokens, a.Requests) > weight(bb.Tokens, bb.Requests)
		})
		for i, n := range cols[layer] {
			rank[n.Key] = i
		}
	}

	// Geometry.
	widest := 0
	for _, c := range cols {
		if len(c) > widest {
			widest = len(c)
		}
	}
	f.Height = math.Min(maxHeight, math.Max(minHeight, float64(widest)*rowPitch))

	totalW := 0.0
	for _, n := range cols[0] {
		totalW += weight(n.Tokens, n.Requests)
	}
	if totalW == 0 {
		totalW = 1
	}
	// Reserve the gaps for the busiest column, then every column is drawn at
	// the same scale — which is what makes a ribbon's width comparable to the
	// box it lands on.
	const gap = 7.0
	usable := f.Height - float64(widest-1)*gap
	scale := usable / totalW

	step := (flowWidth - rightGutter - nodeW - leftPad) / float64(layerCount-1)
	for layer := range cols {
		f.Columns = append(f.Columns, FlowColumn{
			Name: LayerNames[layer], X: leftPad + float64(layer)*step,
		})
	}
	for layer, col := range cols {
		sum := 0.0
		for _, n := range col {
			n.H = math.Max(1.5, weight(n.Tokens, n.Requests)*scale)
			sum += n.H
		}
		colGap := gap
		if len(col) > 1 {
			colGap = math.Max(2, (f.Height-sum)/float64(len(col)-1))
		}
		y := 0.0
		if len(col) == 1 {
			y = (f.Height - sum) / 2
		}
		for _, n := range col {
			n.X = leftPad + float64(layer)*step
			n.W = nodeW
			n.Y = y
			y += n.H + colGap
			n.Href = b.hrefFor(n)
			n.Title = b.titleFor(n)
		}
		declutter(col, f.Height)
		f.Nodes = append(f.Nodes, col...)
	}

	// Ribbons. Both ends stack in the order of the column they attach to, which
	// is what keeps a ribbon from crossing its own neighbours between columns.
	sort.SliceStable(links, func(i, j int) bool {
		a, bb := links[i], links[j]
		if a.From.Layer != bb.From.Layer {
			return a.From.Layer < bb.From.Layer
		}
		if rank[a.From.Key] != rank[bb.From.Key] {
			return rank[a.From.Key] < rank[bb.From.Key]
		}
		if rank[a.To.Key] != rank[bb.To.Key] {
			return rank[a.To.Key] < rank[bb.To.Key]
		}
		return slot[a.Provider] < slot[bb.Provider]
	})
	outAt := map[string]float64{}
	inAt := map[string]float64{}
	for _, l := range links {
		l.Slot = slot[l.Provider]
		l.Width = math.Max(0.8, weight(l.Tokens, l.Requests)*scale)

		sy := l.From.Y + outAt[l.From.Key] + l.Width/2
		ty := l.To.Y + inAt[l.To.Key] + l.Width/2
		outAt[l.From.Key] += l.Width
		inAt[l.To.Key] += l.Width

		sx := l.From.X + l.From.W
		tx := l.To.X
		c := (tx - sx) * 0.45
		l.Path = fmt.Sprintf("M%.1f,%.1f C%.1f,%.1f %.1f,%.1f %.1f,%.1f",
			sx, sy, sx+c, sy, tx-c, ty, tx, ty)
		l.Title = fmt.Sprintf("%s → %s · via %s · %s requests · %s tokens",
			l.From.Label, l.To.Label, l.Provider, commas(l.Requests), commas(l.Tokens))
		f.Links = append(f.Links, l)
	}
	return f
}

// columns groups the built nodes by layer, in first-seen order.
// labelPitch is the smallest vertical distance two labels may sit at.
const labelPitch = 13.0

// declutter spaces one column's labels, then pulls the run back inside the
// diagram if spacing pushed it off the bottom.
func declutter(col []*FlowNode, height float64) {
	prev := math.Inf(-1)
	for _, n := range col {
		mid := n.Y + n.H/2
		n.LabelY = math.Max(mid, prev+labelPitch)
		prev = n.LabelY
	}
	ceiling := height - 3
	for i := len(col) - 1; i >= 0; i-- {
		col[i].LabelY = math.Min(col[i].LabelY, ceiling)
		ceiling = col[i].LabelY - labelPitch
	}
	for _, n := range col {
		n.Leader = math.Abs(n.LabelY-(n.Y+n.H/2)) > 3
	}
}

func (b *FlowBuilder) columns() [layerCount][]*FlowNode {
	var cols [layerCount][]*FlowNode
	for _, k := range b.order {
		n := b.nodes[k]
		cols[n.Layer] = append(cols[n.Layer], n)
	}
	return cols
}

// fold keeps the heaviest nodes in a column and rolls the rest into one box.
// The tail's links are re-pointed at that box, so the diagram still sums.
func (b *FlowBuilder) fold(layer int, col []*FlowNode, weight func(int, int) float64) []*FlowNode {
	limit := perLayerCap[layer]
	if len(col) <= limit {
		return col
	}
	sorted := append([]*FlowNode(nil), col...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return weight(sorted[i].Tokens, sorted[i].Requests) >
			weight(sorted[j].Tokens, sorted[j].Requests)
	})
	keep, tail := sorted[:limit-1], sorted[limit-1:]

	other := &FlowNode{
		Key:   fmt.Sprintf("%d\x00\x02fold", layer),
		Layer: layer, Fold: true, Priced: true,
		Label: fmt.Sprintf("%d more %s", len(tail), plural(LayerNames[layer], len(tail))),
	}
	folded := map[string]bool{}
	for _, n := range tail {
		other.Requests += n.Requests
		other.Tokens += n.Tokens
		other.Cost += n.Cost
		other.Errors += n.Errors
		other.Priced = other.Priced && n.Priced
		folded[n.Key] = true
		delete(b.nodes, n.Key)
	}
	b.nodes[other.Key] = other

	// Re-point the tail's links, merging any that now share both ends.
	merged := map[string]*FlowLink{}
	var ord []string
	for _, k := range b.linkOrd {
		l := b.links[k]
		if l == nil {
			continue
		}
		if folded[l.From.Key] {
			l.From = other
		}
		if folded[l.To.Key] {
			l.To = other
		}
		nk := l.From.Key + "\x01" + l.To.Key + "\x01" + l.Provider
		if prev, ok := merged[nk]; ok {
			prev.Requests += l.Requests
			prev.Tokens += l.Tokens
			continue
		}
		merged[nk] = l
		ord = append(ord, nk)
	}
	b.links, b.linkOrd = merged, ord

	return append(keep, other)
}

func (b *FlowBuilder) linkList(cols [layerCount][]*FlowNode) []*FlowLink {
	live := map[string]bool{}
	for _, col := range cols {
		for _, n := range col {
			live[n.Key] = true
		}
	}
	out := make([]*FlowLink, 0, len(b.linkOrd))
	for _, k := range b.linkOrd {
		if l := b.links[k]; l != nil && live[l.From.Key] && live[l.To.Key] {
			out = append(out, l)
		}
	}
	return out
}

func (b *FlowBuilder) hrefFor(n *FlowNode) string {
	if n.Fold {
		return ""
	}
	// A node already in the filter clears itself, so the same click both
	// narrows and widens and nothing becomes a dead end.
	if *dims[layerDim(n.Layer)].get(&b.q) == n.Value {
		return b.q.Without(n.Dim).Encode()
	}
	return b.q.With(n.Dim, n.Value).Encode()
}

// layerDim maps a column to its entry in dims. They are parallel for the first
// four; the request column maps to the id filter, which sits after policy.
func layerDim(layer int) int {
	if layer == LayerRequest {
		return 5
	}
	return layer
}

func (b *FlowBuilder) titleFor(n *FlowNode) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s: %s\n%s requests · %s tokens",
		LayerNames[n.Layer], n.Label, commas(n.Requests), commas(n.Tokens))
	if n.Priced {
		fmt.Fprintf(&sb, " · %s", money(n.Cost, b.prices.currency()))
	} else {
		sb.WriteString(" · unpriced")
	}
	if n.Errors > 0 {
		fmt.Fprintf(&sb, "\n%s errors", commas(n.Errors))
	}
	return sb.String()
}

func plural(word string, n int) string {
	if n == 1 {
		return word
	}
	if word == "person" {
		return "people"
	}
	return word + "s"
}

// money formats a figure that is often a fraction of a cent. Rounding token
// spend to two places turns most real rows into "$0.00", which reads as free.
func money(v float64, currency string) string {
	sym := "$"
	if currency != "USD" {
		sym = currency + " "
	}
	switch {
	case v == 0:
		return sym + "0"
	case v < 0.01:
		return fmt.Sprintf("%s%.5f", sym, v)
	case v < 1:
		return fmt.Sprintf("%s%.4f", sym, v)
	case v < 1000:
		return fmt.Sprintf("%s%.2f", sym, v)
	default:
		return sym + commasFloat(v)
	}
}

func commasFloat(v float64) string {
	whole := int(v)
	return fmt.Sprintf("%s.%02d", commas(whole), int(math.Round((v-float64(whole))*100)))
}
