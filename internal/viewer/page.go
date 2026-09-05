package viewer

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// Serve renders the log at addr until the listener is closed.
//
// Loopback unless explicitly overridden: this page shows who spent what and,
// where content logging is on, redacted prompts. It is not something to put on
// an interface by accident.
func Serve(addr, path string, key []byte, prices Prices, allowRemote bool) (*http.Server, net.Listener, error) {
	if !allowRemote && !isLoopback(addr) {
		return nil, nil, fmt.Errorf(
			"refusing to bind %s: this page shows spend and redacted content, and it "+
				"has no authentication. Bind loopback and forward a port, or pass "+
				"-allow-remote if you have decided otherwise", addr)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		s, err := Summarise(path, key, ParseQuery(r.URL.Query()), prices)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// No third-party anything: this has to work on a machine with no route
		// to the internet, which is where the interesting deployments are. The
		// diagram is server-rendered SVG for the same reason — there is no
		// script to allow, so none is allowed.
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		if err := page.Execute(w, s); err != nil {
			return
		}
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	return &http.Server{Handler: mux}, ln, nil
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" || host == "" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func commas(n int) string {
	s := fmt.Sprint(n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

var page = template.Must(template.New("page").Funcs(template.FuncMap{
	"inc":    func(i int) int { return i + 1 },
	"commas": commas,
	"short": func(s string) string {
		if len(s) > 12 {
			return s[:12]
		}
		return s
	},
	"stamp": func(t interface{ Format(string) string }) string {
		return t.Format("2006-01-02 15:04:05")
	},
	"trunc": func(n int, s string) string { return truncate(collapse(s), n) },
	"mid":   func(n *FlowNode) float64 { return n.Y + n.H/2 },
	"add":   func(a, b float64) float64 { return a + b },
	"join":  strings.Join,
}).Parse(`<!doctype html>
<meta charset="utf-8">
<title>switchboard — audit log</title>
<style>
  /* Colour is assigned by job. Providers are the only categorical dimension on
     this page, and they take the first three validated slots in fixed order by
     weight; a fourth provider shares the folded grey rather than being given a
     generated hue nothing could tell apart. Everything else — boxes, rules,
     text — is ink, so a colour on this page always means "provider". */
  :root {
    color-scheme: light dark;
    --surface:#fcfcfb; --raise:#f4f3ef;
    --ink:#0b0b0b; --dim:#52514e; --muted:#898781;
    --line:#e1e0d9; --rule:#c3c2b7;
    --bad:#d03b3b; --ok:#0ca30c;
    --p1:#2a78d6; --p2:#eb6834; --p3:#1baf7a; --p0:#898781;
    --node:#c9c8c0;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --surface:#16181d; --raise:#1d2027;
      --ink:#f2f2ef; --dim:#c3c2b7; --muted:#898781;
      --line:#2c2f36; --rule:#3a3e46;
      --bad:#f2b8b5; --ok:#7ddba3;
      --p1:#3987e5; --p2:#d95926; --p3:#199e70; --p0:#898781;
      --node:#454a54;
    }
  }
  body { font: 14px/1.5 ui-monospace, "SF Mono", Menlo, monospace; margin: 0 auto;
         padding: 2rem 1.5rem 4rem; max-width: 78rem;
         background: var(--surface); color: var(--ink); }
  h1 { font-size: 1.1rem; margin: 0 0 .2rem; }
  h2 { font-size: .8rem; text-transform: uppercase; letter-spacing: .08em; color: var(--dim);
       border-bottom: 1px solid var(--line); padding-bottom: .3rem; margin: 2.4rem 0 .6rem; }
  .sub { color: var(--dim); margin: 0 0 1.4rem; }
  a { color: inherit; }
  table { border-collapse: collapse; width: 100%; }
  th { text-align: left; font-weight: 600; color: var(--dim); font-size: .8rem; padding: .3rem .6rem .3rem 0; }
  td { padding: .25rem .6rem .25rem 0; border-top: 1px solid var(--line); white-space: nowrap; }
  td.n, th.n { text-align: right; font-variant-numeric: tabular-nums; }
  td.w { white-space: normal; word-break: break-word; }
  tr.row:hover td { background: var(--raise); }
  .bar { display:inline-block; height:.55rem; background: currentColor; opacity:.35; vertical-align: middle; }
  .ok { color: var(--ok); } .bad { color: var(--bad); }
  .note { color: var(--dim); font-size: .82rem; margin: .5rem 0 0; max-width: 58rem; }
  .banner { border:1px solid var(--line); border-left-width:3px; padding:.6rem .8rem; margin:0 0 1.2rem; }

  /* Filter bar. Standard UI, one row, above the diagram it filters. */
  .filters { display:flex; flex-wrap:wrap; gap:.4rem; align-items:center; margin:0 0 1.2rem; }
  .chip { display:inline-flex; gap:.45rem; align-items:center; border:1px solid var(--rule);
          border-radius:2rem; padding:.15rem .6rem; font-size:.8rem; background:var(--raise); }
  .chip b { font-weight:600; color:var(--dim); text-transform:uppercase; letter-spacing:.05em; font-size:.72rem; }
  .chip a { text-decoration:none; color:var(--muted); }
  .chip a:hover { color:var(--bad); }
  .clear { font-size:.8rem; color:var(--dim); }

  /* KPI row. A handful of headline numbers is a row of tiles, not a chart. */
  .tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(9.5rem,1fr)); gap:.6rem; margin:0 0 1.4rem; }
  .tlwrap { margin:1.1rem 0 .3rem; }
  .tl { width:100%; height:auto; display:block; }
  .tlbar { fill: var(--ink); opacity:.30; }
  .tlbar:hover { opacity:.70; }
  .tlerr { fill:#b3261e; opacity:.85; }
  .tlaxis { stroke: var(--line); stroke-width:1; }
  .tlchange { stroke: var(--ink); stroke-width:1; stroke-dasharray:2 3; opacity:.55; }
  .tlflag { fill: var(--surface); stroke: var(--ink); stroke-width:1.2; }
  .tlflagn { font:600 8px system-ui, sans-serif; fill: var(--ink); text-anchor:middle; }
  .tltick { font:400 10px ui-monospace, SFMono-Regular, Menlo, monospace; fill: var(--muted); }
  .tlright { text-anchor:end; }
  .tlkey { font-size:.76rem; color:var(--dim); margin:.15rem 0 0; }
  .tlkey b { font-weight:600; color:var(--ink); }
  .tile { border:1px solid var(--line); padding:.55rem .7rem; }
  .tile .k { font-size:.72rem; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); }
  .tile .v { font: 600 1.35rem/1.25 system-ui, -apple-system, "Segoe UI", sans-serif; }
  .tile .s { font-size:.76rem; color:var(--dim); }

  .scroll { overflow-x:auto; margin: .2rem 0 .4rem; }
  svg.flow { width:100%; min-width:52rem; height:auto; display:block; }
  .flow .col { fill: var(--muted); font-size: 9.5px; letter-spacing:.09em; text-transform:uppercase; }
  .flow .guide { stroke: var(--line); stroke-width: 1; }
  .flow .node { fill: var(--node); }
  .flow .node.err { fill: var(--bad); }
  .flow .lead { stroke: var(--rule); stroke-width: .8; fill:none; }
  .flow text.lbl { fill: var(--ink); font-size: 11px;
        paint-order: stroke fill; stroke: var(--surface); stroke-width: 3px; stroke-linejoin: round; }
  .flow text.amt { fill: var(--muted); font-size: 9.5px;
        paint-order: stroke fill; stroke: var(--surface); stroke-width: 3px; stroke-linejoin: round; }
  .flow .ribbon { fill:none; stroke-opacity:.34; }
  .flow a:hover .ribbon, .flow g:hover > .ribbon { stroke-opacity:.72; }
  .flow a:hover .node { fill: var(--ink); }
  .flow .s1 { stroke: var(--p1); } .flow .s2 { stroke: var(--p2); }
  .flow .s3 { stroke: var(--p3); } .flow .s0 { stroke: var(--p0); }
  .legend { display:flex; flex-wrap:wrap; gap:1rem; align-items:center; font-size:.8rem; color:var(--dim); margin:.4rem 0 0; }
  .legend a { text-decoration:none; display:inline-flex; gap:.4rem; align-items:center; }
  .sw { width:.7rem; height:.7rem; border-radius:2px; display:inline-block; }
  .sw1{background:var(--p1)} .sw2{background:var(--p2)} .sw3{background:var(--p3)} .sw0{background:var(--p0)}

  .card { border:1px solid var(--line); border-left:3px solid var(--p1); padding:.8rem 1rem; margin:.6rem 0 0; }
  .card dl { display:grid; grid-template-columns:max-content 1fr; gap:.2rem 1rem; margin:0; }
  .card dt { color:var(--muted); font-size:.8rem; }
  .card dd { margin:0; }
  .card pre { white-space:pre-wrap; word-break:break-word; background:var(--raise);
              border:1px solid var(--line); padding:.6rem; margin:.5rem 0 0; font-size:.82rem; }
  .empty { border:1px dashed var(--rule); padding:1.4rem; text-align:center; color:var(--dim); }
</style>

<h1>switchboard — audit log</h1>
<p class="sub">{{.Path}} · {{.Segments}} segment(s) · {{.Window}}</p>

<div class="banner">
{{if .ChainError}}<strong class="bad">chain could not be verified</strong><br>{{.ChainError}}
{{else if .Verified}}<strong class="ok">chain intact</strong> — {{commas .Chain.Entries}} entries verify{{if .Chain.Keyed}}, signed{{else}}, unsigned{{end}}
{{else if .Chain.Break}}<strong class="bad">chain broken</strong> at line {{.Chain.Break.Line}} (seq {{.Chain.Break.Seq}}) — {{.Chain.Break.Reason}}<br>
  {{commas .Chain.Entries}} entries verify before it.
{{end}}
<p class="note">Every number below is read from this log. If the chain does not
verify, they are numbers from a file someone may have edited. Verification covers
the whole log, not the filtered slice — a break anywhere is a break under
everything.</p>
</div>

<div class="filters">
{{if .Filtered}}
  {{range .Query.Chips}}<span class="chip"><b>{{.Label}}</b> {{.Value}} <a href="{{.Clear}}" title="remove this filter">✕</a></span>{{end}}
  {{if not .Static}}<a class="clear" href="?">clear all</a>{{end}}
  <span class="clear">· {{commas .Matched}} of {{commas .Entries}} entries</span>
{{else}}
  <span class="clear">No filter — showing all {{commas .Entries}} entries. Click anything on the diagram to narrow.</span>
{{end}}
</div>

<div class="tiles">
  <div class="tile"><div class="k">requests</div><div class="v">{{commas .Matched}}</div>
    <div class="s">{{if .Errors}}<span class="bad">{{commas .Errors}} failed</span>{{else}}none failed{{end}}</div></div>
  <div class="tile"><div class="k">tokens</div><div class="v">{{commas .TotalTokens}}</div>
    <div class="s">{{commas .TotalPromptTokens}} in · {{commas .TotalReplyTokens}} out{{if .Cached}}<br>{{commas .TotalCacheReadTokens}} cache-read · {{commas .TotalCacheWriteTokens}} cache-write{{end}}</div></div>
{{if .Priced}}
  <div class="tile"><div class="k">cost</div><div class="v">{{.Money .TotalCost}}</div>
    <div class="s">{{if .UnpricedRequests}}<span class="bad">{{commas .UnpricedRequests}} unpriced</span>{{else}}all requests priced{{end}}</div></div>
{{else}}
  <div class="tile"><div class="k">cost</div><div class="v">—</div>
    <div class="s">no rate card configured</div></div>
{{end}}
  <div class="tile"><div class="k">people</div><div class="v">{{len .Teams}}</div>
    <div class="s">teams in this slice</div></div>
  <div class="tile"><div class="k">policies</div><div class="v">{{len .Policies}}</div>
    <div class="s">{{if gt (len .Policies) 1}}<span class="bad">rules changed</span>{{else}}one set of rules{{end}}</div></div>
</div>

{{with .Timeline}}
<div class="tlwrap">
  {{.SVG}}
  {{if .Changes}}
  <p class="tlkey">Dashed marks are points where the decision-affecting configuration changed.
  Entries either side of one were decided under different rules.
  {{range $i, $c := .Changes}}<br><b>{{inc $i}}</b> {{$c.At.Format "2006-01-02 15:04"}} — {{$c.From}} → {{$c.To}}{{end}}</p>
  {{else}}
  <p class="tlkey">One set of rules in force across the whole window.</p>
  {{end}}
</div>
{{end}}

{{if and .Priced .UnpricedModels}}
<div class="banner"><strong class="bad">{{commas .UnpricedRequests}} requests are unpriced</strong> —
no rate is configured for {{join .UnpricedModels ", "}}.
<p class="note">Their tokens are counted; their cost is not. switchboard ships no
price list on purpose, so a total is only ever the sum of the rates you declared
under <code>pricing.models</code> — never a guess at the rest. A model also reads
as unpriced when it served cached tokens and no <code>cache_read_per_mtok</code> or
<code>cache_write_per_mtok</code> is set for it: a cache read costs a fraction of
the input rate, so charging it at the input rate would overstate the figure by
close to tenfold rather than leave it blank.</p></div>
{{end}}

<h2>Path — provider to prompt</h2>
{{if .Flow.Empty}}
<div class="empty">Nothing in this slice. <a href="?">Clear the filter</a>.</div>
{{else}}
<div class="scroll">
<svg class="flow" viewBox="{{.Flow.ViewBox}}" role="img" preserveAspectRatio="xMinYMin meet">
  <title>Provider to prompt, for {{commas .Flow.Records}} requests</title>
  <desc>A five-column flow diagram. Each ribbon is one path from a model provider
  through a model, a team and a person to a request, widthed by {{.Flow.Weighted}}
  and coloured by provider. The tables below carry the same figures.</desc>

  {{range .Flow.Columns}}<text class="col" x="{{printf "%.1f" .X}}" y="-14">{{.Name}}</text>{{end}}
  <line class="guide" x1="0" y1="-7" x2="{{printf "%.0f" .Flow.Width}}" y2="-7"/>

  {{range .Flow.Links}}<path class="ribbon s{{.Slot}}" d="{{.Path}}" stroke-width="{{printf "%.2f" .Width}}"><title>{{.Title}}</title></path>
  {{end}}

  {{range .Flow.Nodes}}
  {{if .Href}}<a href="{{.Href}}">{{end}}
    <g>
      <title>{{.Title}}</title>
      <rect class="node{{if and .Errors (eq .Requests .Errors)}} err{{end}}" x="{{printf "%.1f" .X}}" y="{{printf "%.1f" .Y}}" width="{{printf "%.1f" .W}}" height="{{printf "%.1f" .H}}" rx="1.5"/>
      {{if .Leader}}<path class="lead" d="M{{printf "%.1f" .X}},{{printf "%.1f" (mid .)}} L{{printf "%.1f" (add .X -5.0)}},{{printf "%.1f" .LabelY}}"/>{{end}}
      <text class="lbl" x="{{printf "%.1f" (add .X 17.0)}}" y="{{printf "%.1f" .LabelY}}" dominant-baseline="middle">{{.Label}}</text>
      <text class="amt" x="{{printf "%.1f" (add .X 17.0)}}" y="{{printf "%.1f" (add .LabelY 11.0)}}" dominant-baseline="middle">{{if .Sub}}{{.Sub}} · {{end}}{{commas .Tokens}} tok{{if .Priced}} · {{$.Money .Cost}}{{end}}{{if .Errors}} · {{commas .Errors}} err{{end}}</text>
    </g>
  {{if .Href}}</a>{{end}}
  {{end}}
</svg>
</div>

<div class="legend">
  {{range .Flow.Legend}}<a href="{{.Href}}"><span class="sw sw{{.Slot}}"></span>{{.Provider}} · {{commas .Requests}} req</a>{{end}}
</div>
<p class="note">Ribbon width is {{.Flow.Weighted}}; colour is the provider, carried
all the way across rather than lost at the first join — so a person's row tells you
which provider saw their prompts, not just that one did. Click a box to filter the
whole page to it; click it again to let go.
{{if .Flow.ByRequests}} Nothing in this slice recorded a token count — every request
failed before usage came back — so widths are request counts.{{end}}
{{if .Flow.Folded}} Columns that ran long are folded into a “more” box, which keeps
the widths adding up without pretending the tail is one thing.{{end}}
{{if not .WithContent}} Requests are labelled with their completion id because content
logging is off; with it on they are labelled with the redacted prompt.{{end}}</p>
{{end}}

{{with .Selected}}
<h2>This request</h2>
<div class="card">
  <dl>
    <dt>id</dt><dd>{{.ID}}</dd>
    <dt>time</dt><dd>{{stamp .Time}} UTC</dd>
    <dt>path</dt><dd>{{if .Backend}}{{.Backend}}{{else}}unattributed{{end}} →
      {{.Model}} → {{if .Team}}{{.Team}}{{else}}unattributed{{end}} →
      {{if .Subject}}{{.Subject}}{{else}}no identity recorded{{end}}</dd>
    <dt>policy</dt><dd>{{if .Policy}}<a href="{{($.Query.With "policy" .Policy).Encode}}">{{.Policy}}</a>{{else}}not recorded{{end}}</dd>
    <dt>tokens</dt><dd>{{commas .PromptTokens}} in · {{commas .CompletionTokens}} out{{if .Streamed}} · streamed{{end}}
      {{if .Cached}}<br>{{commas .CacheReadTokens}} read from cache · {{commas .CacheWriteTokens}} written to it{{end}}</dd>
    <dt>cost</dt><dd>{{if .Priced}}{{$.Money .Cost}}{{else}}unpriced — no rate configured for {{.Model}}{{end}}</dd>
    <dt>outcome</dt><dd>{{if .Error}}<span class="bad">{{.Error}}</span>{{else}}{{.StopReason}}{{end}}</dd>
    {{if .TraceID}}<dt>trace</dt><dd>{{.TraceID}}{{if .SpanID}} / {{.SpanID}}{{end}}</dd>{{end}}
    {{if .ToolsOffered}}<dt>tools offered</dt><dd>{{join .ToolsOffered ", "}}</dd>{{end}}
    {{if .ToolCalls}}<dt>tools called</dt><dd>{{range .ToolCalls}}<div>{{.Name}}{{if .Arguments}} <code>{{.Arguments}}</code>{{end}}</div>{{end}}</dd>{{end}}
    {{if .Redactions}}<dt>redacted</dt><dd>{{range $rule, $n := .Redactions}}{{$rule}} ×{{$n}} {{end}}</dd>{{end}}
    <dt>seq</dt><dd>{{.Seq}}{{if .Prev}} · follows {{short .Prev}}…{{end}}</dd>
  </dl>
  {{if .Prompt}}<pre>{{.Prompt}}</pre>{{end}}
  {{if .Completion}}<pre>{{.Completion}}</pre>{{end}}
</div>
<p class="note">Content appears only where logging it was deliberately turned on,
and only after redaction. Sealed values are not opened here; recovering one is a
command run by whoever holds the key.</p>
{{end}}

<h2>Spend by team</h2>
<table>
<tr><th>team</th><th class="n">requests</th><th class="n">prompt</th><th class="n">completion</th>
<th class="n">cost</th><th class="n">errors</th><th class="n">people</th><th>share</th></tr>
{{range .Teams}}
<tr class="row"><td><a href="{{($.Query.With "team" .Team).Encode}}">{{.Team}}</a></td>
<td class="n">{{commas .Requests}}</td><td class="n">{{commas .PromptTokens}}</td>
<td class="n">{{commas .ReplyTokens}}</td>
<td class="n">{{if and $.Priced .Priced}}{{$.Money .Cost}}{{else}}—{{end}}</td>
<td class="n">{{if .Errors}}<span class="bad">{{.Errors}}</span>{{else}}0{{end}}</td>
<td class="n">{{if .Subjects}}{{.Subjects}}{{else}}—{{end}}</td>
<td><span class="bar" style="width:{{.ShareOfTokensPercent}}%"></span> {{.ShareOfTokensPercent}}%</td></tr>
{{end}}
</table>
<p class="note">People is distinct subjects, which is only populated where callers
presented an identity token rather than a shared team key. A dash under cost means
at least one model in that row has no configured rate, so the row would understate.</p>

<h2>Models</h2>
<table>
<tr><th>model</th><th>provider</th><th class="n">requests</th><th class="n">tokens</th><th class="n">cost</th><th>rate</th></tr>
{{range .Models}}<tr class="row"><td><a href="{{($.Query.With "model" .Model).Encode}}">{{.Model}}</a></td>
<td><a href="{{($.Query.With "backend" .Backend).Encode}}">{{.Backend}}</a></td>
<td class="n">{{commas .Requests}}</td><td class="n">{{commas .Tokens}}</td>
<td class="n">{{if .Priced}}{{$.Money .Cost}}{{else}}—{{end}}</td>
<td>{{if .Rate}}{{.Rate}}{{else}}<span class="bad">unpriced</span>{{end}}</td></tr>{{end}}
</table>

<h2>Policy in force</h2>
<table>
<tr><th>fingerprint</th><th class="n">entries</th><th>from</th><th>to</th></tr>
{{range .Policies}}<tr class="row"><td>{{if $.Static}}{{.Fingerprint}}{{else}}<a href="{{($.Query.With "policy" .Fingerprint).Encode}}">{{.Fingerprint}}</a>{{end}}</td>
<td class="n">{{commas .Entries}}</td>
<td>{{stamp .From}}</td><td>{{stamp .To}}</td></tr>{{end}}
</table>
<p class="note">More than one row means the rules changed inside this window. The
entries above and below that boundary were not made under the same policy — click a
fingerprint to see the diagram for one of them.</p>

{{if .Tools}}
<h2>What the models were allowed to do, and did</h2>
<table>
<tr><th>tool</th><th class="n">offered on</th><th class="n">calls</th><th class="n">requests</th></tr>
{{range .Tools}}<tr class="row"><td>{{.Name}}</td>
<td class="n">{{if .Offered}}{{commas .Offered}}{{else}}—{{end}}</td>
<td class="n">{{if .Calls}}{{commas .Calls}}{{else}}0{{end}}</td>
<td class="n">{{if .Requests}}{{commas .Requests}}{{else}}—{{end}}</td></tr>{{end}}
</table>
<p class="note">Offered is how many requests made the tool available; calls is how
many times a model asked for it. A tool offered everywhere and never called is
permission nobody needed. Arguments are recorded only where content logging is on,
and pass through redaction like any other content — the names here are recorded
either way, because that a model called a tool is a fact worth keeping even when
what it passed is not.</p>
{{end}}

{{if .Redactions}}
<h2>Removed before anything was written down</h2>
<table>
<tr><th>rule</th><th class="n">values</th></tr>
{{range .Redactions}}<tr><td>{{.Name}}</td><td class="n">{{commas .Count}}</td></tr>{{end}}
</table>
<p class="note">Counts only. The values are not in this log — where a vault is
configured they are sealed to a key this process does not hold, and recovering
one is a command run by a person.</p>
{{end}}

<h2>Most recent {{len .Recent}}</h2>
<table>
<tr><th>time</th><th>team</th><th>person</th><th>model</th><th class="n">tokens</th><th class="n">cost</th><th>note</th></tr>
{{range .Recent}}
<tr class="row"><td><a href="{{($.Query.With "id" .ID).Encode}}">{{stamp .Time}}</a></td>
<td>{{if .Team}}<a href="{{($.Query.With "team" .Team).Encode}}">{{.Team}}</a>{{else}}—{{end}}</td>
<td>{{if .Subject}}<a href="{{($.Query.With "subject" .Subject).Encode}}">{{.Subject}}</a>{{else}}—{{end}}</td>
<td>{{.Model}}</td>
<td class="n">{{commas .PromptTokens}}/{{commas .CompletionTokens}}</td>
<td class="n">{{if .Priced}}{{$.Money .Cost}}{{else}}—{{end}}</td>
<td class="w">{{if .Error}}<span class="bad">{{.Error}}</span>{{else}}{{.StopReason}}{{end}}</td></tr>
{{end}}
</table>
<p class="note">A time is a link to that one request.</p>

<h2>What this is</h2>
<p class="note">
A proof of concept, served read-only over loopback from the log on disk. It holds
no state and has no database — point it at a segment downloaded from an archive
during an incident and it reads that instead. Filters are query parameters applied
during the read, so a link to a filtered view is a link to a question, and it
survives being pasted into a ticket.
</p>
<p class="note">
It shows what the log contains, which is metadata unless content logging was
deliberately turned on, and which has already passed through redaction. It never
opens the vault. Aggregates over time belong in whatever already receives OTLP;
what is here is the part a time-series tool does not have — the chain, where policy
changed underneath it, and the path one request actually took.
</p>
`))

// Render writes the page for one slice of the log, and returns what it counted.
//
// This is the same page the server renders. Anything producing a durable
// artefact — a file for a ticket, a report inside an evidence package — goes
// through here rather than reimplementing the summary, so the artefact and the
// page can never disagree about what the log says.
func Render(w io.Writer, path string, key []byte, q Query, prices Prices) (*Summary, error) {
	s, err := Summarise(path, key, q, prices)
	if err != nil {
		return nil, err
	}
	if err := page.Execute(w, s); err != nil {
		return nil, err
	}
	return s, nil
}

// query links are the filter navigation: href="?team=x" and friends. They are
// generated in the template and in the flow diagram, and both are right to do
// so when something is serving. In a file they are a lie — a reader clicks and
// nothing happens, which is worse than an element that never looked clickable.
//
// Stripping the attribute rather than the element leaves the anchor in place
// as plain text, so the layout is identical and the page is not re-authored
// for the static case. Anchored to href="? so it can only ever match the
// filter links, never a real destination.
var queryLink = regexp.MustCompile(`\s*href="\?[^"]*"`)

func inert(b []byte) []byte { return queryLink.ReplaceAll(b, nil) }

// RenderStatic writes the page as a standalone file rather than as a served
// response: filter navigation is removed, because there will be nothing behind
// it. Both file-producing paths go through here so neither can drift into
// shipping links that do nothing.
func RenderStatic(w io.Writer, path string, key []byte, q Query, prices Prices) (*Summary, error) {
	s, err := Summarise(path, key, q, prices)
	if err != nil {
		return nil, err
	}
	s.Static = true
	var buf bytes.Buffer
	if err := page.Execute(&buf, s); err != nil {
		return nil, err
	}
	if _, err := w.Write(inert(buf.Bytes())); err != nil {
		return nil, err
	}
	return s, nil
}

// WriteFile renders the whole log to a self-contained HTML file and returns the
// number of bytes written.
//
// It has no script and no external reference, so it can be attached to a
// ticket, mailed to an auditor, or opened years later on a machine that has
// never heard of switchboard.
func WriteFile(out, path string, key []byte, prices Prices) (int, error) {
	var buf bytes.Buffer
	if _, err := RenderStatic(&buf, path, key, Query{}, prices); err != nil {
		return 0, err
	}
	body := buf.Bytes()
	// 0600: it carries spend, identities and — where content logging is on —
	// redacted prompts. The serving path refuses to bind a public interface for
	// the same reason; the file form should not be laxer than the page it is.
	if err := os.WriteFile(out, body, 0o600); err != nil {
		return 0, err
	}
	return len(body), nil
}
