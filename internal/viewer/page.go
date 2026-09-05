package viewer

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
)

// Serve renders the log at addr until the listener is closed.
//
// Loopback unless explicitly overridden: this page shows who spent what and,
// where content logging is on, redacted prompts. It is not something to put on
// an interface by accident.
func Serve(addr, path string, key []byte, allowRemote bool) (*http.Server, net.Listener, error) {
	if !allowRemote && !isLoopback(addr) {
		return nil, nil, fmt.Errorf(
			"refusing to bind %s: this page shows spend and redacted content, and it "+
				"has no authentication. Bind loopback and forward a port, or pass "+
				"-allow-remote if you have decided otherwise", addr)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		s, err := Summarise(path, key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// No third-party anything: this has to work on a machine with no route
		// to the internet, which is where the interesting deployments are.
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
}).Parse(`<!doctype html>
<meta charset="utf-8">
<title>switchboard — audit log</title>
<style>
  :root { color-scheme: light dark; --line:#d5d8de; --dim:#606774; --bad:#b3261e; --ok:#186a3b; }
  @media (prefers-color-scheme: dark) { :root { --line:#333842; --dim:#98a0ae; --bad:#f2b8b5; --ok:#7ddba3; } }
  body { font: 14px/1.5 ui-monospace, "SF Mono", Menlo, monospace; margin: 0 auto; padding: 2rem 1.5rem; max-width: 60rem; }
  h1 { font-size: 1.1rem; margin: 0 0 .2rem; }
  h2 { font-size: .8rem; text-transform: uppercase; letter-spacing: .08em; color: var(--dim);
       border-bottom: 1px solid var(--line); padding-bottom: .3rem; margin: 2rem 0 .6rem; }
  .sub { color: var(--dim); margin: 0 0 1.4rem; }
  table { border-collapse: collapse; width: 100%; }
  th { text-align: left; font-weight: 600; color: var(--dim); font-size: .8rem; padding: .3rem .6rem .3rem 0; }
  td { padding: .25rem .6rem .25rem 0; border-top: 1px solid var(--line); white-space: nowrap; }
  td.n, th.n { text-align: right; }
  td.w { white-space: normal; word-break: break-word; }
  .bar { display:inline-block; height:.55rem; background: currentColor; opacity:.35; vertical-align: middle; }
  .ok { color: var(--ok); } .bad { color: var(--bad); }
  .note { color: var(--dim); font-size: .82rem; margin: .5rem 0 0; }
  .banner { border:1px solid var(--line); border-left-width:3px; padding:.6rem .8rem; margin:0 0 1.5rem; }
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
verify, they are numbers from a file someone may have edited.</p>
</div>

<h2>Spend by team</h2>
<table>
<tr><th>team</th><th class="n">requests</th><th class="n">prompt</th><th class="n">completion</th><th class="n">errors</th><th class="n">people</th><th>share</th></tr>
{{range .Teams}}
<tr><td>{{.Team}}</td><td class="n">{{commas .Requests}}</td><td class="n">{{commas .PromptTokens}}</td>
<td class="n">{{commas .ReplyTokens}}</td><td class="n">{{if .Errors}}<span class="bad">{{.Errors}}</span>{{else}}0{{end}}</td>
<td class="n">{{if .Subjects}}{{.Subjects}}{{else}}—{{end}}</td>
<td><span class="bar" style="width:{{.ShareOfTokensPercent}}%"></span> {{.ShareOfTokensPercent}}%</td></tr>
{{end}}
</table>
<p class="note">People is distinct subjects, which is only populated where callers
presented an identity token rather than a shared team key.</p>

<h2>Models</h2>
<table>
<tr><th>model</th><th class="n">requests</th><th class="n">tokens</th></tr>
{{range .Models}}<tr><td>{{.Model}}</td><td class="n">{{commas .Requests}}</td><td class="n">{{commas .Tokens}}</td></tr>{{end}}
</table>

<h2>Policy in force</h2>
<table>
<tr><th>fingerprint</th><th class="n">entries</th><th>from</th><th>to</th></tr>
{{range .Policies}}<tr><td>{{.Fingerprint}}</td><td class="n">{{commas .Entries}}</td>
<td>{{stamp .From}}</td><td>{{stamp .To}}</td></tr>{{end}}
</table>
<p class="note">More than one row means the rules changed inside this window. The
entries above and below that boundary were not made under the same policy.</p>

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
<tr><th>time</th><th>team</th><th>subject</th><th>model</th><th class="n">tokens</th><th>note</th></tr>
{{range .Recent}}
<tr><td>{{stamp .Time}}</td><td>{{if .Team}}{{.Team}}{{else}}—{{end}}</td>
<td>{{if .Subject}}{{.Subject}}{{else}}—{{end}}</td><td>{{.Model}}</td>
<td class="n">{{commas .PromptTokens}}/{{commas .CompletionTokens}}</td>
<td class="w">{{if .Error}}<span class="bad">{{.Error}}</span>{{else}}{{.StopReason}}{{end}}</td></tr>
{{end}}
</table>

<h2>What this is</h2>
<p class="note">
A proof of concept, served read-only over loopback from the log on disk. It holds
no state and has no database — point it at a segment downloaded from an archive
during an incident and it reads that instead.
</p>
<p class="note">
It shows what the log contains, which is metadata unless content logging was
deliberately turned on, and which has already passed through redaction. It never
opens the vault. Aggregates over time belong in whatever already receives OTLP;
what is here is the part a time-series tool does not have — the chain, and where
policy changed underneath it.
</p>
`))
