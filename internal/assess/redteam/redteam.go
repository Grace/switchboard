// Package redteam reads the output of an adversarial testing tool.
//
// It exists because the assurance rows in an assessment are otherwise a
// checkbox. "Has this deployment been adversarially tested" answered by a
// person ticking yes is worth nothing to a reviewer; answered by a report
// naming the tool, its version, when it ran and how many probes it failed, it
// is evidence. The difference is the same one the rest of switchboard turns on:
// something observed rather than something asserted.
//
// The tools this reads already exist and already run in people's pipelines —
// promptfoo in CI, garak against a model. What has been missing is anywhere for
// their output to go. This is that place.
//
// Only promptfoo is implemented. That is deliberate rather than partial: a
// parser written against a format nobody has verified produces confident
// misreadings of somebody's security evidence, which is worse than declining to
// read it. Adding garak means obtaining a real report and writing the parser
// against it, and Read says so when handed something it does not recognise.
package redteam

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// Result is what a red-team run says, reduced to what an assessment needs.
type Result struct {
	// Tool and Version identify what produced this.
	Tool    string
	Version string
	// Ran is when the run happened, from the report itself rather than the
	// file's mtime — a report copied between machines keeps its timestamp and
	// loses its mtime, and the timestamp is the one that means something.
	Ran time.Time

	Passed int
	Failed int
	Errors int
}

// Total is how many assertions the run made.
func (r Result) Total() int { return r.Passed + r.Failed + r.Errors }

// Age is how long ago the run happened, relative to now.
func (r Result) Age(now time.Time) time.Duration {
	if r.Ran.IsZero() {
		return 0
	}
	return now.Sub(r.Ran)
}

// StaleAfter is when a red-team result stops being current assurance.
//
// It is a switchboard default, not a rule from any regime. Regimes expect
// testing to be periodic without agreeing on a period, so this is a threshold
// for wording a sentence — the report says how old the evidence is and lets the
// reviewer judge, rather than silently scoring a two-year-old run as current.
const StaleAfter = 365 * 24 * time.Hour

// Describe renders the one-line detail an assessment carries.
//
// It states the age unconditionally. A reviewer's first question about a
// security test is when it ran, and a sentence that omits it reads as an
// attempt not to say.
//
// It returns an unpunctuated clause. The caller is embedding this in a sentence
// of its own and supplies the full stop; ending it here produces "3 failed.."
// in the one place it is actually used.
func (r Result) Describe(now time.Time) string {
	when := "at an unrecorded time"
	if !r.Ran.IsZero() {
		when = r.Ran.UTC().Format("2006-01-02")
		if age := r.Age(now); age > StaleAfter {
			when += fmt.Sprintf(" (%d days ago — older than %d days, so this is a "+
				"record of testing rather than current assurance)",
				int(age.Hours()/24), int(StaleAfter.Hours()/24))
		} else if age > 0 {
			when += fmt.Sprintf(" (%d days ago)", int(age.Hours()/24))
		}
	}

	tool := r.Tool
	if r.Version != "" {
		tool += " " + r.Version
	}

	if r.Total() == 0 {
		return fmt.Sprintf("%s, %s. The report records no assertions, so it "+
			"evidences that the tool ran and nothing about what it found", tool, when)
	}
	out := fmt.Sprintf("%s, %s: %d of %d assertions passed",
		tool, when, r.Passed, r.Total())
	if r.Failed > 0 {
		out += fmt.Sprintf(", %d failed", r.Failed)
	}
	if r.Errors > 0 {
		out += fmt.Sprintf(", %d errored", r.Errors)
	}
	return out
}

// Clean reports whether the run found nothing. A run with failures is still
// evidence that testing happened; it is the caller's business whether the
// failures matter.
func (r Result) Clean() bool { return r.Failed == 0 && r.Errors == 0 }

// ReadFile reads a report from disk.
func ReadFile(path string) (Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	r, err := Read(f)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

// Read parses a report.
//
// promptfoo has moved its output shape between versions, so the fields are
// looked for in more than one place. What it will not do is guess: a document
// with no recognisable statistics is an error naming what was looked for,
// because the alternative is reporting a deployment as tested on the strength
// of a file that might be anything.
func Read(in io.Reader) (Result, error) {
	data, err := io.ReadAll(in)
	if err != nil {
		return Result{}, err
	}

	var doc promptfooDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return Result{}, fmt.Errorf("not JSON: %w", err)
	}

	// results.stats is the current shape; stats at the top level is the older
	// one. Either may be absent from a document that is not a promptfoo report
	// at all, which is the case that must fail rather than default.
	stats := doc.Results.Stats
	if stats == nil {
		stats = doc.Stats
	}
	if stats == nil {
		return Result{}, fmt.Errorf("no promptfoo statistics found: looked for " +
			"results.stats and stats, each carrying successes/failures. If this is " +
			"a garak or PyRIT report, switchboard cannot read it yet — it declines " +
			"rather than guess at a format it has not been written against")
	}

	res := Result{
		Tool:    "promptfoo",
		Version: doc.Results.Version,
		Passed:  stats.Successes,
		Failed:  stats.Failures,
		Errors:  stats.Errors,
	}
	if res.Version == "" && doc.Version != "" {
		res.Version = doc.Version
	}
	res.Ran = firstTime(doc.Results.Timestamp, doc.Timestamp, doc.CreatedAt)
	return res, nil
}

type promptfooDoc struct {
	Version   string          `json:"version"`
	Timestamp string          `json:"timestamp"`
	CreatedAt string          `json:"createdAt"`
	Stats     *promptfooStats `json:"stats"`
	Results   struct {
		Version   string          `json:"version"`
		Timestamp string          `json:"timestamp"`
		Stats     *promptfooStats `json:"stats"`
	} `json:"results"`
}

type promptfooStats struct {
	Successes int `json:"successes"`
	Failures  int `json:"failures"`
	Errors    int `json:"errors"`
}

// firstTime takes the first value that parses, so a report carrying its
// timestamp under any of the names promptfoo has used still dates correctly.
func firstTime(candidates ...string) time.Time {
	layouts := []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		for _, l := range layouts {
			if t, err := time.Parse(l, c); err == nil {
				return t.UTC()
			}
		}
	}
	return time.Time{}
}

// Version is unmarshalled as a string, but promptfoo has emitted it as a
// number. UnmarshalJSON accepts both rather than failing the whole document
// over a field that is only ever printed.
func (d *promptfooDoc) UnmarshalJSON(b []byte) error {
	type alias promptfooDoc
	var raw struct {
		alias
		Version json.RawMessage `json:"version"`
		Results struct {
			Version   json.RawMessage `json:"version"`
			Timestamp string          `json:"timestamp"`
			Stats     *promptfooStats `json:"stats"`
		} `json:"results"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*d = promptfooDoc(raw.alias)
	d.Version = looseString(raw.Version)
	d.Results.Version = looseString(raw.Results.Version)
	d.Results.Timestamp = raw.Results.Timestamp
	d.Results.Stats = raw.Results.Stats
	return nil
}

func looseString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String()
	}
	return ""
}
