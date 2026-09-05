package reconcile

import (
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// ReadInvoice reads a provider export, choosing a reader from its header.
//
// Two shapes are understood: switchboard's own normalised CSV, and an AWS Cost
// and Usage Report. Anything else is a conversion somebody has to write, and
// the format to convert to is the normalised one — it is four columns and
// documented in docs/reconciliation.md, because a gateway that could only be
// reconciled against one cloud would be reconcilable by almost nobody.
func ReadInvoice(path, tagKey string) (Invoice, error) {
	f, err := os.Open(path)
	if err != nil {
		return Invoice{}, err
	}
	defer f.Close()
	inv, err := parseInvoice(f, tagKey)
	inv.Source = path
	return inv, err
}

func parseInvoice(r io.Reader, tagKey string) (Invoice, error) {
	cr := csv.NewReader(r)
	// CUR exports are wide and ragged between versions; a fixed field count
	// would reject a valid file over a column nothing here reads.
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true

	head, err := cr.Read()
	if err == io.EOF {
		return Invoice{}, fmt.Errorf("the export is empty")
	}
	if err != nil {
		return Invoice{}, err
	}
	idx := map[string]int{}
	for i, h := range head {
		idx[normHeader(h)] = i
	}

	switch {
	case has(idx, "line_item_usage_type"):
		return readCUR(cr, idx, tagKey)
	case has(idx, "month") && has(idx, "kind"):
		return readNormalised(cr, idx)
	}
	return Invoice{}, fmt.Errorf("unrecognised export: the header names neither %q (a Cost and Usage Report) "+
		"nor %q and %q (switchboard's normalised format, see docs/reconciliation.md)",
		"line_item_usage_type", "month", "kind")
}

// normHeader folds the two CUR column spellings and the normalised format onto
// one key. CUR 2.0 writes line_item_usage_type; the legacy export writes
// lineItem/UsageType for the same column.
func normHeader(h string) string {
	h = strings.TrimSpace(h)
	h = strings.ReplaceAll(h, "/", "_")
	var b strings.Builder
	for i, r := range h {
		switch {
		case r >= 'A' && r <= 'Z':
			// Insert a break at a camel-case hump so UsageType and usage_type
			// land on the same key.
			if i > 0 && b.Len() > 0 && !strings.HasSuffix(b.String(), "_") {
				prev := rune(h[i-1])
				if prev >= 'a' && prev <= 'z' || prev >= '0' && prev <= '9' {
					b.WriteByte('_')
				}
			}
			b.WriteRune(r + 32)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func has(idx map[string]int, k string) bool { _, ok := idx[k]; return ok }

func field(rec []string, idx map[string]int, name string) string {
	i, ok := idx[name]
	if !ok || i >= len(rec) {
		return ""
	}
	return strings.TrimSpace(rec[i])
}

// readNormalised reads switchboard's own four-column format.
func readNormalised(cr *csv.Reader, idx map[string]int) (Invoice, error) {
	inv := Invoice{}
	line := 1
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return inv, err
		}
		line++
		month := field(rec, idx, "month")
		model := field(rec, idx, "model")
		kind := Kind(strings.ToLower(field(rec, idx, "kind")))
		if month == "" && model == "" {
			continue
		}
		if !validMonth(month) {
			return inv, fmt.Errorf("line %d: month %q is not YYYY-MM", line, month)
		}
		if !validKind(kind) {
			return inv, fmt.Errorf("line %d: kind %q is not one of input, output, cache_write, cache_read",
				line, kind)
		}
		tok, err := strconv.ParseFloat(orZero(field(rec, idx, "tokens")), 64)
		if err != nil {
			return inv, fmt.Errorf("line %d: tokens %q is not a number", line, field(rec, idx, "tokens"))
		}
		l := Line{Month: month, Model: model, Kind: kind, Tokens: int64(math.Round(tok))}
		if c := field(rec, idx, "cost"); c != "" {
			v, err := strconv.ParseFloat(c, 64)
			if err != nil {
				return inv, fmt.Errorf("line %d: cost %q is not a number", line, c)
			}
			l.Cost, l.CostKnown = v, true
		}
		if t := field(rec, idx, "team"); t != "" {
			l.Team = t
			inv.TeamsPresent = true
		}
		if cur := field(rec, idx, "currency"); cur != "" && inv.Currency == "" {
			inv.Currency = cur
		}
		inv.Lines = append(inv.Lines, l)
	}
	return inv, nil
}

// readCUR reads an AWS Cost and Usage Report.
//
// CUR carries no per-request line item and no request id — it aggregates by
// usage type over an hour or a day — so what comes out of here is tokens by
// model and month, and there is no way to make it requests.
func readCUR(cr *csv.Reader, idx map[string]int, tagKey string) (Invoice, error) {
	inv := Invoice{}
	teamCol, teamHeader := findTagColumn(idx, tagKey)
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return inv, err
		}
		usage := field(rec, idx, "line_item_usage_type")
		if usage == "" {
			continue
		}
		// A full CUR carries every service in the account. Rows that are not
		// this provider's inference are not ours to interpret and are not a
		// gap in understanding, so they are passed over rather than counted.
		product := strings.ToLower(field(rec, idx, "line_item_product_code"))
		if product != "" && !strings.Contains(product, "bedrock") {
			continue
		}
		model, kind, ok := parseUsageType(usage)
		if !ok {
			if product != "" {
				// Bedrock, and not a token charge: a guardrail, storage, an
				// evaluation. Counted so the report can say the export was not
				// read in full rather than implying it was.
				inv.Skipped++
			}
			continue
		}
		month := field(rec, idx, "line_item_usage_start_date")
		if len(month) >= 7 {
			month = month[:7]
		}
		if !validMonth(month) {
			inv.Skipped++
			continue
		}
		amount, err := strconv.ParseFloat(orZero(field(rec, idx, "line_item_usage_amount")), 64)
		if err != nil {
			inv.Skipped++
			continue
		}
		l := Line{Month: month, Model: model, Kind: kind, Tokens: int64(math.Round(amount))}
		if c := field(rec, idx, "line_item_unblended_cost"); c != "" {
			if v, err := strconv.ParseFloat(c, 64); err == nil {
				l.Cost, l.CostKnown = v, true
			}
		}
		if teamCol >= 0 && teamCol < len(rec) {
			if t := strings.TrimSpace(rec[teamCol]); t != "" {
				l.Team = t
				inv.TeamsPresent = true
			}
		}
		if cur := field(rec, idx, "line_item_currency_code"); cur != "" && inv.Currency == "" {
			inv.Currency = cur
		}
		inv.Lines = append(inv.Lines, l)
	}

	// Absent and empty are different claims about attribution, and only one of
	// them is a finding about this deployment.
	switch {
	case teamCol < 0 && tagKey != "":
		inv.Notes = append(inv.Notes, fmt.Sprintf(
			"No column in this export carries the %q tag, so per-team reconciliation is unknown here "+
				"rather than absent. A tag must be activated in Billing → Cost allocation tags before it "+
				"appears in CUR at all.", tagKey))
	case teamCol >= 0 && !inv.TeamsPresent:
		inv.Notes = append(inv.Notes, fmt.Sprintf(
			"The export carries a %s column and every row of it is empty. The tag is activated and "+
				"nothing is being tagged, which is what a missing sts:TagSession looks like on the bill.",
			teamHeader))
	}
	return inv, nil
}

// findTagColumn looks for a cost allocation tag column carrying the attribution
// key. CUR exposes them as resource_tags_<key> and iam_principal_<key>, and
// session tags — the ones a gateway sets — arrive under the second.
func findTagColumn(idx map[string]int, key string) (int, string) {
	if key == "" {
		return -1, ""
	}
	want := strings.ToLower(key)
	best, header := -1, ""
	for h, i := range idx {
		if !strings.HasSuffix(h, "_"+want) {
			continue
		}
		switch {
		case strings.HasPrefix(h, "iam_principal"):
			return i, h
		case strings.HasPrefix(h, "resource_tags"):
			best, header = i, h
		}
	}
	return best, header
}

// tokenMarkers are the substrings AWS puts in a usage type to name a token
// type, longest and most specific first. Cache markers must be tested before
// the plain ones or a cache-read row reads as input.
var tokenMarkers = []struct {
	marker string
	kind   Kind
}{
	{"cache-read-input-token-count", CacheRead},
	{"cache-write-input-token-count", CacheWrite},
	{"input-tokens", Input},
	{"output-tokens", Output},
}

// region matches the code CUR prefixes a usage type with: USE1, EUW1, APNE1.
var region = regexp.MustCompile(`^[A-Za-z]{2,5}[0-9]$`)

// parseUsageType pulls the model and the token type out of a CUR usage type.
//
// The documented shapes are {region}-{model}-{token-type} with optional
// -{tier} and -cross-region-global suffixes, and a -mantle- infix for the
// bedrock-mantle endpoint. What comes back is the model exactly as AWS spells
// it — "Claude4.6Sonnet" — which is neither the name callers ask for nor the
// model id this gateway sent. Bridging that is a mapping somebody declares.
func parseUsageType(s string) (string, Kind, bool) {
	lower := strings.ToLower(s)
	for _, tm := range tokenMarkers {
		i := strings.Index(lower, tm.marker)
		if i < 0 {
			continue
		}
		// ToLower does not change length for the ASCII these identifiers are
		// made of, so the index into the lowered string is the index into the
		// original and the model keeps the case AWS gave it.
		head := strings.Trim(s[:i], "-")
		if seg, rest, ok := strings.Cut(head, "-"); ok && region.MatchString(seg) {
			head = rest
		} else if region.MatchString(head) {
			head = ""
		}
		head = strings.TrimSuffix(strings.Trim(head, "-"), "-mantle")
		head = strings.Trim(head, "-")
		if head == "" {
			return "", "", false
		}
		return head, tm.kind, true
	}
	return "", "", false
}

func validKind(k Kind) bool {
	for _, want := range Kinds {
		if k == want {
			return true
		}
	}
	return false
}

var monthRE = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])$`)

func validMonth(s string) bool { return monthRE.MatchString(s) }

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}
