package reconcile

import (
	"strings"
	"testing"
)

// The usage type is the only place a CUR row names the model, and the shapes
// come straight from AWS's own documentation. Getting this wrong reconciles the
// right numbers against the wrong model.
func TestUsageTypeShapesFromTheDocumentation(t *testing.T) {
	cases := []struct {
		usage string
		model string
		kind  Kind
	}{
		{"USE1-Claude4.6Sonnet-input-tokens", "Claude4.6Sonnet", Input},
		{"USE1-Claude4.6Sonnet-cache-read-input-token-count", "Claude4.6Sonnet", CacheRead},
		{"USE1-Claude4.6Sonnet-cache-write-input-token-count", "Claude4.6Sonnet", CacheWrite},
		{"USE1-Claude4.6Sonnet-output-tokens-cross-region-global", "Claude4.6Sonnet", Output},
		{"USE1-Nova2.0Lite-input-tokens-flex", "Nova2.0Lite", Input},
		{"USE1-gpt-oss-120b-output-tokens-priority", "gpt-oss-120b", Output},
		{"USE1-openai.gpt-oss-120b-mantle-input-tokens-standard", "openai.gpt-oss-120b", Input},
		{"EUW1-Claude4.6Sonnet-input-tokens", "Claude4.6Sonnet", Input},
		{"APNE1-Claude4.6Sonnet-input-tokens", "Claude4.6Sonnet", Input},
	}
	for _, c := range cases {
		model, kind, ok := parseUsageType(c.usage)
		if !ok {
			t.Errorf("%s: not recognised", c.usage)
			continue
		}
		if model != c.model || kind != c.kind {
			t.Errorf("%s → %q/%s, want %q/%s", c.usage, model, kind, c.model, c.kind)
		}
	}
}

// A cache row must not read as input. The two are priced an order of magnitude
// apart, so this mistake balances a month that does not balance.
func TestCacheUsageTypesDoNotReadAsInput(t *testing.T) {
	_, kind, ok := parseUsageType("USE1-Claude4.6Sonnet-cache-read-input-token-count")
	if !ok || kind != CacheRead {
		t.Fatalf("kind = %s, ok = %v", kind, ok)
	}
}

// Anything that is not a token charge is not a model, and guessing one would
// put a fictional row in front of a reviewer.
func TestNonTokenUsageTypesAreRefused(t *testing.T) {
	for _, u := range []string{"USE1-GuardrailsTextUnit", "USE1-DataStorage-ByteHrs", "Requests"} {
		if _, _, ok := parseUsageType(u); ok {
			t.Errorf("%s was read as a token charge", u)
		}
	}
}

const curHeader = "line_item_product_code,line_item_usage_type,line_item_usage_start_date," +
	"line_item_usage_amount,line_item_unblended_cost,line_item_currency_code"

func TestCURIsReadAtTheModelAndMonthGrain(t *testing.T) {
	csv := curHeader + "\n" +
		"AmazonBedrock,USE1-Claude4.6Sonnet-input-tokens,2026-08-04T00:00:00Z,1000000,15.00,USD\n" +
		"AmazonBedrock,USE1-Claude4.6Sonnet-input-tokens,2026-08-05T00:00:00Z,500000,7.50,USD\n" +
		"AmazonBedrock,USE1-Claude4.6Sonnet-output-tokens,2026-08-05T00:00:00Z,200000,15.00,USD\n"

	inv, err := parseInvoice(strings.NewReader(csv), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Lines) != 3 {
		t.Fatalf("lines = %+v", inv.Lines)
	}
	if inv.Currency != "USD" {
		t.Errorf("currency = %q", inv.Currency)
	}
	for _, l := range inv.Lines {
		if l.Month != "2026-08" {
			t.Errorf("month = %q, want the day rolled up to its month", l.Month)
		}
		if !l.CostKnown {
			t.Error("a row carrying cost was read as not carrying it")
		}
	}
}

// A full CUR holds every service in the account. Rows that are not this
// provider's inference are not a gap in understanding.
func TestOtherServicesArePassedOverAndBedrockOddsAreCounted(t *testing.T) {
	csv := curHeader + "\n" +
		"AmazonEC2,USE1-BoxUsage:m5.large,2026-08-04T00:00:00Z,720,80.00,USD\n" +
		"AmazonBedrock,USE1-GuardrailsTextUnit,2026-08-04T00:00:00Z,4000,3.00,USD\n" +
		"AmazonBedrock,USE1-Claude4.6Sonnet-input-tokens,2026-08-04T00:00:00Z,1000000,15.00,USD\n"

	inv, err := parseInvoice(strings.NewReader(csv), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Lines) != 1 {
		t.Fatalf("lines = %+v", inv.Lines)
	}
	if inv.Skipped != 1 {
		t.Errorf("skipped = %d, want the guardrail row counted and the EC2 row passed over", inv.Skipped)
	}
}

// The legacy export spells the same column lineItem/UsageType. Refusing it
// would send somebody to rewrite a file over punctuation.
func TestLegacyCURColumnNamesAreAccepted(t *testing.T) {
	csv := "lineItem/ProductCode,lineItem/UsageType,lineItem/UsageStartDate,lineItem/UsageAmount\n" +
		"AmazonBedrock,USE1-Claude4.6Sonnet-input-tokens,2026-08-04T00:00:00Z,1000000\n"
	inv, err := parseInvoice(strings.NewReader(csv), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Lines) != 1 || inv.Lines[0].Tokens != 1_000_000 {
		t.Fatalf("lines = %+v", inv.Lines)
	}
	if inv.Lines[0].CostKnown {
		t.Error("an export with no cost column was read as reporting a cost")
	}
}

// An export with no tag column cannot say anything about teams. That is
// unknown, and reporting it as untagged traffic would be a finding about this
// deployment drawn from a missing column.
func TestAMissingTagColumnIsUnknownNotUntagged(t *testing.T) {
	csv := curHeader + "\n" +
		"AmazonBedrock,USE1-Claude4.6Sonnet-input-tokens,2026-08-04T00:00:00Z,1000000,15.00,USD\n"
	inv, err := parseInvoice(strings.NewReader(csv), "team")
	if err != nil {
		t.Fatal(err)
	}
	if inv.TeamsPresent {
		t.Error("teams reported present with no tag column")
	}
	if len(inv.Notes) != 1 || !strings.Contains(inv.Notes[0], "unknown") {
		t.Fatalf("notes = %v", inv.Notes)
	}
}

// A tag column that is present and empty on every row is the signature of the
// failure docs/cost-attribution.md names first: the assume succeeded and
// sts:TagSession was missing, so everything still bills to one identity.
func TestAnActivatedTagWithNoValuesIsCalledOut(t *testing.T) {
	csv := curHeader + ",iam_principal_team\n" +
		"AmazonBedrock,USE1-Claude4.6Sonnet-input-tokens,2026-08-04T00:00:00Z,1000000,15.00,USD,\n"
	inv, err := parseInvoice(strings.NewReader(csv), "team")
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Notes) != 1 || !strings.Contains(inv.Notes[0], "TagSession") {
		t.Fatalf("notes = %v", inv.Notes)
	}
}

// Session tags are what a gateway sets, and they arrive under iamPrincipal.
// Where both columns exist that one wins.
func TestSessionTagsAreReadAndPreferred(t *testing.T) {
	csv := curHeader + ",resource_tags_team,iam_principal_team\n" +
		"AmazonBedrock,USE1-Claude4.6Sonnet-input-tokens,2026-08-04T00:00:00Z,1000000,15.00,USD,infra,search\n"
	inv, err := parseInvoice(strings.NewReader(csv), "team")
	if err != nil {
		t.Fatal(err)
	}
	if !inv.TeamsPresent || inv.Lines[0].Team != "search" {
		t.Fatalf("team = %q, want the session tag", inv.Lines[0].Team)
	}
}

func TestNormalisedFormatRoundTrips(t *testing.T) {
	csv := "month,model,kind,tokens,cost,currency,team\n" +
		"2026-08,Claude4.6Sonnet,input,1000000,15.00,USD,search\n" +
		"2026-08,Claude4.6Sonnet,cache_read,4000000,6.00,USD,search\n"
	inv, err := parseInvoice(strings.NewReader(csv), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Lines) != 2 || inv.Lines[1].Kind != CacheRead {
		t.Fatalf("lines = %+v", inv.Lines)
	}
	if !inv.TeamsPresent || inv.Currency != "USD" {
		t.Errorf("teams = %v, currency = %q", inv.TeamsPresent, inv.Currency)
	}
}

// A typo in a token type must stop the run. Silently dropping the row would
// take tokens out of the comparison and report a gap that is a parse error.
func TestAnUnknownTokenTypeIsAnError(t *testing.T) {
	csv := "month,model,kind,tokens\n2026-08,Claude4.6Sonnet,inputs,1000000\n"
	if _, err := parseInvoice(strings.NewReader(csv), ""); err == nil {
		t.Fatal("an unknown kind was accepted")
	}
}

func TestAnUnrecognisedExportSaysWhatItWanted(t *testing.T) {
	_, err := parseInvoice(strings.NewReader("date,service,amount\n2026-08-01,bedrock,100\n"), "")
	if err == nil || !strings.Contains(err.Error(), "reconciliation.md") {
		t.Fatalf("err = %v", err)
	}
}

// Two local models resembling one billing name is ambiguity, and picking one is
// how a suggestion becomes the wrong mapping.
func TestAmbiguousResemblanceSuggestsNothing(t *testing.T) {
	if got := suggest("Claude4.6Sonnet", []string{"claude-sonnet-3", "claude-sonnet-4"}); got != "" {
		t.Errorf("suggest = %q, want nothing", got)
	}
	if got := suggest("Claude4.6Sonnet", []string{"claude-sonnet", "titan"}); got != "claude-sonnet" {
		t.Errorf("suggest = %q", got)
	}
}
