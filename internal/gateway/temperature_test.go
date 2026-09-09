package gateway

import (
	"testing"
	"time"
)

// A false positive is the expensive error: dropping a temperature the caller
// chose changes their output without telling them, which is worse than the 400
// it replaces. So the match requires the provider to name the field, not merely
// to be unhappy.
func TestRejectsTemperatureRequiresTheProviderToNameTheField(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"openai reasoning model", 400,
			`{"error":{"message":"Unsupported value: 'temperature' does not support 0.7 with this model."}}`, true},
		{"phrased as not supported", 400,
			`{"error":{"message":"temperature is not supported for this model"}}`, true},
		{"uppercase from the provider", 400,
			`{"error":{"message":"Temperature Is Not Supported For This Model"}}`, true},

		// Everything below must leave the request untouched.
		{"a different unsupported parameter", 400,
			`{"error":{"message":"Unsupported parameter: 'top_k' is not supported"}}`, false},
		{"an account that cannot pay", 400,
			`{"error":{"message":"Your credit balance is too low"}}`, false},
		{"malformed request", 400, `{"error":{"message":"messages: field required"}}`, false},
		{"mentions temperature incidentally", 400,
			`{"error":{"message":"the temperature of the room is irrelevant"}}`, false},
		{"rate limited", 429,
			`{"error":{"message":"temperature is not supported"}}`, false},
		{"server error", 500,
			`{"error":{"message":"temperature is not supported"}}`, false},
		{"empty", 400, ``, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := rejectsTemperature(tc.status, []byte(tc.body)); got != tc.want {
				t.Errorf("rejectsTemperature = %v, want %v", got, tc.want)
			}
		})
	}
}

// The point of remembering: the 400 is paid once per model, not once per
// request. Without this the gateway would round-trip a doomed request every
// time a caller set a temperature against a reasoning model.
func TestTemperatureTableRemembersPerModel(t *testing.T) {
	tt := newTemperatureTable()
	if tt.omit("openai", "gpt-5-nano") {
		t.Fatal("omitting before anything was observed")
	}
	tt.observe("openai", "gpt-5-nano")

	if !tt.omit("openai", "gpt-5-nano") {
		t.Error("did not remember a model that refused the field")
	}
	// Scoped to the model, because this is a property of the model rather than
	// of the provider -- gpt-4o-mini honours temperature at the same provider.
	if tt.omit("openai", "gpt-4o-mini") {
		t.Error("a refusal by one model suppressed the field for another")
	}
	if tt.omit("anthropic", "gpt-5-nano") {
		t.Error("a refusal at one provider leaked to another")
	}
}

// Model behaviour moves: two of the three models named in this repository's live
// tests were retired by their providers mid-project. A stale observation must
// not suppress a caller's temperature forever.
func TestTemperatureObservationsExpire(t *testing.T) {
	tt := newTemperatureTable()
	tt.ttl = 40 * time.Millisecond
	tt.observe("openai", "gpt-5-nano")
	if !tt.omit("openai", "gpt-5-nano") {
		t.Fatal("not remembered at all")
	}
	time.Sleep(70 * time.Millisecond)
	if tt.omit("openai", "gpt-5-nano") {
		t.Error("an expired observation still suppresses the field")
	}
}

// A gateway serving many models must not accumulate an entry per model forever.
// Dropping the table is crude and correct: every entry costs one 400 to relearn.
func TestTemperatureTableIsBounded(t *testing.T) {
	tt := newTemperatureTable()
	tt.limit = 4
	for _, m := range []string{"a", "b", "c", "d", "e", "f"} {
		tt.observe("openai", m)
	}
	tt.mu.Lock()
	n := len(tt.seen)
	tt.mu.Unlock()
	if n > tt.limit {
		t.Errorf("table holds %d entries, limit is %d", n, tt.limit)
	}
}

// A nil table is the off state and must not panic: Server values built in tests
// and any future construction path that skips it should behave as "nothing
// learned" rather than crash a request.
func TestNilTemperatureTableIsInert(t *testing.T) {
	var tt *temperatureTable
	if tt.omit("openai", "gpt-5-nano") {
		t.Error("a nil table claimed to know something")
	}
	tt.observe("openai", "gpt-5-nano") // must not panic
}
