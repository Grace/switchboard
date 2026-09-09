// Models that refuse a temperature, learned rather than listed.
//
// Reasoning models reject any temperature but their default, and answer a
// request carrying one with a 400. A caller who sets temperature against such a
// model therefore gets a hard failure for a field every other model accepts.
//
// The obvious fixes are both bad. A list of model names drifts: two of the three
// models named in this repository's live tests were retired by their providers
// mid-project, and a name list would have to be edited every time a provider
// ships. Stripping temperature for everyone silently changes results for the
// models that honour it.
//
// So this copies budget.go, which solved the same shape of problem: a property
// of a model that can only be discovered by trying, remembered per
// {provider, model}, bounded and expiring so a stale observation cannot shadow a
// model forever. The gateway learns which models refuse the field by being told
// so, once, by the provider.
//
// The retry that makes the first request succeed is safe for a specific reason:
// a 400 means the provider rejected the request before generating anything, so
// nothing was accepted and nothing was billed. The no-replay-after-acceptance
// rule this codebase enforces elsewhere is about accepted requests and does not
// apply here.
package gateway

import (
	"bytes"
	"sync"
	"time"
)

// temperaturePhrases are lifted from provider refusals. Like accountPhrases in
// fault.go this is not a durable contract with anyone, and it fails safe in the
// same direction: an unrecognised 400 leaves the request untouched, so a miss
// costs one failed request rather than silently altering a caller's parameters.
//
// A false positive is the worse error here, which is why the match requires the
// word temperature and not merely "unsupported": dropping a temperature the
// caller chose changes their output without telling them.
var temperaturePhrases = [][]byte{
	[]byte("'temperature' does not support"),
	[]byte("temperature is not supported"),
	[]byte("does not support temperature"),
	[]byte("unsupported parameter: 'temperature'"),
	[]byte("unsupported value: 'temperature'"),
	[]byte("temperature must be"),
}

// rejectsTemperature reports whether this body is a provider saying it will not
// take the temperature that was sent.
func rejectsTemperature(status int, body []byte) bool {
	if status != 400 && status != 422 {
		return false
	}
	lower := bytes.ToLower(body)
	if !bytes.Contains(lower, []byte("temperature")) {
		return false
	}
	for _, p := range temperaturePhrases {
		if bytes.Contains(lower, p) {
			return true
		}
	}
	return false
}

// temperatureTable remembers which models refused the field.
type temperatureTable struct {
	mu     sync.Mutex
	seen   map[budgetKey]time.Time
	ttl    time.Duration
	limit  int
	always bool // test hook: treat every model as refusing.
}

func newTemperatureTable() *temperatureTable {
	return &temperatureTable{seen: map[budgetKey]time.Time{}, ttl: 6 * time.Hour, limit: 256}
}

// omit reports whether temperature should be left out of a request to this
// route, because this model has refused it recently.
func (t *temperatureTable) omit(provider, model string) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.always {
		return true
	}
	at, ok := t.seen[budgetKey{provider, model}]
	if !ok {
		return false
	}
	if time.Since(at) > t.ttl {
		delete(t.seen, budgetKey{provider, model})
		return false
	}
	return true
}

// observe records that this model refused a temperature.
func (t *temperatureTable) observe(provider, model string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// Bounded the way budgetTable is: a gateway serving many models must not
	// accumulate a map entry per model forever. Dropping the whole table is
	// crude and correct -- every entry is re-learnable at the cost of one 400.
	if len(t.seen) >= t.limit {
		t.seen = map[budgetKey]time.Time{}
	}
	t.seen[budgetKey{provider, model}] = time.Now()
}
