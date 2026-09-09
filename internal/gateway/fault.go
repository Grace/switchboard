package gateway

// Classifying why a provider refused a request.
//
// The routing loop used to continue only on 429 and 503, and treat every other
// non-200 as a dead end. Live testing showed that discards the cases failover
// exists for. Three real refusals, all measured:
//
//	OpenAI, out of credits      429, and no Retry-After or x-ratelimit headers
//	Anthropic, balance too low  400, not 402 and not 429
//	Gemini, quota exhausted     429, "exceeded your current quota"
//
// The middle one is the point. A 400 was read as "this request is malformed",
// so the gateway returned an opaque error while a funded provider sat unused in
// the same policy. But an account that cannot pay is exactly when another
// provider should be tried, and a genuinely malformed request is exactly when it
// should not, because it would fail identically everywhere and multiply the
// waste. Nothing in the status code separates them; only the body does.
//
// So this matches strings, which is not a durable contract with any provider.
// It therefore fails safe: anything unrecognised stays terminal, keeping the
// old behaviour. A missed billing phrase costs a failover that could have
// happened. A wrongly matched one would replay a bad request across every
// configured provider, which is worse.

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

type fault int

const (
	// faultTerminal is a request this provider will not serve and no other
	// provider would either. Failing over cannot help.
	faultTerminal fault = iota
	// faultRateLimit is this caller briefly over quota against a healthy
	// provider. Fail over, respect any stated wait, do not blame the provider.
	faultRateLimit
	// faultAccount is an account that cannot serve at all: no credits, balance
	// too low, quota exhausted. The provider is healthy; this account is not.
	// Retrying it every request, as the gateway used to, is pure waste.
	faultAccount
	// faultDegraded is the provider itself failing. This is what the breaker is for.
	faultDegraded
	// faultRefused is this provider declining the request before generating
	// anything: credentials it will not accept (401), access it will not grant
	// (403), or a model it does not have (404).
	//
	// Two things follow, and both were previously wrong. Nothing was accepted and
	// nothing was billed -- the same reasoning temperature.go applies to a 400 --
	// so failing over cannot charge twice. And the refusal is specific to this
	// provider: a key rotated at OpenAI says nothing about Anthropic, and a model
	// one provider retired is not a model every provider retired. So
	// faultTerminal's premise, that "this request would fail the same way at
	// every provider", is simply false here.
	//
	// Added last so the existing values stay stable; String() is a query surface.
	faultRefused
)

// String is what reaches telemetry as switchboard.fault. These four names are
// the only provider-neutral vocabulary the gateway has: OpenAI says 429,
// Anthropic says overloaded_error, Bedrock says ThrottlingException and Gemini
// says RESOURCE_EXHAUSTED, and without this reduction a question like "how many
// requests failed because an account could not pay" has to be asked once per
// provider and rewritten whenever one changes its wording. Keep the values
// stable and lowercase; they are a query surface, not a log line.
func (f fault) String() string {
	switch f {
	case faultTerminal:
		return "terminal"
	case faultRateLimit:
		return "rate_limit"
	case faultAccount:
		return "account"
	case faultDegraded:
		return "degraded"
	case faultRefused:
		return "refused"
	}
	return "unknown"
}

// accountPhrases are lifted verbatim from real provider responses. They will
// drift, and there is no version to pin, so treat a miss as expected rather than
// exceptional: the consequence is a failover that did not happen, not a wrong
// answer. Kept lowercase; the body is folded before comparison.
var accountPhrases = []string{
	"no credits remaining",        // OpenAI, 429
	"credit balance is too low",   // Anthropic, 400
	"exceeded your current quota", // Gemini, 429
	"check your plan and billing", // Gemini, 429
	"purchase credits",
	"add credits",
	"billing details",
	"insufficient_quota",
	"insufficient funds",
}

// classify decides how the routing loop should treat a non-200. The body is
// capped before scanning because it is attacker-influenced and only the error
// message is ever near the front.
func classify(status int, body []byte) fault {
	switch status {
	case 503:
		return faultDegraded
	case 429:
		if accountExhausted(body) {
			return faultAccount
		}
		return faultRateLimit
	case 400, 422:
		if accountExhausted(body) {
			return faultAccount
		}
		return faultTerminal
	case 401, 403, 404:
		// Refused before generation, and specific to this provider. See
		// faultRefused. Deliberately not folded into the default below, which is
		// where 500/502/504 still land: those may mean the provider accepted the
		// request and failed while generating it, which is not replayable.
		return faultRefused
	}
	return faultTerminal
}

func accountExhausted(body []byte) bool {
	const scan = 4096
	if len(body) > scan {
		body = body[:scan]
	}
	lower := strings.ToLower(string(bytes.TrimSpace(body)))
	for _, p := range accountPhrases {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// providerReason pulls the provider's own error text out of a response so the
// caller is told why rather than "provider rejected request". All four providers
// nest it differently, so this is deliberately loose: it returns "" rather than
// guessing, and the caller falls back to a generic message.
func providerReason(body []byte) string {
	const scan = 8192
	if len(body) > scan {
		body = body[:scan]
	}
	var w struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &w) != nil {
		return ""
	}
	msg := w.Error.Message
	if msg == "" {
		msg = w.Message
	}
	msg = strings.TrimSpace(msg)
	// Bounded: this reaches a client response, and a provider could return an
	// arbitrarily long message. Cut on a rune boundary -- a byte slice can land
	// mid-sequence, and the result is a message ending in a replacement
	// character in the caller's error body.
	if len(msg) > 300 {
		cut := 300
		for cut > 0 && !utf8.RuneStart(msg[cut]) {
			cut--
		}
		msg = msg[:cut]
	}
	return msg
}
