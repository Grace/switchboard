package gateway

import "testing"

// Every body here is a verbatim response from a real provider, captured during
// live verification. Inventing them would defeat the purpose: this classifier
// exists precisely because the status code is not enough and the wording is.
func TestClassifyRealProviderRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   fault
	}{{
		// The one that made this necessary. Anthropic reports an unpayable
		// account as 400, which the gateway used to read as a malformed request
		// and refuse to fail over on.
		name:   "anthropic billing, reported as 400",
		status: 400,
		body: `{"type":"error","error":{"type":"invalid_request_error","message":` +
			`"Your credit balance is too low to access the Anthropic API. Please go to Plans & Billing to upgrade or purchase credits."}}`,
		want: faultAccount,
	}, {
		name:   "openai out of credits",
		status: 429,
		body: `{"error":{"message":"You have no credits remaining. Add credits to continue using the API at ` +
			`https://platform.openai.com/settings/organization/billing/","type":"insufficient_quota"}}`,
		want: faultAccount,
	}, {
		name:   "gemini quota exhausted",
		status: 429,
		body: `{"error":{"code":429,"message":"You exceeded your current quota, please check your plan and billing details.",` +
			`"status":"RESOURCE_EXHAUSTED"}}`,
		want: faultAccount,
	}, {
		// A real 400 that must NOT fail over: the account is fine and the
		// request would be refused identically by any provider asked the same
		// way. Failing over here would multiply the waste rather than avoid it.
		name:   "openai reasoning model, budget too small",
		status: 400,
		body: `{"error":{"message":"Could not finish the message because max_tokens or model output limit was reached. ` +
			`Please try again with higher max_tokens.","type":"invalid_request_error","param":null,"code":null}}`,
		want: faultTerminal,
	}, {
		// An ordinary rate limit is transient and self-clearing, so it must stay
		// distinct from an account that cannot pay at all.
		name:   "ordinary rate limit",
		status: 429,
		body:   `{"error":{"message":"Rate limit reached for gpt-4o-mini in organization org-x on requests per min.","type":"requests"}}`,
		want:   faultRateLimit,
	}, {
		name:   "provider degraded",
		status: 503,
		body:   `{"error":{"message":"This model is currently experiencing high demand."}}`,
		want:   faultDegraded,
	}, {
		// Fail safe. An unrecognised 400 keeps the old, conservative behaviour.
		name:   "unrecognised 400 stays terminal",
		status: 400,
		body:   `{"error":{"message":"messages: at least one message is required"}}`,
		want:   faultTerminal,
	}, {
		name:   "empty body stays terminal",
		status: 400,
		body:   ``,
		want:   faultTerminal,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.status, []byte(tc.body)); got != tc.want {
				t.Errorf("classify(%d) = %v, want %v", tc.status, got, tc.want)
			}
		})
	}
}

// The caller used to be told only "provider rejected request", which made a
// token-budget problem indistinguishable from a malformed one.
func TestProviderReasonIsExtractedAndBounded(t *testing.T) {
	got := providerReason([]byte(`{"error":{"message":"Could not finish the message because max_tokens was reached."}}`))
	if got != "Could not finish the message because max_tokens was reached." {
		t.Errorf("reason = %q", got)
	}
	if got := providerReason([]byte(`{"type":"error"}`)); got != "" {
		t.Errorf("absent message should yield empty, got %q", got)
	}
	if got := providerReason([]byte(`not json at all`)); got != "" {
		t.Errorf("unparseable body should yield empty, got %q", got)
	}
	long := `{"error":{"message":"` + string(make([]byte, 0)) + repeat("A", 5000) + `"}}`
	if n := len(providerReason([]byte(long))); n > 300 {
		t.Errorf("reason not bounded: %d chars", n)
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n)
	for range n {
		out = append(out, s[0])
	}
	return string(out)
}
