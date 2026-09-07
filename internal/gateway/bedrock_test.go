package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestBedrockFinishMapping(t *testing.T) {
	for _, tc := range []struct {
		stop, want string
		ok         bool
	}{
		{"end_turn", "stop", true},
		{"stop_sequence", "stop", true},
		{"max_tokens", "length", true},
		{"guardrail_intervened", "content_filter", true},
		{"content_filtered", "content_filter", true},
		// An unrecognised stop reason is refused rather than guessed at. A new
		// one is far likelier to mean "something we do not model happened" than
		// "the model stopped normally".
		{"tool_use", "", false},
		{"malformed_model_output", "", false},
		{"", "", false},
	} {
		got, err := bedrockFinish(tc.stop)
		if tc.ok && (err != nil || got != tc.want) {
			t.Fatalf("bedrockFinish(%q) = %q, %v; want %q, nil", tc.stop, got, err, tc.want)
		}
		if !tc.ok && err == nil {
			t.Fatalf("bedrockFinish(%q) accepted an unmodelled stop reason", tc.stop)
		}
	}
}

func TestBedrockBodyAlwaysSetsMaxTokens(t *testing.T) {
	// Leaving maxTokens unset makes Bedrock reserve the model's maximum, which
	// silently consumes far more quota than the request needs.
	b := bedrockBody(Chat{MaxTokens: 64}, "", []Message{{Role: "user", Content: "hi"}})
	inf, ok := b["inferenceConfig"].(map[string]any)
	if !ok {
		t.Fatal("no inferenceConfig in the request body")
	}
	if inf["maxTokens"] != 64 {
		t.Fatalf("maxTokens = %v, want 64", inf["maxTokens"])
	}
	if _, present := b["system"]; present {
		t.Fatal("an empty system prompt should be omitted, not sent empty")
	}
}

func TestBedrockBodyCarriesSystemAndRoles(t *testing.T) {
	b := bedrockBody(Chat{MaxTokens: 8}, "be brief",
		[]Message{{Role: "user", Content: "one"}, {Role: "assistant", Content: "two"}})
	raw, _ := json.Marshal(b)
	for _, want := range []string{`"system"`, `"be brief"`, `"role":"user"`, `"role":"assistant"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("request body missing %s: %s", want, raw)
		}
	}
}

func TestNormalizeBedrockRejectsUnsupportedBlocks(t *testing.T) {
	// Tools and reasoning are unsupported here. Flattening them to text would
	// silently discard content the caller never agreed to lose.
	for _, body := range []string{
		`{"output":{"message":{"content":[{"toolUse":{"name":"x"}}]}},"stopReason":"end_turn","usage":{"inputTokens":1,"outputTokens":1}}`,
		`{"output":{"message":{"content":[{"reasoningContent":{"text":"x"}}]}},"stopReason":"end_turn","usage":{"inputTokens":1,"outputTokens":1}}`,
	} {
		if _, err := normalizeBedrock([]byte(body)); err == nil {
			t.Fatalf("accepted an unsupported content block: %s", body)
		}
	}
}

func TestNormalizeBedrockHappyPath(t *testing.T) {
	body := `{"output":{"message":{"role":"assistant","content":[{"text":"hello"}]}},` +
		`"stopReason":"end_turn","usage":{"inputTokens":11,"outputTokens":7,"totalTokens":18}}`
	n, err := normalizeBedrock([]byte(body))
	if err != nil {
		t.Fatalf("rejected a valid Converse response: %v", err)
	}
	if n.Text != "hello" || n.Finish != "stop" || n.Input != 11 || n.Output != 7 {
		t.Fatalf("got %+v", n)
	}
}

// Streaming is refused at route selection so the request falls through to a
// provider that can serve it, rather than failing the whole request.
func TestBedrockDoesNotClaimStreaming(t *testing.T) {
	if streams("bedrock") {
		t.Fatal("bedrock claims streaming support it does not have")
	}
	for _, p := range []string{"openai", "anthropic", "gemini"} {
		if !streams(p) {
			t.Fatalf("%s should stream", p)
		}
	}
}

func TestBedrockStreamRequestIsRefused(t *testing.T) {
	_, err := upstream(context.Background(), Chat{Stream: true, MaxTokens: 8},
		Route{Provider: "bedrock", Model: "us.amazon.nova-micro-v1:0"},
		ProviderConfig{URL: "https://bedrock-runtime.us-east-1.amazonaws.com", Region: "us-east-1"}, nil)
	if err == nil {
		t.Fatal("a streaming bedrock request was accepted")
	}
}

// Signing must fail closed. A request that cannot be signed must not be sent
// unsigned, where it would be rejected by the service anyway but after leaking
// the request body to the network.
func TestBedrockUnsignedRequestIsRefused(t *testing.T) {
	_, err := upstream(context.Background(), Chat{MaxTokens: 8},
		Route{Provider: "bedrock", Model: "us.amazon.nova-micro-v1:0"},
		ProviderConfig{URL: "https://bedrock-runtime.us-east-1.amazonaws.com", Region: "us-east-1"}, nil)
	if err == nil {
		t.Fatal("built a bedrock request with no signer")
	}
}

// Exercises the real service. Skipped unless explicitly enabled, because it
// costs money and needs credentials; nova-micro is the cheapest text model.
func TestBedrockAgainstRealService(t *testing.T) {
	if os.Getenv("SWITCHBOARD_BEDROCK_LIVE") != "1" {
		t.Skip("set SWITCHBOARD_BEDROCK_LIVE=1 to exercise the real Bedrock API")
	}
	ctx := context.Background()
	signer, err := NewBedrockSigner(ctx, "us-east-1")
	if err != nil {
		t.Fatalf("no signer: %v", err)
	}
	req, err := upstream(ctx,
		Chat{MaxTokens: 16, Messages: []Message{{Role: "user", Content: "Reply with the single word: ok"}}},
		Route{Provider: "bedrock", Model: "us.amazon.nova-micro-v1:0"},
		ProviderConfig{URL: "https://bedrock-runtime.us-east-1.amazonaws.com", Region: "us-east-1"},
		signer)
	if err != nil {
		t.Fatalf("could not build a signed request: %v", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("bedrock returned %d", res.StatusCode)
	}
	buf := make([]byte, 8192)
	n, _ := res.Body.Read(buf)
	got, err := normalizeBedrock(buf[:n])
	if err != nil {
		t.Fatalf("could not normalize a real response: %v", err)
	}
	if got.Text == "" || got.Finish == "" {
		t.Fatalf("empty normalized response: %+v", got)
	}
	t.Logf("live bedrock: text=%q finish=%s in=%d out=%d", got.Text, got.Finish, got.Input, got.Output)
}
