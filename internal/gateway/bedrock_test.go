package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
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

// All four providers stream now. Bedrock's event-stream framing is translated at
// the provider boundary, so route selection no longer has to skip it.
func TestAllProvidersClaimStreaming(t *testing.T) {
	for _, p := range []string{"openai", "anthropic", "gemini", "bedrock"} {
		if !streams(p) {
			t.Fatalf("%s should stream", p)
		}
	}
}

// Converse and ConverseStream are separate operations rather than a flag on the
// body, so the wrong path would silently return a non-streaming response.
func TestBedrockStreamUsesTheStreamingOperation(t *testing.T) {
	signer := &BedrockSigner{signer: v4.NewSigner(), creds: staticCreds{}, region: "us-east-1"}
	for _, tc := range []struct {
		stream bool
		want   string
	}{
		{false, "/converse"},
		{true, "/converse-stream"},
	} {
		req, err := upstream(context.Background(), Chat{Stream: tc.stream, MaxTokens: 8,
			Messages: []Message{{Role: "user", Content: "hi"}}},
			Route{Provider: "bedrock", Model: "us.amazon.nova-micro-v1:0"},
			ProviderConfig{URL: "https://bedrock-runtime.us-east-1.amazonaws.com", Region: "us-east-1"}, signer)
		if err != nil {
			t.Fatalf("stream=%v: %v", tc.stream, err)
		}
		if !strings.HasSuffix(req.URL.Path, tc.want) {
			t.Errorf("stream=%v: path %q, want suffix %q", tc.stream, req.URL.Path, tc.want)
		}
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

// staticCreds lets the signing path run in a test without resolving real AWS
// credentials, so path construction is testable without an AWS account.
type staticCreds struct{}

func (staticCreds) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret", Source: "test"}, nil
}

// bedrockFrame encodes one AWS event-stream message the way the real service
// does, so the translator is exercised against the actual framing rather than a
// hand-written approximation of it.
func bedrockFrame(t *testing.T, w io.Writer, eventType string, payload string) {
	t.Helper()
	enc := eventstream.NewEncoder()
	if err := enc.Encode(w, eventstream.Message{
		Headers: eventstream.Headers{
			{Name: ":event-type", Value: eventstream.StringValue(eventType)},
			{Name: ":message-type", Value: eventstream.StringValue("event")},
		},
		Payload: []byte(payload),
	}); err != nil {
		t.Fatalf("encoding %s: %v", eventType, err)
	}
}

// The behaviour worth protecting: Bedrock sends the stop reason and the token
// usage as two separate events, and the pipeline stops at the first frame
// reporting completion. Emitting messageStop as it arrives would end the stream
// before usage was seen and report every streamed request as costing nothing.
func TestBedrockStreamCarriesUsagePastTheStopReason(t *testing.T) {
	var raw bytes.Buffer
	bedrockFrame(t, &raw, "messageStart", `{"role":"assistant"}`)
	bedrockFrame(t, &raw, "contentBlockDelta", `{"delta":{"text":"one "},"contentBlockIndex":0}`)
	bedrockFrame(t, &raw, "contentBlockDelta", `{"delta":{"text":"two"},"contentBlockIndex":0}`)
	bedrockFrame(t, &raw, "contentBlockStop", `{"contentBlockIndex":0}`)
	bedrockFrame(t, &raw, "messageStop", `{"stopReason":"end_turn"}`)
	bedrockFrame(t, &raw, "metadata", `{"usage":{"inputTokens":11,"outputTokens":7,"totalTokens":18}}`)

	var text strings.Builder
	var got normalized
	frames, done := 0, false
	err := readSSE(bedrockSSE(io.NopCloser(&raw), 1<<20), func(b []byte) error {
		n, complete, e := normalize("bedrock", b, true)
		if e != nil {
			return e
		}
		frames++
		text.WriteString(n.Text)
		if complete {
			got, done = n, true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("translating a real event stream failed: %v", err)
	}
	if text.String() != "one two" {
		t.Errorf("text = %q, want %q", text.String(), "one two")
	}
	if !done {
		t.Fatal("stream never reported completion")
	}
	if got.Finish != "stop" {
		t.Errorf("finish = %q, want stop", got.Finish)
	}
	// The point of the test.
	if got.Input != 11 || got.Output != 7 {
		t.Errorf("usage = in %d/out %d, want 11/7; usage was lost past the stop reason",
			got.Input, got.Output)
	}
	if frames != 3 {
		t.Errorf("frames = %d, want 3 (two deltas and one terminal)", frames)
	}
}

// A stream that ends without a stop reason is truncation, and must not be
// presented as a complete answer.
func TestBedrockStreamWithoutStopReasonFails(t *testing.T) {
	var raw bytes.Buffer
	bedrockFrame(t, &raw, "contentBlockDelta", `{"delta":{"text":"partial"}}`)
	err := readSSE(bedrockSSE(io.NopCloser(&raw), 1<<20), func(b []byte) error {
		_, _, e := normalize("bedrock", b, true)
		return e
	})
	if err == nil {
		t.Fatal("a truncated bedrock stream was accepted as complete")
	}
}

// Tools and reasoning are refused on the streaming path exactly as they are on
// the complete-response path; flattening them would discard content silently.
func TestBedrockStreamRefusesUnsupportedBlocks(t *testing.T) {
	var raw bytes.Buffer
	bedrockFrame(t, &raw, "contentBlockStart", `{"start":{"toolUse":{"name":"x"}},"contentBlockIndex":0}`)
	bedrockFrame(t, &raw, "messageStop", `{"stopReason":"end_turn"}`)
	err := readSSE(bedrockSSE(io.NopCloser(&raw), 1<<20), func(b []byte) error {
		_, _, e := normalize("bedrock", b, true)
		return e
	})
	if err == nil {
		t.Fatal("a tool-use block was accepted on the streaming path")
	}
}
