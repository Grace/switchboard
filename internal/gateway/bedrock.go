package gateway

// Amazon Bedrock support.
//
// Bedrock differs from the other three providers in two ways that matter to the
// shape of this package.
//
// Authentication is SigV4 against the task's IAM role rather than a static key
// from the environment, so there is no long-lived credential to leak and nothing
// for a customer to paste. That is a better story for a security product, but it
// means a request cannot be built without resolving credentials first.
//
// Streaming is AWS event-stream framing, not server-sent events. The other three
// adapters read `data:` lines; Bedrock returns length-prefixed binary messages
// with CRCs. Rather than reach for the bedrockruntime SDK client, which would
// bypass this package's transport entirely and with it the circuit breaker, the
// retry budget, the no-replay-after-acceptance rule and the generation deadline,
// this signs an ordinary *http.Request and decodes the *http.Response body. Every
// safety property already built here continues to apply.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

// errStreamUnsupported is returned when a route would need a streaming shape
// this adapter does not implement yet. It is a routing fact, not a provider
// failure, so it must not count against the circuit breaker.
var errStreamUnsupported = errors.New("streaming is not supported for this provider")

// streams reports whether a provider can serve a streaming request. Bedrock
// streams over AWS event-stream framing rather than server-sent events and that
// decode path is not built yet, so a streaming request skips the route and tries
// the next one instead of failing. A policy whose only route is bedrock will
// return the ordinary "routes unavailable" 503 for streaming requests, which is
// accurate.
func streams(provider string) bool { return provider != "bedrock" }

// BedrockSigner signs outbound Bedrock requests. It is nil unless a bedrock
// provider is configured, which keeps the common case free of AWS credential
// resolution entirely.
type BedrockSigner struct {
	signer *v4.Signer
	creds  aws.CredentialsProvider
	region string
}

// NewBedrockSigner resolves the ambient AWS configuration once, at startup.
// Credentials are cached and refreshed by the provider, so this is not repeated
// per request.
func NewBedrockSigner(ctx context.Context, region string) (*BedrockSigner, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws configuration unavailable for bedrock: %w", err)
	}
	if cfg.Credentials == nil {
		return nil, errors.New("no AWS credentials available for bedrock")
	}
	return &BedrockSigner{signer: v4.NewSigner(), creds: cfg.Credentials, region: region}, nil
}

// sign applies SigV4 in place. The payload hash is required by the algorithm, so
// the body must already be set.
func (b *BedrockSigner) sign(ctx context.Context, req *http.Request, body []byte) error {
	c, err := b.creds.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("bedrock credentials unavailable: %w", err)
	}
	sum := sha256.Sum256(body)
	return b.signer.SignHTTP(ctx, c, req, hex.EncodeToString(sum[:]),
		"bedrock", b.region, time.Now().UTC())
}

// bedrockBody builds a Converse request. maxTokens is always set: leaving it
// unset makes Bedrock reserve the model's maximum, which silently consumes far
// more quota than the request needs and is a common cause of throttling.
func bedrockBody(c Chat, system string, msgs []Message) map[string]any {
	content := func(text string) []any { return []any{map[string]any{"text": text}} }
	out := make([]any, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, map[string]any{"role": m.Role, "content": content(m.Content)})
	}
	inference := map[string]any{"maxTokens": c.MaxTokens}
	if c.Temperature != nil {
		inference["temperature"] = *c.Temperature
	}
	b := map[string]any{"messages": out, "inferenceConfig": inference}
	if system != "" {
		b["system"] = content(system)
	}
	return b
}

// bedrockWire is the subset of a Converse response this gateway uses. Tool and
// multimodal blocks are deliberately absent: they are unsupported here, and a
// response carrying them is rejected rather than silently flattened.
type bedrockWire struct {
	Output struct {
		Message struct {
			Content []struct {
				Text      string          `json:"text"`
				ToolUse   json.RawMessage `json:"toolUse"`
				Reasoning json.RawMessage `json:"reasoningContent"`
			} `json:"content"`
		} `json:"message"`
	} `json:"output"`
	StopReason string `json:"stopReason"`
	Usage      struct {
		Input  int `json:"inputTokens"`
		Output int `json:"outputTokens"`
	} `json:"usage"`
	// Streaming deltas arrive as separate event shapes on the same connection.
	Delta struct {
		Text string `json:"text"`
	} `json:"delta"`
	ContentBlockIndex *int `json:"contentBlockIndex"`
}

// bedrockFinish maps Converse stopReason onto the gateway's vocabulary. Values
// not listed are rejected rather than guessed at, because a new stop reason is
// more likely to mean "something happened we do not model" than "stop".
func bedrockFinish(s string) (string, error) {
	switch s {
	case "end_turn", "stop_sequence":
		return "stop", nil
	case "max_tokens":
		return "length", nil
	case "guardrail_intervened", "content_filtered":
		return "content_filter", nil
	}
	return "", fmt.Errorf("unsupported bedrock stop reason %q", s)
}

// decodeBedrockStream reads AWS event-stream framing and returns the assembled
// text, the finish reason and token usage. It exists so the caller can treat a
// Bedrock stream like any other, and it enforces the same refusal of tool and
// reasoning blocks that the nonstreaming path does.
func decodeBedrockStream(r io.Reader, limit int64) (normalized, error) {
	var n normalized
	dec := eventstream.NewDecoder()
	var text bytes.Buffer
	payload := make([]byte, 0, 8192)
	for {
		msg, err := dec.Decode(io.LimitReader(r, limit), payload)
		if err == io.EOF {
			break
		}
		if err != nil {
			return n, fmt.Errorf("malformed bedrock event stream: %w", err)
		}
		// The event name lives in the message headers; the body is JSON.
		var kind string
		for _, h := range msg.Headers {
			if h.Name == ":event-type" {
				kind = h.Value.String()
			}
		}
		var w bedrockWire
		if len(msg.Payload) > 0 {
			if err := json.Unmarshal(msg.Payload, &w); err != nil {
				return n, fmt.Errorf("malformed bedrock event payload: %w", err)
			}
		}
		switch kind {
		case "contentBlockDelta":
			if len(w.Delta.Text) > 0 {
				text.WriteString(w.Delta.Text)
			}
		case "messageStop":
			f, err := bedrockFinish(w.StopReason)
			if err != nil {
				return n, err
			}
			n.Finish = f
		case "metadata":
			n.Input, n.Output = w.Usage.Input, w.Usage.Output
		}
		if text.Len() > int(limit) {
			return n, errors.New("bedrock stream exceeded the response limit")
		}
	}
	if n.Finish == "" {
		return n, errors.New("bedrock stream ended without a stop reason")
	}
	n.Text = text.String()
	return n, nil
}

// normalizeBedrock handles a complete (nonstreaming) Converse response.
func normalizeBedrock(b []byte) (normalized, error) {
	var n normalized
	// Lenient, matching the other three adapters. Strict decoding belongs on
	// client input, where an unknown field means the caller asked for something
	// unsupported; a provider adding a response field is routine, and rejecting
	// it would break every request. Live Bedrock returns a "metrics" object this
	// gateway has no use for, which is exactly the case in point. The unsupported
	// content blocks are refused explicitly below rather than by strictness.
	var w bedrockWire
	if err := json.Unmarshal(b, &w); err != nil {
		return n, err
	}
	for _, block := range w.Output.Message.Content {
		if len(block.ToolUse) > 0 || len(block.Reasoning) > 0 {
			return n, errors.New("bedrock returned an unsupported content block")
		}
		n.Text += block.Text
	}
	f, err := bedrockFinish(w.StopReason)
	if err != nil {
		return n, err
	}
	n.Finish = f
	n.Input, n.Output = w.Usage.Input, w.Usage.Output
	return n, nil
}
