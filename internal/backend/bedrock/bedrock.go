// Package bedrock runs models on AWS.
//
// It uses the Converse API rather than per-model InvokeModel payloads, so one
// code path covers every model family Bedrock hosts and adding a model is a
// config line rather than a new marshaller.
package bedrock

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"

	"github.com/Grace/switchboard/internal/config"
	"github.com/Grace/switchboard/internal/switchboard"
)

// Options configures the backend.
type Options struct {
	// Region overrides the region from the environment or shared config.
	Region string
	// Profile selects a named profile from the shared config file.
	Profile string
	// Attribution, when enabled, makes each request carry the calling team's
	// identity to the provider so the bill can be split by it.
	Attribution config.Attribution
}

// Backend is a switchboard.Backend backed by Amazon Bedrock.
type Backend struct {
	opts  Options
	specs map[string]config.Line
	order []string

	// The client is built on first use so that switchboard starts, serves local
	// models, and lists its roster on a machine with no AWS credentials at all.
	once    sync.Once
	baseCfg aws.Config
	client  *bedrockruntime.Client
	initErr error

	// Per-team clients, each holding credentials assumed for that team. See
	// attribution.go.
	attr   config.Attribution
	mu     sync.Mutex
	byTeam map[string]*bedrockruntime.Client
}

var _ switchboard.Backend = (*Backend)(nil)

// New builds a backend serving the given lines.
func New(opts Options, models []config.Line) *Backend {
	b := &Backend{
		opts:  opts,
		attr:  opts.Attribution,
		specs: make(map[string]config.Line, len(models)),
	}
	for _, m := range models {
		b.specs[m.Name] = m
		b.order = append(b.order, m.Name)
	}
	return b
}

// Name implements switchboard.Backend.
func (b *Backend) Name() string { return config.BackendBedrock }

// Models implements switchboard.Backend. It reports what config declares rather than
// calling ListFoundationModels: the roster should be visible without
// credentials, and access to a model id is not knowable until you invoke it.
func (b *Backend) Models(context.Context) ([]switchboard.Model, error) {
	out := make([]switchboard.Model, 0, len(b.order))
	for _, name := range b.order {
		spec := b.specs[name]
		detail := spec.ModelID
		if b.opts.Region != "" {
			detail = fmt.Sprintf("%s @ %s", detail, b.opts.Region)
		}
		out = append(out, switchboard.Model{
			Name:    name,
			Backend: b.Name(),
			Detail:  detail,
			Live:    true,
		})
	}
	return out, nil
}

// resolve builds the client once, on first use.
func (b *Backend) resolve(ctx context.Context) (*bedrockruntime.Client, error) {
	b.once.Do(func() {
		var opts []func(*awsconfig.LoadOptions) error
		if b.opts.Region != "" {
			opts = append(opts, awsconfig.WithRegion(b.opts.Region))
		}
		if b.opts.Profile != "" {
			opts = append(opts, awsconfig.WithSharedConfigProfile(b.opts.Profile))
		}

		cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			b.initErr = fmt.Errorf("loading AWS config: %w", err)
			return
		}
		if cfg.Region == "" {
			b.initErr = errors.New("no AWS region: set bedrock.region in config, or AWS_REGION")
			return
		}
		b.baseCfg = cfg
		b.client = bedrockruntime.NewFromConfig(cfg)
	})
	return b.client, b.initErr
}

// Chat implements switchboard.Backend.
func (b *Backend) Chat(ctx context.Context, req *switchboard.ChatRequest, emit func(switchboard.Chunk) error) (*switchboard.Result, error) {
	spec, ok := b.specs[req.Model]
	if !ok {
		return nil, &switchboard.UnknownModelError{Model: req.Model}
	}
	client, err := b.clientFor(ctx)
	if err != nil {
		return nil, err
	}

	system, turns := req.System()
	messages, err := toBedrock(turns)
	if err != nil {
		return nil, err
	}

	input := &bedrockruntime.ConverseStreamInput{
		ModelId:         aws.String(spec.ModelID),
		Messages:        messages,
		InferenceConfig: inferenceConfig(req),
	}
	if system != "" {
		input.System = []types.SystemContentBlock{
			&types.SystemContentBlockMemberText{Value: system},
		}
	}

	out, err := client.ConverseStream(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("bedrock: %w", err)
	}
	stream := out.GetStream()
	defer stream.Close()

	var text strings.Builder
	result := &switchboard.Result{}

	for event := range stream.Events() {
		switch e := event.(type) {
		case *types.ConverseStreamOutputMemberContentBlockDelta:
			delta, ok := e.Value.Delta.(*types.ContentBlockDeltaMemberText)
			if !ok {
				// Reasoning, citation, and tool deltas arrive here too. v0
				// streams assistant text only.
				continue
			}
			text.WriteString(delta.Value)
			if err := emit(switchboard.Chunk{Text: delta.Value}); err != nil {
				return nil, err
			}
		case *types.ConverseStreamOutputMemberMessageStop:
			result.StopReason = string(e.Value.StopReason)
		case *types.ConverseStreamOutputMemberMetadata:
			if u := e.Value.Usage; u != nil {
				result.Usage = switchboard.Usage{
					InputTokens:  int(aws.ToInt32(u.InputTokens)),
					OutputTokens: int(aws.ToInt32(u.OutputTokens)),
				}
			}
		}
	}
	if err := stream.Err(); err != nil {
		return nil, fmt.Errorf("bedrock stream: %w", err)
	}

	result.Text = text.String()
	return result, nil
}

// toBedrock converts neutral turns into Converse messages. Bedrock requires
// strictly alternating user/assistant turns, so consecutive same-role messages
// are merged rather than rejected.
func toBedrock(turns []switchboard.Message) ([]types.Message, error) {
	var out []types.Message
	for _, m := range turns {
		var role types.ConversationRole
		switch m.Role {
		case switchboard.RoleUser:
			role = types.ConversationRoleUser
		case switchboard.RoleAssistant:
			role = types.ConversationRoleAssistant
		default:
			return nil, fmt.Errorf("bedrock: unsupported role %q outside the leading system prompt", m.Role)
		}
		if m.Content == "" {
			continue
		}

		if n := len(out); n > 0 && out[n-1].Role == role {
			prev := out[n-1].Content[0].(*types.ContentBlockMemberText)
			prev.Value += "\n\n" + m.Content
			continue
		}
		out = append(out, types.Message{
			Role:    role,
			Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: m.Content}},
		})
	}
	if len(out) == 0 {
		return nil, errors.New("bedrock: no messages to send")
	}
	if out[0].Role != types.ConversationRoleUser {
		return nil, errors.New("bedrock: conversation must start with a user message")
	}
	return out, nil
}

// inferenceConfig maps only the parameters the caller actually set, leaving
// everything else to the model's own defaults.
func inferenceConfig(req *switchboard.ChatRequest) *types.InferenceConfiguration {
	cfg := &types.InferenceConfiguration{}
	set := false

	if req.MaxTokens > 0 {
		cfg.MaxTokens = aws.Int32(int32(req.MaxTokens))
		set = true
	}
	if req.Temperature != nil {
		cfg.Temperature = aws.Float32(float32(*req.Temperature))
		set = true
	}
	if req.TopP != nil {
		cfg.TopP = aws.Float32(float32(*req.TopP))
		set = true
	}
	if len(req.Stop) > 0 {
		cfg.StopSequences = req.Stop
		set = true
	}
	if !set {
		return nil
	}
	return cfg
}

// Close implements switchboard.Backend. Nothing to release: the SDK client holds no
// long-lived resources of its own.
func (b *Backend) Close() error { return nil }
