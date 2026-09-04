package bedrock

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"

	"github.com/Grace/switchboard/internal/config"
	"github.com/Grace/switchboard/internal/switchboard"
)

func msg(role switchboard.Role, content string) switchboard.Message {
	return switchboard.Message{Role: role, Content: content}
}

func textOf(t *testing.T, m types.Message) string {
	t.Helper()
	if len(m.Content) == 0 {
		t.Fatal("message has no content blocks")
	}
	blk, ok := m.Content[0].(*types.ContentBlockMemberText)
	if !ok {
		t.Fatalf("content block is %T, want text", m.Content[0])
	}
	return blk.Value
}

// Bedrock rejects a conversation with two turns of the same role in a row, so
// consecutive turns have to be folded. This is the translation most likely to
// be wrong, and the failure is a 400 from the provider rather than anything
// visible locally.
func TestConsecutiveSameRoleTurnsAreMerged(t *testing.T) {
	out, err := toBedrock([]switchboard.Message{
		msg(switchboard.RoleUser, "first"),
		msg(switchboard.RoleUser, "second"),
		msg(switchboard.RoleAssistant, "reply"),
		msg(switchboard.RoleAssistant, "more"),
	})
	if err != nil {
		t.Fatalf("toBedrock: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 merged turns, got %d", len(out))
	}
	if got := textOf(t, out[0]); got != "first\n\nsecond" {
		t.Errorf("user turn = %q", got)
	}
	if got := textOf(t, out[1]); got != "reply\n\nmore" {
		t.Errorf("assistant turn = %q", got)
	}
	if out[0].Role != types.ConversationRoleUser || out[1].Role != types.ConversationRoleAssistant {
		t.Errorf("roles = %v, %v", out[0].Role, out[1].Role)
	}
}

func TestAlternatingTurnsSurviveIntact(t *testing.T) {
	out, err := toBedrock([]switchboard.Message{
		msg(switchboard.RoleUser, "a"),
		msg(switchboard.RoleAssistant, "b"),
		msg(switchboard.RoleUser, "c"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3 turns, got %d", len(out))
	}
	for i, want := range []string{"a", "b", "c"} {
		if got := textOf(t, out[i]); got != want {
			t.Errorf("turn %d = %q, want %q", i, got, want)
		}
	}
}

// Bedrock requires the conversation to open with a user turn. Catching that
// here beats a provider error the caller cannot act on.
func TestConversationMustStartWithUser(t *testing.T) {
	_, err := toBedrock([]switchboard.Message{msg(switchboard.RoleAssistant, "hello")})
	if err == nil || !strings.Contains(err.Error(), "must start with a user message") {
		t.Fatalf("err = %v", err)
	}
}

func TestEmptyConversationIsRefused(t *testing.T) {
	if _, err := toBedrock(nil); err == nil {
		t.Error("no messages should be an error, not an empty request")
	}
	// Empty content is dropped, which can leave nothing at all.
	if _, err := toBedrock([]switchboard.Message{msg(switchboard.RoleUser, "")}); err == nil {
		t.Error("a conversation of only empty turns should be refused")
	}
}

func TestUnsupportedRoleIsNamed(t *testing.T) {
	_, err := toBedrock([]switchboard.Message{
		msg(switchboard.RoleUser, "hi"),
		msg(switchboard.Role("tool"), "result"),
	})
	if err == nil || !strings.Contains(err.Error(), "tool") {
		t.Fatalf("error should name the offending role, got %v", err)
	}
}

// Unset parameters must stay unset: sending a zero temperature is a different
// request from sending none, and the model's own default is usually wanted.
func TestInferenceConfigOmitsWhatWasNotAsked(t *testing.T) {
	if cfg := inferenceConfig(&switchboard.ChatRequest{}); cfg != nil {
		t.Errorf("a request setting nothing should produce no config, got %+v", cfg)
	}

	temp := 0.25
	topP := 0.9
	cfg := inferenceConfig(&switchboard.ChatRequest{
		MaxTokens: 256, Temperature: &temp, TopP: &topP, Stop: []string{"END"},
	})
	if cfg == nil {
		t.Fatal("config should be built when parameters are set")
	}
	if cfg.MaxTokens == nil || *cfg.MaxTokens != 256 {
		t.Errorf("MaxTokens = %v", cfg.MaxTokens)
	}
	if cfg.Temperature == nil || *cfg.Temperature != 0.25 {
		t.Errorf("Temperature = %v", cfg.Temperature)
	}
	if cfg.TopP == nil || *cfg.TopP != 0.9 {
		t.Errorf("TopP = %v", cfg.TopP)
	}
	if len(cfg.StopSequences) != 1 || cfg.StopSequences[0] != "END" {
		t.Errorf("StopSequences = %v", cfg.StopSequences)
	}
}

func TestInferenceConfigBuildsFromAnySingleParameter(t *testing.T) {
	temp := 0.0
	for name, req := range map[string]*switchboard.ChatRequest{
		"max tokens":  {MaxTokens: 1},
		"temperature": {Temperature: &temp}, // zero is a value, not an absence
		"stop":        {Stop: []string{"x"}},
	} {
		if inferenceConfig(req) == nil {
			t.Errorf("%s alone should produce a config", name)
		}
	}
}

func backend(models ...config.Line) *Backend {
	return New(Options{Region: "us-east-1"}, models)
}

func TestUnknownModelIsTypedAndDoesNotTouchAWS(t *testing.T) {
	b := backend(config.Line{Name: "known", Backend: config.BackendBedrock, ModelID: "x"})
	_, err := b.Chat(context.Background(), &switchboard.ChatRequest{Model: "missing"},
		func(switchboard.Chunk) error { return nil })

	var unknown *switchboard.UnknownModelError
	if !errors.As(err, &unknown) {
		t.Fatalf("want UnknownModelError, got %T: %v", err, err)
	}
}

// The roster is visible on a machine that has never seen an AWS credential —
// the client is built lazily precisely so that listing works offline.
func TestModelsListedWithoutCredentials(t *testing.T) {
	b := backend(
		config.Line{Name: "opus", Backend: config.BackendBedrock, ModelID: "anthropic.x"},
		config.Line{Name: "haiku", Backend: config.BackendBedrock, ModelID: "anthropic.y"},
	)
	models, err := b.Models(context.Background())
	if err != nil {
		t.Fatalf("Models: %v", err)
	}
	if len(models) != 2 {
		t.Fatalf("models = %+v", models)
	}
	if models[0].Name != "opus" || models[1].Name != "haiku" {
		t.Errorf("roster should keep config order, got %+v", models)
	}
	for _, m := range models {
		if m.Backend != config.BackendBedrock {
			t.Errorf("backend = %q", m.Backend)
		}
	}
}

// Attribution off: an unattributed request is served on the gateway's own
// credentials rather than refused.
func TestUnattributedIsRefusedOnlyWhenRequired(t *testing.T) {
	b := backend(config.Line{Name: "m", Backend: config.BackendBedrock, ModelID: "x"})
	b.attr = config.Attribution{
		Enabled: true, RoleARN: "arn:aws:iam::1:role/r", TagKey: "team", RequireCaller: true,
	}

	// No caller on the context, and no AWS reachable: the refusal must come
	// from the attribution check, not from credential resolution.
	_, err := b.clientFor(context.Background())
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !Unattributed(err) {
		t.Fatalf("want an unattributed refusal, got %v", err)
	}
	if !strings.Contains(err.Error(), "bearer token") {
		t.Errorf("the error should tell the caller what to do, got %v", err)
	}
}

func TestUnattributedHelperRejectsOtherErrors(t *testing.T) {
	if Unattributed(errors.New("something else")) {
		t.Error("Unattributed must not claim unrelated errors")
	}
	if Unattributed(nil) {
		t.Error("nil is not an unattributed refusal")
	}
}

func TestNameIsStable(t *testing.T) {
	if got := backend().Name(); got != config.BackendBedrock {
		t.Errorf("Name() = %q", got)
	}
}
