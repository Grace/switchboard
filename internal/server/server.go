// Package server exposes the registry over HTTP.
//
// The dialect is OpenAI-compatible on purpose: it costs nothing to implement
// and means every existing client — editors, SDKs, curl — can point at golem
// without knowing golem exists.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/grace/golem/internal/golem"
	"github.com/grace/golem/internal/wire"
)

// Server serves the golem HTTP API.
type Server struct {
	reg    *golem.Registry
	logger *log.Logger
	// now is injected so tests get deterministic timestamps.
	now func() time.Time
}

// New builds a server over a registry.
func New(reg *golem.Registry, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	return &Server{reg: reg, logger: logger, now: time.Now}
}

// Handler returns the routed handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /v1/models", s.handleModels)
	mux.HandleFunc("POST /v1/chat/completions", s.handleChat)
	mux.HandleFunc("POST /v1/animate", s.handleAnimate)
	mux.HandleFunc("POST /v1/rest", s.handleRest)
	return mux
}

// Animator is implemented by backends that can load and unload models on
// demand. Backends that hold no local state simply do not implement it.
type Animator interface {
	Animate(ctx context.Context, model string) error
	Rest(model string) bool
}

// ToolCaller is implemented by backends that can forward tool definitions to a
// model. Like Animator, it is an optional capability asked at the door: a
// backend that cannot do this does not implement it, and the server turns the
// request away rather than dropping the tools on the floor.
type ToolCaller interface {
	ToolsSupported() bool
}

func toolsSupported(b golem.Backend) bool {
	tc, ok := b.(ToolCaller)
	return ok && tc.ToolsSupported()
}

// handleAnimate loads a model ahead of first use.
func (s *Server) handleAnimate(w http.ResponseWriter, r *http.Request) {
	backend, model, ok := s.adminTarget(w, r)
	if !ok {
		return
	}
	animator, canAnimate := backend.(Animator)
	if !canAnimate {
		writeJSON(w, http.StatusOK, map[string]any{
			"model": model, "state": "remote",
			"detail": fmt.Sprintf("%s models are always available; nothing to load", backend.Name()),
		})
		return
	}
	if err := animator.Animate(r.Context(), model); err != nil {
		s.logger.Printf("animate %s: %v", model, err)
		writeError(w, http.StatusBadGateway, "backend_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"model": model, "state": "animated"})
}

// handleRest unloads a model, freeing its memory.
func (s *Server) handleRest(w http.ResponseWriter, r *http.Request) {
	backend, model, ok := s.adminTarget(w, r)
	if !ok {
		return
	}
	animator, canAnimate := backend.(Animator)
	if !canAnimate {
		writeJSON(w, http.StatusOK, map[string]any{"model": model, "state": "remote"})
		return
	}
	state := "resting"
	if !animator.Rest(model) {
		state = "was not animated"
	}
	writeJSON(w, http.StatusOK, map[string]any{"model": model, "state": state})
}

// adminTarget decodes {"model": "..."} and resolves it, reporting any failure
// to the client itself.
func (s *Server) adminTarget(w http.ResponseWriter, r *http.Request) (golem.Backend, string, bool) {
	var body struct {
		Model string `json:"model"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request_error", fmt.Sprintf("malformed request body: %v", err))
		return nil, "", false
	}
	backend, model, err := s.reg.Resolve(body.Model)
	if err != nil {
		writeError(w, http.StatusNotFound, "model_not_found", err.Error())
		return nil, "", false
	}
	return backend, model, true
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	models := s.reg.Models(r.Context())
	list := wire.ModelList{Object: "list", Data: make([]wire.Model, 0, len(models))}
	for _, m := range models {
		list.Data = append(list.Data, wire.Model{
			ID:      m.Name,
			Object:  "model",
			Created: s.now().Unix(),
			OwnedBy: m.Backend,
		})
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	var req wire.ChatRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request_error", fmt.Sprintf("malformed request body: %v", err))
		return
	}
	if len(req.Messages) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request_error", "messages must not be empty")
		return
	}

	backend, model, err := s.reg.Resolve(req.Model)
	if err != nil {
		status, kind := http.StatusNotFound, "model_not_found"
		if req.Model == "" && s.reg.Default() == "" {
			status, kind = http.StatusBadRequest, "invalid_request_error"
			err = errors.New("no model specified and no default_model configured")
		}
		writeError(w, status, kind, err.Error())
		return
	}

	chatReq := &golem.ChatRequest{
		Model:       model,
		Messages:    make([]golem.Message, 0, len(req.Messages)),
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		Stop:        req.Stop,
	}
	for _, m := range req.Messages {
		chatReq.Messages = append(chatReq.Messages, toNeutralMessage(m))
	}

	if len(req.Tools) > 0 {
		// Refuse rather than drop: a client that asked for tools and got prose
		// back has no way to tell that the tools never reached the model.
		if !toolsSupported(backend) {
			writeError(w, http.StatusBadRequest, "invalid_request_error",
				fmt.Sprintf("%s cannot forward tool definitions to %q", backend.Name(), model))
			return
		}
		tools, err := toNeutralTools(req.Tools)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
			return
		}
		chatReq.Tools = tools
	}
	if len(req.ToolChoice) > 0 {
		choice, err := parseToolChoice(req.ToolChoice)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
			return
		}
		chatReq.ToolChoice = choice
	}

	id := fmt.Sprintf("chatcmpl-%d", s.now().UnixNano())
	if req.Stream {
		s.streamChat(w, r, backend, chatReq, id)
		return
	}

	result, err := backend.Chat(r.Context(), chatReq, func(golem.Chunk) error { return nil })
	if err != nil {
		s.logger.Printf("chat %s: %v", model, err)
		writeError(w, http.StatusBadGateway, "backend_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.response(id, model, result))
}

// streamChat writes the completion as server-sent events.
func (s *Server) streamChat(w http.ResponseWriter, r *http.Request, backend golem.Backend, req *golem.ChatRequest, id string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "server_error", "streaming unsupported by this server")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	created := s.now().Unix()
	send := func(frame wire.ChatResponse) error {
		data, err := json.Marshal(frame)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}

	role := string(golem.RoleAssistant)
	err := send(wire.ChatResponse{
		ID: id, Object: "chat.completion.chunk", Created: created, Model: req.Model,
		Choices: []wire.Choice{{Index: 0, Delta: &wire.Message{Role: role}}},
	})
	if err != nil {
		return
	}

	result, err := backend.Chat(r.Context(), req, func(c golem.Chunk) error {
		delta := &wire.Message{Content: c.Text}
		if c.ToolCall != nil {
			delta.ToolCalls = []wire.ToolCall{toWireToolCallDelta(*c.ToolCall)}
		}
		return send(wire.ChatResponse{
			ID: id, Object: "chat.completion.chunk", Created: created, Model: req.Model,
			Choices: []wire.Choice{{Index: 0, Delta: delta}},
		})
	})
	if err != nil {
		// The headers are long gone, so the only honest way to report a
		// mid-stream failure is an error frame before [DONE].
		if r.Context().Err() == nil {
			s.logger.Printf("chat %s: %v", req.Model, err)
			data, _ := json.Marshal(wire.ErrorResponse{Error: wire.Error{
				Message: err.Error(),
				Type:    "backend_error",
			}})
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
		return
	}

	finish := finishReasonFor(result)
	final := wire.ChatResponse{
		ID: id, Object: "chat.completion.chunk", Created: created, Model: req.Model,
		Choices: []wire.Choice{{Index: 0, Delta: &wire.Message{}, FinishReason: &finish}},
		Usage:   usage(result),
	}
	if err := send(final); err != nil {
		return
	}
	fmt.Fprint(w, "data: [DONE]\n\n")
	flusher.Flush()
}

// response builds a non-streaming completion body.
func (s *Server) response(id, model string, result *golem.Result) wire.ChatResponse {
	finish := finishReasonFor(result)
	return wire.ChatResponse{
		ID:      id,
		Object:  "chat.completion",
		Created: s.now().Unix(),
		Model:   model,
		Choices: []wire.Choice{{
			Index: 0,
			Message: &wire.Message{
				Role:      string(golem.RoleAssistant),
				Content:   result.Text,
				ToolCalls: toWireToolCalls(result.ToolCalls),
			},
			FinishReason: &finish,
		}},
		Usage: usage(result),
	}
}

// toNeutralMessage converts one turn off the wire, flattening OpenAI's nested
// function object into golem's flat call.
func toNeutralMessage(m wire.Message) golem.Message {
	out := golem.Message{
		Role:       golem.Role(m.Role),
		Content:    m.Content,
		ToolCallID: m.ToolCallID,
	}
	for _, tc := range m.ToolCalls {
		out.ToolCalls = append(out.ToolCalls, golem.ToolCall{
			ID:        tc.ID,
			Name:      tc.Function.Name,
			Arguments: tc.Function.Arguments,
		})
	}
	return out
}

// toNeutralTools validates the tools array and flattens it. The schema itself
// is not inspected — backends hand it to the model, which is the only thing
// that can judge it.
func toNeutralTools(tools []wire.Tool) ([]golem.Tool, error) {
	out := make([]golem.Tool, 0, len(tools))
	for i, t := range tools {
		if t.Type != "" && t.Type != "function" {
			return nil, fmt.Errorf("tools[%d]: unsupported tool type %q, want \"function\"", i, t.Type)
		}
		if t.Function.Name == "" {
			return nil, fmt.Errorf("tools[%d]: function.name is required", i)
		}
		out = append(out, golem.Tool{
			Name:        t.Function.Name,
			Description: t.Function.Description,
			Schema:      t.Function.Parameters,
		})
	}
	return out, nil
}

// parseToolChoice decodes OpenAI's polymorphic tool_choice: either a bare
// string ("auto", "none", "required") or a named function object.
func parseToolChoice(raw json.RawMessage) (*golem.ToolChoice, error) {
	var mode string
	if err := json.Unmarshal(raw, &mode); err == nil {
		switch mode {
		case "auto":
			return &golem.ToolChoice{Mode: golem.ToolChoiceAuto}, nil
		case "none":
			return &golem.ToolChoice{Mode: golem.ToolChoiceNone}, nil
		case "required", "any":
			return &golem.ToolChoice{Mode: golem.ToolChoiceAny}, nil
		default:
			return nil, fmt.Errorf("tool_choice %q: want auto, none, or required", mode)
		}
	}

	var named struct {
		Type     string `json:"type"`
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if err := json.Unmarshal(raw, &named); err != nil {
		return nil, errors.New("tool_choice must be a string or a function object")
	}
	if named.Function.Name == "" {
		return nil, errors.New("tool_choice: function.name is required")
	}
	return &golem.ToolChoice{Mode: golem.ToolChoiceTool, Name: named.Function.Name}, nil
}

// toWireToolCalls renders finished calls onto a complete response.
func toWireToolCalls(calls []golem.ToolCall) []wire.ToolCall {
	if len(calls) == 0 {
		return nil
	}
	out := make([]wire.ToolCall, 0, len(calls))
	for _, c := range calls {
		out = append(out, wire.ToolCall{
			ID:       c.ID,
			Type:     "function",
			Function: wire.ToolCallFunction{Name: c.Name, Arguments: c.Arguments},
		})
	}
	return out
}

// toWireToolCallDelta renders one streamed increment. Index goes on every
// frame so a client can correlate fragments; id, type, and name appear only on
// the frame that opened the call, which is the shape OpenAI clients expect.
func toWireToolCallDelta(d golem.ToolCallDelta) wire.ToolCall {
	index := d.Index
	out := wire.ToolCall{
		Index:    &index,
		ID:       d.ID,
		Function: wire.ToolCallFunction{Name: d.Name, Arguments: d.Arguments},
	}
	if d.ID != "" {
		out.Type = "function"
	}
	return out
}

func usage(result *golem.Result) *wire.Usage {
	if result.Usage.InputTokens == 0 && result.Usage.OutputTokens == 0 {
		return nil
	}
	return &wire.Usage{
		PromptTokens:     result.Usage.InputTokens,
		CompletionTokens: result.Usage.OutputTokens,
		TotalTokens:      result.Usage.InputTokens + result.Usage.OutputTokens,
	}
}

// finishReasonFor picks the reason a client should see. A backend that
// produced tool calls but reported a plain stop is corrected here: clients
// branch on finish_reason to decide whether to run the tools, and a wrong
// answer strands the call with no way to notice.
func finishReasonFor(result *golem.Result) string {
	reason := finishReason(result.StopReason)
	if len(result.ToolCalls) > 0 && reason == "stop" {
		return "tool_calls"
	}
	return reason
}

// finishReason normalises backend stop reasons onto OpenAI's vocabulary, since
// clients branch on these exact strings.
func finishReason(reason string) string {
	switch strings.ToLower(reason) {
	case "", "end_turn", "stop_sequence", "stop":
		return "stop"
	case "max_tokens", "length":
		return "length"
	case "tool_use", "tool_calls":
		return "tool_calls"
	case "content_filtered", "content_filter":
		return "content_filter"
	default:
		return reason
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, kind, message string) {
	writeJSON(w, status, wire.ErrorResponse{Error: wire.Error{Message: message, Type: kind}})
}

// ListenAndServe runs the server until ctx is cancelled, then drains in-flight
// requests before returning.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: s.Handler(),
		// No write timeout: a long generation is a long response, and cutting
		// it off mid-stream is worse than an idle connection.
		ReadHeaderTimeout: 15 * time.Second,
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
