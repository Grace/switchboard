// Package server exposes the registry over HTTP.
//
// The dialect is OpenAI-compatible on purpose: it costs nothing to implement
// and means every existing client — editors, SDKs, curl — can point at switchboard
// without knowing switchboard exists.
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

	"github.com/Grace/switchboard/internal/config"
	"github.com/Grace/switchboard/internal/switchboard"
	"github.com/Grace/switchboard/internal/wire"
)

// Server serves the switchboard HTTP API.
type Server struct {
	reg    *switchboard.Registry
	logger *log.Logger
	// now is injected so tests get deterministic timestamps.
	now func() time.Time

	// teams maps a presented key to the team it authenticates as, and
	// requireCaller refuses requests that present none.
	teams         []config.Team
	requireCaller bool
}

// New builds a server over a registry.
func New(reg *switchboard.Registry, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	return &Server{reg: reg, logger: logger, now: time.Now}
}

// WithAttribution gives the server the roster it authenticates callers against.
// Without it every request is unattributed, which is the behaviour of a gateway
// that has no idea who its callers are.
func (s *Server) WithAttribution(teams []config.Team, requireCaller bool) *Server {
	s.teams, s.requireCaller = teams, requireCaller
	return s
}

// caller resolves the bearer token on a request to a team.
//
// A gateway is the last place that knows who is calling. If it does not write
// that down here, nothing downstream can reconstruct it — which is why an
// unattributed request is refused rather than quietly billed to everyone.
func (s *Server) caller(r *http.Request) (switchboard.Caller, bool) {
	key, ok := bearer(r.Header.Get("Authorization"))
	if !ok {
		return switchboard.Caller{}, false
	}
	team, ok := config.TeamForKey(s.teams, key)
	if !ok {
		return switchboard.Caller{}, false
	}
	return switchboard.Caller{Team: team}, true
}

func bearer(h string) (string, bool) {
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(h[len(prefix):]), true
}

// Handler returns the routed handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /v1/models", s.handleModels)
	mux.HandleFunc("POST /v1/chat/completions", s.handleChat)
	mux.HandleFunc("POST /v1/connect", s.handleConnect)
	mux.HandleFunc("POST /v1/disconnect", s.handleDisconnect)
	return mux
}

// Connector is implemented by backends that can load and unload models on
// demand. Backends that hold no local state simply do not implement it.
type Connector interface {
	Connect(ctx context.Context, model string) error
	Disconnect(model string) bool
}

// ToolCaller is implemented by backends that can forward tool definitions to a
// model. Like Connector, it is an optional capability asked at the door: a
// backend that cannot do this does not implement it, and the server turns the
// request away rather than dropping the tools on the floor.
type ToolCaller interface {
	ToolsSupported() bool
}

func toolsSupported(b switchboard.Backend) bool {
	tc, ok := b.(ToolCaller)
	return ok && tc.ToolsSupported()
}

// handleConnect loads a model ahead of first use.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	backend, model, ok := s.adminTarget(w, r)
	if !ok {
		return
	}
	connector, canConnect := backend.(Connector)
	if !canConnect {
		writeJSON(w, http.StatusOK, map[string]any{
			"model": model, "state": "remote",
			"detail": fmt.Sprintf("%s models are always available; nothing to load", backend.Name()),
		})
		return
	}
	if err := connector.Connect(r.Context(), model); err != nil {
		s.logger.Printf("connect %s: %v", model, err)
		writeError(w, http.StatusBadGateway, "backend_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"model": model, "state": "connected"})
}

// handleDisconnect unloads a model, freeing its memory.
func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	backend, model, ok := s.adminTarget(w, r)
	if !ok {
		return
	}
	connector, canConnect := backend.(Connector)
	if !canConnect {
		writeJSON(w, http.StatusOK, map[string]any{"model": model, "state": "remote"})
		return
	}
	state := "disconnected"
	if !connector.Disconnect(model) {
		state = "was not connected"
	}
	writeJSON(w, http.StatusOK, map[string]any{"model": model, "state": state})
}

// adminTarget decodes {"model": "..."} and resolves it, reporting any failure
// to the client itself.
func (s *Server) adminTarget(w http.ResponseWriter, r *http.Request) (switchboard.Backend, string, bool) {
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
	if c, ok := s.caller(r); ok {
		r = r.WithContext(switchboard.WithCaller(r.Context(), c))
	} else if s.requireCaller {
		writeError(w, http.StatusUnauthorized, "invalid_request_error",
			"this gateway attributes spend per team: present a team key as a bearer token")
		return
	}

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

	chatReq := &switchboard.ChatRequest{
		Model:       model,
		Messages:    make([]switchboard.Message, 0, len(req.Messages)),
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

	result, err := backend.Chat(r.Context(), chatReq, func(switchboard.Chunk) error { return nil })
	if err != nil {
		s.logger.Printf("chat %s: %v", model, err)
		writeError(w, http.StatusBadGateway, "backend_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.response(id, model, result))
}

// streamChat writes the completion as server-sent events.
func (s *Server) streamChat(w http.ResponseWriter, r *http.Request, backend switchboard.Backend, req *switchboard.ChatRequest, id string) {
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

	role := string(switchboard.RoleAssistant)
	err := send(wire.ChatResponse{
		ID: id, Object: "chat.completion.chunk", Created: created, Model: req.Model,
		Choices: []wire.Choice{{Index: 0, Delta: &wire.Message{Role: role}}},
	})
	if err != nil {
		return
	}

	result, err := backend.Chat(r.Context(), req, func(c switchboard.Chunk) error {
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
func (s *Server) response(id, model string, result *switchboard.Result) wire.ChatResponse {
	finish := finishReasonFor(result)
	return wire.ChatResponse{
		ID:      id,
		Object:  "chat.completion",
		Created: s.now().Unix(),
		Model:   model,
		Choices: []wire.Choice{{
			Index: 0,
			Message: &wire.Message{
				Role:      string(switchboard.RoleAssistant),
				Content:   result.Text,
				ToolCalls: toWireToolCalls(result.ToolCalls),
			},
			FinishReason: &finish,
		}},
		Usage: usage(result),
	}
}

// toNeutralMessage converts one turn off the wire, flattening OpenAI's nested
// function object into switchboard's flat call.
func toNeutralMessage(m wire.Message) switchboard.Message {
	out := switchboard.Message{
		Role:       switchboard.Role(m.Role),
		Content:    m.Content,
		ToolCallID: m.ToolCallID,
	}
	for _, tc := range m.ToolCalls {
		out.ToolCalls = append(out.ToolCalls, switchboard.ToolCall{
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
func toNeutralTools(tools []wire.Tool) ([]switchboard.Tool, error) {
	out := make([]switchboard.Tool, 0, len(tools))
	for i, t := range tools {
		if t.Type != "" && t.Type != "function" {
			return nil, fmt.Errorf("tools[%d]: unsupported tool type %q, want \"function\"", i, t.Type)
		}
		if t.Function.Name == "" {
			return nil, fmt.Errorf("tools[%d]: function.name is required", i)
		}
		out = append(out, switchboard.Tool{
			Name:        t.Function.Name,
			Description: t.Function.Description,
			Schema:      t.Function.Parameters,
		})
	}
	return out, nil
}

// parseToolChoice decodes OpenAI's polymorphic tool_choice: either a bare
// string ("auto", "none", "required") or a named function object.
func parseToolChoice(raw json.RawMessage) (*switchboard.ToolChoice, error) {
	var mode string
	if err := json.Unmarshal(raw, &mode); err == nil {
		switch mode {
		case "auto":
			return &switchboard.ToolChoice{Mode: switchboard.ToolChoiceAuto}, nil
		case "none":
			return &switchboard.ToolChoice{Mode: switchboard.ToolChoiceNone}, nil
		case "required", "any":
			return &switchboard.ToolChoice{Mode: switchboard.ToolChoiceAny}, nil
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
	return &switchboard.ToolChoice{Mode: switchboard.ToolChoiceTool, Name: named.Function.Name}, nil
}

// toWireToolCalls renders finished calls onto a complete response.
func toWireToolCalls(calls []switchboard.ToolCall) []wire.ToolCall {
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
func toWireToolCallDelta(d switchboard.ToolCallDelta) wire.ToolCall {
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

func usage(result *switchboard.Result) *wire.Usage {
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
func finishReasonFor(result *switchboard.Result) string {
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
