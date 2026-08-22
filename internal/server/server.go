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
		chatReq.Messages = append(chatReq.Messages, golem.Message{
			Role:    golem.Role(m.Role),
			Content: m.Content,
		})
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
		return send(wire.ChatResponse{
			ID: id, Object: "chat.completion.chunk", Created: created, Model: req.Model,
			Choices: []wire.Choice{{Index: 0, Delta: &wire.Message{Content: c.Text}}},
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

	finish := finishReason(result.StopReason)
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
	finish := finishReason(result.StopReason)
	return wire.ChatResponse{
		ID:      id,
		Object:  "chat.completion",
		Created: s.now().Unix(),
		Model:   model,
		Choices: []wire.Choice{{
			Index:        0,
			Message:      &wire.Message{Role: string(golem.RoleAssistant), Content: result.Text},
			FinishReason: &finish,
		}},
		Usage: usage(result),
	}
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
