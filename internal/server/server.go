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
	"strconv"
	"strings"
	"time"

	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/config"
	"github.com/Grace/switchboard/internal/envelope"
	"github.com/Grace/switchboard/internal/limit"
	"github.com/Grace/switchboard/internal/oidc"
	"github.com/Grace/switchboard/internal/switchboard"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/Grace/switchboard/internal/telemetry"
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

	// audit records what was sent to which provider. Nil means no log.
	audit *audit.Log
	// auditRequired refuses a request whose audit entry could not be written.
	auditRequired bool

	// oidc verifies bearer tokens when an identity provider is configured.
	oidc *oidc.Verifier

	// limits bounds what a caller may consume. Nil means unlimited.
	limits *limit.Limiter

	// metrics answers the aggregate question the audit log cannot. Nil means
	// the endpoint is not served.
	metrics *telemetry.Meter
	// tracer joins this record to the caller's own traces.
	tracer *telemetry.Tracer

	// toolManifests and toolGrant bound which functions a model may be made to
	// call. Nil manifests means enforcement is off and calls are recorded
	// without being judged.
	toolManifests map[string]envelope.Manifest
	toolGrant     func(team string) envelope.Grant
}

// WithTracer adopts the caller's trace context and emits a span per completion.
func (s *Server) WithTracer(t *telemetry.Tracer) *Server {
	s.tracer = t
	return s
}

// WithMetrics records completions, refusals and redactions.
func (s *Server) WithMetrics(r *telemetry.Meter) *Server {
	s.metrics = r
	return s
}

// observe records one completion for the aggregate view.
//
// Labelled by team, model, backend and outcome — all bounded by configuration.
// Deliberately not by subject: a series per person grows without limit, and
// per-person questions belong to the audit log, which carries subject on every
// entry.
func (s *Server) observe(ctx context.Context, model, backend, outcome string, u switchboard.Usage) {
	if s.metrics == nil {
		return
	}
	var team string
	if c, ok := switchboard.CallerFrom(ctx); ok {
		team = c.Team
	}
	s.metrics.Completion(ctx, team, model, backend, outcome, u.InputTokens, u.OutputTokens)
}

// WithLimits bounds requests, concurrency and token spend per caller —
// MITRE ATLAS AML.M0004.
func (s *Server) WithLimits(l *limit.Limiter) *Server {
	s.limits = l
	return s
}

// admit applies the caller's allowance, answering 429 with enough detail to act
// on. "Slow down" and "your team has spent its budget for the day" need
// different responses from whoever is holding the error.
func (s *Server) admit(w http.ResponseWriter, r *http.Request) (func(), bool) {
	if s.limits == nil {
		return func() {}, true
	}
	var team string
	if c, ok := switchboard.CallerFrom(r.Context()); ok {
		team = c.Team
	}

	release, err := s.limits.Acquire(team)
	if err == nil {
		return release, true
	}

	var ex *limit.Exceeded
	if !errors.As(err, &ex) {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return nil, false
	}
	retry := int(ex.RetryAfter.Seconds())
	if retry < 1 {
		retry = 1
	}
	if s.metrics != nil {
		s.metrics.Refused(r.Context(), ex.Limit, team)
	}
	w.Header().Set("Retry-After", strconv.Itoa(retry))
	w.Header().Set("X-RateLimit-Limit", ex.Limit)
	writeError(w, http.StatusTooManyRequests, "rate_limit_exceeded", ex.Error())
	return nil, false
}

// charge records what a completion actually used, against the caller's budget.
func (s *Server) charge(ctx context.Context, usage switchboard.Usage) {
	if s.limits == nil {
		return
	}
	var team string
	if c, ok := switchboard.CallerFrom(ctx); ok {
		team = c.Team
	}
	// Cache reads count. They are cheaper, not free, and a budget that ignored
	// them would let a caller with a large cached prompt consume most of a
	// provider's capacity while charging almost nothing against its allowance —
	// which is the shape of the limit being bypassed rather than applied.
	s.limits.Charge(team, usage.PromptTokens()+usage.OutputTokens)
}

// WithOIDC lets the server accept identity-provider tokens as well as static
// team keys. The team a token names must still be on the roster: an identity
// provider decides who someone is, not which teams exist here.
// WithTools enforces a permission envelope over the calls a model asks for.
//
// Enforcement is on the response rather than the request: offering a tool is
// not using one, and refusing a request because it made something available
// would break applications that offer a broad toolset and use a narrow part of
// it. What is refused is the action.
//
// The cost of checking after the completion is that the tokens are already
// spent by the time a call is refused. That is the right trade — the thing
// being prevented is the action, not the expense, and refusing earlier would
// mean refusing on what a caller might do rather than on what the model did.
func (s *Server) WithTools(manifests map[string]envelope.Manifest, grant func(string) envelope.Grant) *Server {
	if len(manifests) == 0 || grant == nil {
		return s
	}
	s.toolManifests, s.toolGrant = manifests, grant
	return s
}

// checkTools decides which of the calls a model asked for may proceed.
//
// It returns the audit view of every call, refusals included, and an error when
// any was refused. Both are needed: the caller fails the request, and the log
// records what was attempted.
func (s *Server) checkTools(team string, offered []switchboard.Tool, calls []switchboard.ToolCall) ([]audit.ToolCall, error) {
	recorded := auditToolCalls(calls)
	if s.toolManifests == nil || len(calls) == 0 {
		return recorded, nil
	}
	env := envelope.Compute(auditToolsOffered(offered), s.toolManifests, s.toolGrant(team))

	var refused []string
	for i := range recorded {
		if env.Permits(recorded[i].Name) {
			continue
		}
		reason := env.Why(recorded[i].Name)
		if reason == "" {
			// The model asked for something the request never offered. That is
			// not a permission question at all, and it is worth naming
			// differently: nothing declared this call, so nothing authorised it.
			reason = "the model asked for a tool this request did not offer"
		}
		recorded[i].Refused, recorded[i].Reason = true, reason
		refused = append(refused, fmt.Sprintf("%s (%s)", recorded[i].Name, reason))
	}
	if len(refused) == 0 {
		return recorded, nil
	}
	return recorded, fmt.Errorf("refused %d tool call(s): %s",
		len(refused), strings.Join(refused, "; "))
}

func (s *Server) WithOIDC(v *oidc.Verifier) *Server {
	s.oidc = v
	return s
}

// WithAudit gives the server a log to record completions in. Redaction is the
// log's own concern: the server hands it raw content and the log decides what
// survives, so no call site here can forget to redact.
func (s *Server) WithAudit(l *audit.Log, required bool) *Server {
	s.audit, s.auditRequired = l, required
	return s
}

// record writes one completion to the audit log, if there is one.
func (s *Server) record(ctx context.Context, r audit.Record) error {
	if s.audit == nil {
		return nil
	}
	if c, ok := switchboard.CallerFrom(ctx); ok {
		r.Team, r.Subject = c.Team, c.Subject
	}
	if c, ok := conversationFrom(ctx); ok {
		r.Conversation = c
	}
	// The caller's trace id, so this entry can be found from their traces and
	// their traces from this entry.
	r.TraceID, r.SpanID = telemetry.IDs(ctx)
	if err := s.audit.Write(r); err != nil {
		n, _ := s.audit.Health()
		s.logger.Printf("audit: WRITE FAILED (%d consecutive): %v", n, err)
		return err
	}
	return nil
}

// auditable reports whether the log is healthy enough to serve.
//
// With audit.required set, a completion that cannot be recorded is refused
// before it is made. That is the same shape as every other control here: no
// record, no request. Without it, the request proceeds and the failure is
// visible through /health and the log — which is the right default only for
// deployments where availability outranks evidence.
func (s *Server) auditable(w http.ResponseWriter) bool {
	if !s.auditRequired || s.audit == nil {
		return true
	}
	if n, err := s.audit.Health(); err != nil {
		s.logger.Printf("refusing: audit log unavailable (%d consecutive failures): %v", n, err)
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable",
			"this gateway records every completion and cannot right now, so it is "+
				"refusing rather than serving unrecorded requests")
		return false
	}
	return true
}

// promptText flattens a request into the text an audit log should consider.
func promptText(req *switchboard.ChatRequest) string {
	var b strings.Builder
	for i, m := range req.Messages {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(string(m.Role))
		b.WriteString(": ")
		b.WriteString(m.Content)
	}
	return b.String()
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
	presented, ok := bearer(r.Header.Get("Authorization"))
	if !ok {
		return switchboard.Caller{}, false
	}

	// A static key first: it is a local comparison, and a deployment using
	// only keys should never depend on an identity provider being reachable.
	if team, ok := config.TeamForKey(s.teams, presented); ok {
		return switchboard.Caller{Team: team}, true
	}
	if s.oidc == nil {
		return switchboard.Caller{}, false
	}

	claims, err := s.oidc.Verify(r.Context(), presented)
	if err != nil {
		s.logger.Printf("oidc: rejected token: %v", err)
		return switchboard.Caller{}, false
	}
	team, ok := s.oidc.Team(claims)
	if !ok {
		s.logger.Printf("oidc: token for %q carries no team claim", claims.Subject)
		return switchboard.Caller{}, false
	}
	// The roster is the allowlist. Without this, any group name an identity
	// provider happens to emit would become a billable team and a session tag.
	if !knownTeam(s.teams, team) {
		s.logger.Printf("oidc: token for %q names team %q, which is not on the roster",
			claims.Subject, team)
		return switchboard.Caller{}, false
	}
	return switchboard.Caller{Team: team, Subject: claims.Subject}, true
}

type conversationKey struct{}

// Conversations are the client's to name. switchboard is stateless — every
// request carries its whole history — so nothing here can infer that two calls
// belong to the same thread. A caller that wants its turns linked in the audit
// log says so with a header.
const conversationHeader = "X-Conversation-Id"

func conversationFrom(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(conversationKey{}).(string)
	return v, ok && v != ""
}

// sanitiseConversation bounds what a client can write into the log.
func sanitiseConversation(s string) string {
	if len(s) > 128 {
		s = s[:128]
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.', r == ':':
			out = append(out, r)
		}
	}
	return string(out)
}

func knownTeam(teams []config.Team, name string) bool {
	for _, t := range teams {
		if t.Name == name {
			return true
		}
	}
	return false
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
	mux.HandleFunc("GET /health", s.handleHealth)
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

// handleHealth reports liveness, and degradation in the body rather than the
// status code. A failing audit log should page someone; it should not make a
// liveness probe restart the process, which would lose nothing and fix nothing.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if s.audit != nil {
		if n, err := s.audit.Health(); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"status":         "degraded",
				"audit":          err.Error(),
				"audit_failures": n,
			})
			return
		}
	}
	s.handleHealthOK(w, r)
}

func (s *Server) handleHealthOK(w http.ResponseWriter, r *http.Request) {
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
	// Adopt the caller's trace context first, so everything below — the span,
	// the audit entry, the metrics — hangs off the trace their request started.
	r = r.WithContext(s.tracer.Extract(r.Context(), propagation.HeaderCarrier(r.Header)))

	if id := sanitiseConversation(r.Header.Get(conversationHeader)); id != "" {
		r = r.WithContext(context.WithValue(r.Context(), conversationKey{}, id))
	}
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

	if !s.auditable(w) {
		return
	}
	release, ok := s.admit(w, r)
	if !ok {
		return
	}
	defer release()

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

	var team, subject string
	if c, ok := switchboard.CallerFrom(r.Context()); ok {
		team, subject = c.Team, c.Subject
	}
	spanCtx, span := s.tracer.Start(r.Context(), model, team, subject)
	r = r.WithContext(spanCtx)

	id := fmt.Sprintf("chatcmpl-%d", s.now().UnixNano())
	if req.Stream {
		s.streamChat(w, r, backend, chatReq, id, span)
		return
	}

	result, err := backend.Chat(r.Context(), chatReq, func(switchboard.Chunk) error { return nil })
	if err != nil {
		telemetry.Tools(span, auditToolsOffered(chatReq.Tools), nil)
		telemetry.Finish(span, id, 0, 0, "", err)
		s.logger.Printf("chat %s: %v", model, err)
		s.observe(r.Context(), model, backend.Name(), "error", switchboard.Usage{})
		_ = s.record(r.Context(), audit.Record{
			ID: id, Model: model, Backend: backend.Name(),
			Prompt: promptText(chatReq), Error: err.Error(),
			ToolsOffered: auditToolsOffered(chatReq.Tools),
		})
		writeError(w, http.StatusBadGateway, "backend_error", err.Error())
		return
	}
	calls, toolErr := s.checkTools(teamOf(r.Context()), chatReq.Tools, result.ToolCalls)
	telemetry.Tools(span, auditToolsOffered(chatReq.Tools), traceTools(result.ToolCalls))
	telemetry.Finish(span, id, result.Usage.InputTokens, result.Usage.OutputTokens, result.StopReason, toolErr)
	s.charge(r.Context(), result.Usage)
	s.observe(r.Context(), model, backend.Name(), okOrRefused(toolErr), result.Usage)
	rec := audit.Record{
		ID: id, Model: model, Backend: backend.Name(),
		ModelID: result.ModelID, ProviderModel: result.ProviderModel,
		Prompt: promptText(chatReq), Completion: result.Text,
		PromptTokens:     result.Usage.InputTokens,
		CompletionTokens: result.Usage.OutputTokens,
		CacheWriteTokens: result.Usage.CacheWriteTokens,
		CacheReadTokens:  result.Usage.CacheReadTokens,
		ToolsOffered:     auditToolsOffered(chatReq.Tools),
		ToolCalls:        calls,
		StopReason:       result.StopReason,
	}
	if toolErr != nil {
		rec.Error = toolErr.Error()
	}
	_ = s.record(r.Context(), rec)
	// The record is written before the refusal is returned. An attempted
	// escalation that was stopped is exactly the event this log exists for,
	// and failing the request first would risk losing it.
	if toolErr != nil {
		s.logger.Printf("chat %s: %v", model, toolErr)
		writeError(w, http.StatusForbidden, "tool_not_permitted", toolErr.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.response(id, model, result))
}

// streamChat writes the completion as server-sent events.
func (s *Server) streamChat(w http.ResponseWriter, r *http.Request, backend switchboard.Backend, req *switchboard.ChatRequest, id string, span trace.Span) {
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
		telemetry.Tools(span, auditToolsOffered(req.Tools), nil)
		telemetry.Finish(span, id, 0, 0, "", err)
		s.observe(r.Context(), req.Model, backend.Name(), "error", switchboard.Usage{})
		_ = s.record(r.Context(), audit.Record{
			ID: id, Model: req.Model, Backend: backend.Name(), Streamed: true,
			Prompt: promptText(req), Error: err.Error(),
			ToolsOffered: auditToolsOffered(req.Tools),
		})
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

	calls, toolErr := s.checkTools(teamOf(r.Context()), req.Tools, result.ToolCalls)
	telemetry.Tools(span, auditToolsOffered(req.Tools), traceTools(result.ToolCalls))
	telemetry.Finish(span, id, result.Usage.InputTokens, result.Usage.OutputTokens, result.StopReason, toolErr)
	s.charge(r.Context(), result.Usage)
	s.observe(r.Context(), req.Model, backend.Name(), okOrRefused(toolErr), result.Usage)
	rec := audit.Record{
		ID: id, Model: req.Model, Backend: backend.Name(), Streamed: true,
		Prompt: promptText(req), Completion: result.Text,
		PromptTokens:     result.Usage.InputTokens,
		CompletionTokens: result.Usage.OutputTokens,
		CacheWriteTokens: result.Usage.CacheWriteTokens,
		CacheReadTokens:  result.Usage.CacheReadTokens,
		ToolsOffered:     auditToolsOffered(req.Tools),
		ToolCalls:        calls,
		StopReason:       result.StopReason,
	}
	if toolErr != nil {
		rec.Error = toolErr.Error()
	}
	_ = s.record(r.Context(), rec)

	// A refusal on the streaming path is weaker than on the non-streaming one,
	// and pretending otherwise would be the worst thing this code could do.
	//
	// Tool-call deltas are forwarded as the backend produces them, so by the
	// time the call is complete enough to check, a client assembling deltas has
	// already seen it. What this does is refuse to send the final frame that
	// completes the call, emit an error, and write the refusal down. It stops a
	// client that waits for the finish reason; it does not stop one that acts on
	// deltas. A deployment that needs tool enforcement to be a control rather
	// than a signal should not offer tools on streaming requests — see
	// docs/tools.md.
	if toolErr != nil {
		s.logger.Printf("chat %s: %v", req.Model, toolErr)
		if r.Context().Err() == nil {
			data, _ := json.Marshal(wire.ErrorResponse{Error: wire.Error{
				Message: toolErr.Error(),
				Type:    "tool_not_permitted",
			}})
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
			fmt.Fprint(w, "data: [DONE]\n\n")
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
	return s.listenAndServe(ctx, addr, TLS{})
}

// ListenAndServeTLS serves over TLS, optionally requiring client certificates.
func (s *Server) ListenAndServeTLS(ctx context.Context, addr string, t TLS) error {
	return s.listenAndServe(ctx, addr, t)
}

func (s *Server) listenAndServe(ctx context.Context, addr string, t TLS) error {
	tlsCfg, err := t.config()
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:    addr,
		Handler: s.Handler(),
		// No write timeout: a long generation is a long response, and cutting
		// it off mid-stream is worse than an idle connection.
		ReadHeaderTimeout: 15 * time.Second,
		TLSConfig:         tlsCfg,
	}

	errc := make(chan error, 1)
	go func() {
		if tlsCfg != nil {
			// Paths are already in TLSConfig; passing them again would reload
			// and could pick up a different file.
			errc <- srv.ListenAndServeTLS("", "")
			return
		}
		errc <- srv.ListenAndServe()
	}()

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

// auditTools renders a request's tool definitions and a result's tool calls for
// the audit record.
//
// Offered and invoked are both recorded because neither answers the other's
// question. Offered bounds what the model could have done; invoked is what it
// did. A record with only the second cannot show that a call was outside the
// permissions in force, which is the finding an incident review is looking for.
func auditToolsOffered(tools []switchboard.Tool) []string {
	if len(tools) == 0 {
		return nil
	}
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		names = append(names, t.Name)
	}
	return names
}

func auditToolCalls(calls []switchboard.ToolCall) []audit.ToolCall {
	if len(calls) == 0 {
		return nil
	}
	out := make([]audit.ToolCall, 0, len(calls))
	for _, c := range calls {
		out = append(out, audit.ToolCall{Name: c.Name, ID: c.ID, Arguments: c.Arguments})
	}
	return out
}

// teamOf names the caller, or the sentinel for one that presented nothing.
func teamOf(ctx context.Context) string {
	if c, ok := switchboard.CallerFrom(ctx); ok {
		return c.Team
	}
	return ""
}

// okOrRefused labels the metric. A refused call is not a backend error and
// should not be counted as one — the backend did its job; the gateway declined
// the result.
func okOrRefused(err error) string {
	if err != nil {
		return "refused"
	}
	return "ok"
}

// traceTools is the same information stripped of arguments, for the span. The
// two conversions are separate rather than one shared shape precisely so that
// adding an argument to the trace has to be a deliberate act.
func traceTools(calls []switchboard.ToolCall) []telemetry.Invocation {
	if len(calls) == 0 {
		return nil
	}
	out := make([]telemetry.Invocation, 0, len(calls))
	for _, c := range calls {
		out = append(out, telemetry.Invocation{Name: c.Name, ID: c.ID})
	}
	return out
}
