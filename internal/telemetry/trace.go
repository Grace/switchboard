package telemetry

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Traces are what make the audit log joinable.
//
// Metrics say a team spent forty thousand dollars. A trace says which user
// request that spend happened inside, and the audit entry says what the rules
// were and proves nobody edited it since. Each is weak alone: an aggregate you
// cannot drill into, a trace with no integrity guarantee, a record you cannot
// correlate with anything.
//
// The link is the caller's own trace context. A request arriving with a
// traceparent header belongs to a trace that started in their application, and
// carrying that id onto the audit entry means an investigation can move between
// their observability and this record without matching timestamps by hand.

// Tracer emits one span per completion.
type Tracer struct {
	tracer         trace.Tracer
	prop           propagation.TextMapPropagator
	includeSubject bool
	policy         string
	shutdown       func(context.Context) error
}

// NewTracer builds a tracer exporting to an OTLP receiver. An empty endpoint
// disables tracing without disabling metrics.
func NewTracer(ctx context.Context, cfg Config) (*Tracer, error) {
	if cfg.Endpoint == "" {
		return nil, nil
	}
	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(cfg.Endpoint)}
	if cfg.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
	}
	exp, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("otlp trace exporter: %w", err)
	}

	res, err := resourceFor(cfg.Version)
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exp, sdktrace.WithBatchTimeout(5*time.Second)),
	)
	otel.SetTracerProvider(tp)

	// W3C trace context, so a caller's traceparent is honoured and ours is
	// propagated onward. Baggage is deliberately absent: it is a channel for
	// arbitrary caller-controlled key-values, and this is a trust boundary.
	prop := propagation.TraceContext{}
	otel.SetTextMapPropagator(prop)

	return &Tracer{
		tracer:         tp.Tracer("github.com/Grace/switchboard"),
		prop:           prop,
		includeSubject: cfg.IncludeSubject,
		policy:         cfg.Policy,
		shutdown:       tp.Shutdown,
	}, nil
}

// Extract adopts the caller's trace context, if it sent one.
func (t *Tracer) Extract(ctx context.Context, carrier propagation.TextMapCarrier) context.Context {
	if t == nil {
		return ctx
	}
	return t.prop.Extract(ctx, carrier)
}

// Start opens a span for one completion.
//
// Subject goes here rather than on a metric, when it goes anywhere at all.
// The two have different economics: a metric label per person creates an
// unbounded number of time series and breaks the backend, while a span
// attribute per person is ordinary — finding everything one user did is what a
// tracing tool is for.
//
// It is still opt-in, because it means an identity leaves the process. Off, the
// export identifies nobody; on, per-person investigation happens in the tool
// the team already uses rather than only in the log.
func (t *Tracer) Start(ctx context.Context, model, team, subject string) (context.Context, trace.Span) {
	if t == nil {
		return ctx, noopSpan{}
	}
	attrs := []attribute.KeyValue{
		attribute.String("gen_ai.request.model", model),
		attribute.String("switchboard.team", or(team, "unattributed")),
	}
	if t.includeSubject && subject != "" {
		attrs = append(attrs, attribute.String("enduser.id", subject))
	}
	// The rules this request was judged under. An exported event lives in a
	// backend that samples and expires; the fingerprint is what lets one that
	// survives be resolved against the archived configuration, months after the
	// event itself is gone.
	if t.policy != "" {
		attrs = append(attrs, attribute.String("switchboard.policy", t.policy))
	}
	return t.tracer.Start(ctx, "chat.completion",
		trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(attrs...))
}

// Outcome is what a completion produced, minus content.
//
// A struct rather than a longer argument list because this is the wide event —
// Honeycomb's model, and the one this design already suited: one rich row per
// unit of work, sliced afterwards on whichever field turns out to matter. Every
// field here is on the audit record too. The difference is not what is
// exported but what is guaranteed about it: this copy is sampled and expires,
// and the record is neither.
type Outcome struct {
	AuditID string
	Backend string
	// ModelID is what this gateway sent; ProviderModel is what the provider
	// said served it. Two different claims, kept apart here as in the log.
	ModelID       string
	ProviderModel string

	PromptTokens     int
	ReplyTokens      int
	CacheWriteTokens int
	CacheReadTokens  int

	StopReason string
	Streamed   bool
	// Recorded reports whether this completion reached the audit log. False is
	// the interesting value: a request that happened and was not recorded is
	// precisely the gap the evidence tier exists to close, and it should be
	// visible in the tool people actually watch.
	Recorded bool
}

// Finish records the outcome on a span.
//
// Attribute names follow the OpenTelemetry GenAI convention where one exists,
// so these land in the same fields as everything else emitting LLM telemetry.
// Those conventions are still marked Development, which is worth knowing rather
// than discovering: the names may move.
func Finish(span trace.Span, o Outcome, err error) {
	if span == nil {
		return
	}
	span.SetAttributes(
		attribute.Int("gen_ai.usage.input_tokens", o.PromptTokens),
		attribute.Int("gen_ai.usage.output_tokens", o.ReplyTokens),
		attribute.String("switchboard.audit.id", o.AuditID),
		attribute.Bool("switchboard.audit.recorded", o.Recorded),
	)
	// Cached tokens are their own fields, not folded into input. They are
	// billed at a different rate by up to an order of magnitude, so a chart
	// that sums them is a cost chart that is wrong for exactly the deployments
	// with a large stable prompt.
	if o.CacheWriteTokens > 0 {
		span.SetAttributes(attribute.Int("gen_ai.usage.cache_write_tokens", o.CacheWriteTokens))
	}
	if o.CacheReadTokens > 0 {
		span.SetAttributes(attribute.Int("gen_ai.usage.cache_read_tokens", o.CacheReadTokens))
	}
	if o.Backend != "" {
		span.SetAttributes(attribute.String("switchboard.backend", o.Backend))
	}
	if o.ModelID != "" {
		span.SetAttributes(attribute.String("switchboard.model_id", o.ModelID))
	}
	// The provider's own answer, under the convention's response-model field,
	// and only where a provider gives one. Filling it from our own routing
	// would turn a configuration value into an attestation from somebody else.
	if o.ProviderModel != "" {
		span.SetAttributes(attribute.String("gen_ai.response.model", o.ProviderModel))
	}
	if o.Streamed {
		span.SetAttributes(attribute.Bool("switchboard.streamed", true))
	}
	if o.StopReason != "" {
		span.SetAttributes(attribute.String("gen_ai.response.finish_reason", o.StopReason))
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.End()
}

// Invocation is one tool call, reduced to what may leave the process.
type Invocation struct {
	Name string
	ID   string
	// Refused marks a call the gateway would not pass back, and Reason says
	// why. A refusal is the highest-signal thing on this span: it is either an
	// attack that was stopped or a permission somebody needs and lacks, and a
	// trace showing only the calls that succeeded is silent about both.
	Refused bool
	Reason  string
}

// Tools records what the model was permitted to do and what it did.
//
// Names and call ids only, never arguments. This is the boundary that matters:
// telemetry leaves for a collector switchboard does not control and has no
// redaction step of its own, while an argument to transfer_funds is content and
// carries whatever the model put in it. Content goes to the audit log behind
// the redactor, or nowhere. A trace that showed the argument would route around
// the one chokepoint the whole design depends on.
//
// Offered is recorded alongside called because the gap between them is the
// interesting part, and because a trace showing only the calls cannot show that
// one fell outside the permissions in force.
func Tools(span trace.Span, offered []string, called []Invocation) {
	if span == nil || (len(offered) == 0 && len(called) == 0) {
		return
	}
	if len(offered) > 0 {
		span.SetAttributes(attribute.StringSlice("switchboard.tools.offered", offered))
	}
	refused := 0
	for _, c := range called {
		if c.Refused {
			refused++
		}
	}
	span.SetAttributes(attribute.Int("gen_ai.tool.call_count", len(called)))
	if refused > 0 {
		// Its own attribute rather than something to be derived from the
		// events: this is the field somebody builds an alert on, and a count
		// that has to be computed from a nested list will not be.
		span.SetAttributes(attribute.Int("switchboard.tools.refused", refused))
	}
	for _, c := range called {
		attrs := []attribute.KeyValue{attribute.String("gen_ai.tool.name", c.Name)}
		if c.ID != "" {
			attrs = append(attrs, attribute.String("gen_ai.tool.call.id", c.ID))
		}
		if c.Refused {
			attrs = append(attrs, attribute.Bool("switchboard.tool.refused", true))
			if c.Reason != "" {
				attrs = append(attrs, attribute.String("switchboard.tool.refusal_reason", c.Reason))
			}
		}
		// One event per call rather than one attribute listing them: a tool
		// called twice in a turn is two things that happened, and an attribute
		// would collapse them into a set.
		span.AddEvent("gen_ai.tool.call", trace.WithAttributes(attrs...))
	}
}

// IDs returns the trace and span ids on a context, for the audit record.
func IDs(ctx context.Context) (traceID, spanID string) {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return "", ""
	}
	return sc.TraceID().String(), sc.SpanID().String()
}

func (t *Tracer) Shutdown(ctx context.Context) error {
	if t == nil || t.shutdown == nil {
		return nil
	}
	return t.shutdown(ctx)
}

type noopSpan struct{ trace.Span }

func (noopSpan) End(...trace.SpanEndOption)              {}
func (noopSpan) AddEvent(string, ...trace.EventOption)   {}
func (noopSpan) SetAttributes(...attribute.KeyValue)     {}
func (noopSpan) RecordError(error, ...trace.EventOption) {}
func (noopSpan) SetStatus(codes.Code, string)            {}
func (noopSpan) SpanContext() trace.SpanContext          { return trace.SpanContext{} }
func (noopSpan) IsRecording() bool                       { return false }
