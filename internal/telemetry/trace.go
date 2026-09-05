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
	return t.tracer.Start(ctx, "chat.completion",
		trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(attrs...))
}

// Finish records the outcome on a span.
//
// Attribute names follow the OpenTelemetry GenAI convention where one exists,
// so these land in the same fields as everything else emitting LLM telemetry.
// Those conventions are still marked Development, which is worth knowing rather
// than discovering: the names may move.
func Finish(span trace.Span, auditID string, promptTokens, replyTokens int, stopReason string, err error) {
	if span == nil {
		return
	}
	span.SetAttributes(
		attribute.Int("gen_ai.usage.input_tokens", promptTokens),
		attribute.Int("gen_ai.usage.output_tokens", replyTokens),
		attribute.String("switchboard.audit.id", auditID),
	)
	if stopReason != "" {
		span.SetAttributes(attribute.String("gen_ai.response.finish_reason", stopReason))
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.End()
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
func (noopSpan) SetAttributes(...attribute.KeyValue)     {}
func (noopSpan) RecordError(error, ...trace.EventOption) {}
func (noopSpan) SetStatus(codes.Code, string)            {}
func (noopSpan) SpanContext() trace.SpanContext          { return trace.SpanContext{} }
func (noopSpan) IsRecording() bool                       { return false }
