// Package telemetry answers the aggregate question the audit log cannot.
//
// The log reconstructs any single decision perfectly and says nothing about
// trends, so "team X burned forty thousand dollars last month, what happened"
// cannot be answered from it without reading every entry. That question is
// aggregate by nature, and aggregates belong in whatever the operator already
// runs.
//
// OTLP rather than a bespoke endpoint, because the destinations that matter
// here — Splunk, Databricks, Honeycomb, Grafana, a collector fanning out to all
// of them — ingest it natively. The cost is a dependency tree, which is a real
// change to a project whose go.mod was the standard library and the AWS SDK.
package telemetry

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/resource"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// Meter records what happened, in aggregate.
//
// Attributes are bounded by configuration rather than by traffic. The tempting
// one is the label that would ruin it: a series per user grows without limit.
// Per-person questions are audit-log questions — the log carries subject on
// every entry — so nothing here does.
type Meter struct {
	requests   metric.Int64Counter
	promptTok  metric.Int64Counter
	replyTok   metric.Int64Counter
	refusals   metric.Int64Counter
	redactions metric.Int64Counter

	shutdown func(context.Context) error
}

// Config describes where telemetry goes.
type Config struct {
	// Endpoint is an OTLP/HTTP receiver, host:port. Empty disables telemetry
	// entirely rather than falling back to something surprising.
	Endpoint string
	// Insecure sends over plain HTTP, for a collector on the same host.
	Insecure bool
	// Interval bounds how stale an aggregate can be.
	Interval time.Duration
	// IncludeSubject puts the calling identity on spans — never on metrics,
	// where a label per person is unbounded. Off by default: it means an
	// identity leaves the process.
	IncludeSubject bool
	Version        string
	// Headers go on every OTLP request. A hosted backend authenticates this
	// way — Honeycomb wants x-honeycomb-team — and without them switchboard
	// can reach a local collector and nothing else.
	//
	// Resolved before they get here, so this package never reads the
	// environment: a secret should enter the process at one place that can
	// fail loudly, not wherever it happens to be needed.
	Headers map[string]string
	// Policy is the fingerprint of the configuration in force. It goes on every
	// span, which is what lets an event in a sampled, expiring backend be
	// resolved against the archived configuration that produced it.
	Policy string
}

// New builds a meter exporting to an OTLP receiver.
//
// It does not reach the network here. A collector that is briefly down should
// not stop a gateway from starting, and the SDK retries on its own.
func New(ctx context.Context, cfg Config) (*Meter, error) {
	if cfg.Endpoint == "" {
		return nil, nil
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}

	opts := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpoint(cfg.Endpoint)}
	if cfg.Insecure {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlpmetrichttp.WithHeaders(cfg.Headers))
	}
	exp, err := otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("otlp exporter: %w", err)
	}

	// Schemaless deliberately: merging a versioned resource with the SDK's
	// default fails whenever the two semconv versions differ, which is a
	// dependency-bump away at any time. The attribute names are the stable part.
	res, err := resourceFor(cfg.Version)
	if err != nil {
		return nil, err
	}

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp,
			sdkmetric.WithInterval(cfg.Interval))),
	)
	otel.SetMeterProvider(provider)

	m := provider.Meter("github.com/Grace/switchboard")
	mt := &Meter{shutdown: provider.Shutdown}

	var errs error
	mk := func(name, desc, unit string) metric.Int64Counter {
		c, err := m.Int64Counter(name, metric.WithDescription(desc), metric.WithUnit(unit))
		if err != nil && errs == nil {
			errs = err
		}
		return c
	}
	mt.requests = mk("switchboard.requests", "Completions handled.", "{request}")
	mt.promptTok = mk("switchboard.prompt_tokens", "Prompt tokens consumed.", "{token}")
	mt.replyTok = mk("switchboard.completion_tokens", "Completion tokens produced.", "{token}")
	mt.refusals = mk("switchboard.refusals", "Requests refused, by the limit that refused them.", "{request}")
	mt.redactions = mk("switchboard.redactions", "Values removed before anything was written down.", "{value}")
	if errs != nil {
		return nil, errs
	}
	return mt, nil
}

// Completion records one served or failed completion.
func (m *Meter) Completion(ctx context.Context, team, model, backend, outcome string, promptTokens, replyTokens int) {
	if m == nil {
		return
	}
	attrs := metric.WithAttributes(
		attribute.String("team", or(team, "unattributed")),
		attribute.String("model", model),
		attribute.String("backend", backend),
		attribute.String("outcome", outcome),
	)
	m.requests.Add(ctx, 1, attrs)
	if promptTokens > 0 {
		m.promptTok.Add(ctx, int64(promptTokens), attrs)
	}
	if replyTokens > 0 {
		m.replyTok.Add(ctx, int64(replyTokens), attrs)
	}
}

// Refused records a request turned away by a limit.
func (m *Meter) Refused(ctx context.Context, limit, team string) {
	if m == nil {
		return
	}
	m.refusals.Add(ctx, 1, metric.WithAttributes(
		attribute.String("limit", limit),
		attribute.String("team", or(team, "unattributed")),
	))
}

// Redacted records what the redactor removed, by rule.
//
// The count travels; the value never does. Knowing that eleven thousand email
// addresses were removed last week is useful, and is not the same as keeping
// any of them.
func (m *Meter) Redacted(ctx context.Context, counts map[string]int) {
	if m == nil {
		return
	}
	for rule, n := range counts {
		m.redactions.Add(ctx, int64(n), metric.WithAttributes(attribute.String("rule", rule)))
	}
}

// Shutdown flushes pending exports.
func (m *Meter) Shutdown(ctx context.Context) error {
	if m == nil || m.shutdown == nil {
		return nil
	}
	return m.shutdown(ctx)
}

func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// resourceFor identifies this process to a receiver.
//
// Schemaless deliberately: merging a versioned resource with the SDK's default
// fails whenever the two semconv versions differ, which is a dependency bump
// away at any time. The attribute names are the stable part.
func resourceFor(version string) (*resource.Resource, error) {
	return resource.Merge(resource.Default(), resource.NewSchemaless(
		attribute.String("service.name", "switchboard"),
		attribute.String("service.version", version),
	))
}
