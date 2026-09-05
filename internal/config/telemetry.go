package config

import (
	"fmt"
	"net"
	"time"

	"github.com/Grace/switchboard/internal/telemetry"
)

// Telemetry exports aggregates over OTLP.
//
// The audit log reconstructs any single decision and says nothing about trends.
// This is the other half: what a team spent, which models, how often a limit
// refused someone. Off unless an endpoint is configured — a gateway should not
// start emitting somewhere by default.
//
// There is deliberately no `headers` field, and its absence is the feature.
// Every hosted OTLP backend authenticates with one — Honeycomb wants
// x-honeycomb-team, Grafana Cloud basic auth, Datadog DD-API-KEY — which makes
// headers credentials, and switchboard does not keep credentials in a config
// file. The exporter reads the standard environment variable instead:
//
//	export OTEL_EXPORTER_OTLP_HEADERS="x-honeycomb-team=KEY"
//	"telemetry": { "endpoint": "api.honeycomb.io:443", "interval": "60s" }
//
// Attributes follow the OpenTelemetry GenAI semantic conventions, so any OTLP
// backend understands the spans without an adapter. Each span carries
// switchboard.audit.id, which is the join back to the audit entry: the span
// expires on your observability vendor's retention, the record does not.
type Telemetry struct {
	Endpoint string   `json:"endpoint,omitempty"`
	Insecure bool     `json:"insecure,omitempty"`
	Interval Duration `json:"interval,omitempty"`
	// IncludeSubject puts the calling identity on exported spans, so per-person
	// investigation can happen in your tracing tool rather than only in the
	// audit log. Never on metrics: a label per person is unbounded.
	IncludeSubject bool `json:"include_subject,omitempty"`
}

func (t *Telemetry) validate() error {
	if t.Endpoint == "" {
		if t.IncludeSubject {
			return fmt.Errorf("telemetry.include_subject without telemetry.endpoint: nothing would be exported")
		}
		if t.Insecure || t.Interval != 0 {
			return fmt.Errorf("telemetry settings without telemetry.endpoint: nothing would be exported")
		}
		return nil
	}
	if _, _, err := net.SplitHostPort(t.Endpoint); err != nil {
		return fmt.Errorf("telemetry.endpoint %q should be host:port for an OTLP/HTTP receiver", t.Endpoint)
	}
	if d := time.Duration(t.Interval); d != 0 && d < time.Second {
		return fmt.Errorf("telemetry.interval of %s is shorter than any receiver wants", d)
	}
	return nil
}

// Options renders the runtime form.
func (t Telemetry) Options(version string) telemetry.Config {
	return telemetry.Config{
		Endpoint:       t.Endpoint,
		Insecure:       t.Insecure,
		Interval:       time.Duration(t.Interval),
		IncludeSubject: t.IncludeSubject,
		Version:        version,
	}
}
