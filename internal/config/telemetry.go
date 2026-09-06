package config

import (
	"fmt"
	"net"
	"os"
	"strings"
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
	// Headers go on every OTLP request, which is how a hosted backend
	// authenticates: Honeycomb wants x-honeycomb-team. Without them switchboard
	// can reach a collector on your own network and nothing beyond it.
	//
	// A value of "env:NAME" is read from the environment at startup. Put the
	// key there rather than in this file — it is a credential for somebody
	// else's system, this file gets committed, and an approver reviewing a
	// configuration change should not be reading secrets to do it.
	Headers map[string]string `json:"headers,omitempty"`
}

// EnvPrefix marks a header value to be read from the environment.
const EnvPrefix = "env:"

// ResolveHeaders reads any env: indirections.
//
// It fails rather than sending an empty header. An OTLP endpoint that rejects
// an unauthenticated request produces an export error in a log nobody reads,
// and the first sign of trouble is a dashboard that was quietly empty for a
// week — so a missing variable stops startup instead.
func (t Telemetry) ResolveHeaders() (map[string]string, error) {
	if len(t.Headers) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(t.Headers))
	for k, v := range t.Headers {
		if !strings.HasPrefix(v, EnvPrefix) {
			out[k] = v
			continue
		}
		name := strings.TrimPrefix(v, EnvPrefix)
		got := os.Getenv(name)
		if got == "" {
			return nil, fmt.Errorf("telemetry.headers[%q] reads %s and %s is unset or empty",
				k, name, name)
		}
		out[k] = got
	}
	return out, nil
}

func (t *Telemetry) validate() error {
	if t.Endpoint == "" {
		if t.IncludeSubject {
			return fmt.Errorf("telemetry.include_subject without telemetry.endpoint: nothing would be exported")
		}
		if t.Insecure || t.Interval != 0 || len(t.Headers) > 0 {
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
//
// Headers and policy are supplied by the caller rather than read here: one
// resolves credentials from the environment and can fail, and the other is a
// digest of the whole configuration, so neither belongs in a struct conversion.
func (t Telemetry) Options(version string, headers map[string]string, policy string) telemetry.Config {
	return telemetry.Config{
		Endpoint:       t.Endpoint,
		Insecure:       t.Insecure,
		Interval:       time.Duration(t.Interval),
		IncludeSubject: t.IncludeSubject,
		Version:        version,
		Headers:        headers,
		Policy:         policy,
	}
}
