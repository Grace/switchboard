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
type Telemetry struct {
	Endpoint string   `json:"endpoint,omitempty"`
	Insecure bool     `json:"insecure,omitempty"`
	Interval Duration `json:"interval,omitempty"`
}

func (t *Telemetry) validate() error {
	if t.Endpoint == "" {
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
		Endpoint: t.Endpoint,
		Insecure: t.Insecure,
		Interval: time.Duration(t.Interval),
		Version:  version,
	}
}
