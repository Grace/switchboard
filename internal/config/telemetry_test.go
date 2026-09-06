package config

import (
	"strings"
	"testing"
)

// The credential for somebody else's system does not belong in a file that gets
// committed and reviewed.
func TestHeadersResolveFromTheEnvironment(t *testing.T) {
	t.Setenv("HONEYCOMB_API_KEY", "hcaik_secret")
	tel := Telemetry{
		Endpoint: "api.honeycomb.io:443",
		Headers: map[string]string{
			"x-honeycomb-team":    "env:HONEYCOMB_API_KEY",
			"x-honeycomb-dataset": "switchboard",
		},
	}
	got, err := tel.ResolveHeaders()
	if err != nil {
		t.Fatal(err)
	}
	if got["x-honeycomb-team"] != "hcaik_secret" {
		t.Errorf("api key = %q", got["x-honeycomb-team"])
	}
	if got["x-honeycomb-dataset"] != "switchboard" {
		t.Errorf("a literal value should pass through, got %q", got["x-honeycomb-dataset"])
	}
}

// An unauthenticated export fails in a log nobody reads, and the first sign of
// trouble is a dashboard that was quietly empty for a week.
func TestAMissingVariableStopsStartup(t *testing.T) {
	tel := Telemetry{
		Endpoint: "api.honeycomb.io:443",
		Headers:  map[string]string{"x-honeycomb-team": "env:NOT_SET_ANYWHERE"},
	}
	_, err := tel.ResolveHeaders()
	if err == nil {
		t.Fatal("a missing variable was accepted")
	}
	if !strings.Contains(err.Error(), "NOT_SET_ANYWHERE") {
		t.Errorf("the error should name the variable: %v", err)
	}
}

// An empty variable is the same failure as a missing one and is easier to
// create: an unset shell variable expands to nothing.
func TestAnEmptyVariableIsRefused(t *testing.T) {
	t.Setenv("EMPTY_KEY", "")
	tel := Telemetry{
		Endpoint: "api.honeycomb.io:443",
		Headers:  map[string]string{"x-honeycomb-team": "env:EMPTY_KEY"},
	}
	if _, err := tel.ResolveHeaders(); err == nil {
		t.Fatal("an empty variable was accepted")
	}
}

func TestHeadersWithoutAnEndpointAreRefused(t *testing.T) {
	tel := Telemetry{Headers: map[string]string{"x-honeycomb-team": "k"}}
	if err := tel.validate(); err == nil {
		t.Fatal("headers with nothing to send them to were accepted")
	}
}

func TestNoHeadersIsNil(t *testing.T) {
	got, err := Telemetry{Endpoint: "localhost:4318"}.ResolveHeaders()
	if err != nil || got != nil {
		t.Fatalf("got %v, %v", got, err)
	}
}
