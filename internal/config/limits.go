package config

import (
	"fmt"
	"time"

	"github.com/Grace/switchboard/internal/limit"
)

// Limits bounds what callers may consume — MITRE ATLAS AML.M0004.
//
// Visibility tells you spend climbed. This is what stops it. A zero field is
// unlimited, so a partial configuration restricts only what it names.
type Limits struct {
	Enabled bool `json:"enabled"`
	// Window is the period a token budget is measured over.
	Window Duration `json:"window,omitempty"`
	// Default applies to any team without its own allowance.
	Default TeamLimits `json:"default,omitempty"`
}

// TeamLimits is one allowance.
type TeamLimits struct {
	RequestsPerMinute int `json:"requests_per_minute,omitempty"`
	Concurrent        int `json:"concurrent,omitempty"`
	TokensPerWindow   int `json:"tokens_per_window,omitempty"`
}

func (t TeamLimits) to(window time.Duration) limit.Limits {
	return limit.Limits{
		RequestsPerMinute: t.RequestsPerMinute,
		Concurrent:        t.Concurrent,
		TokensPerWindow:   t.TokensPerWindow,
		Window:            window,
	}
}

func (l *Limits) validate(teams []Team) error {
	if !l.Enabled {
		return nil
	}
	if l.Window == 0 {
		l.Window = Duration(24 * time.Hour)
	}
	if time.Duration(l.Window) < time.Minute {
		return fmt.Errorf("limits.window of %s is too short to be a budget period",
			time.Duration(l.Window))
	}

	all := append([]TeamLimits{l.Default}, func() []TeamLimits {
		var out []TeamLimits
		for _, t := range teams {
			out = append(out, t.Limits)
		}
		return out
	}()...)
	for _, t := range all {
		if t.RequestsPerMinute < 0 || t.Concurrent < 0 || t.TokensPerWindow < 0 {
			return fmt.Errorf("limits must not be negative; use 0 for unlimited")
		}
	}

	empty := l.Default.RequestsPerMinute == 0 && l.Default.Concurrent == 0 && l.Default.TokensPerWindow == 0
	if empty {
		anyTeam := false
		for _, t := range teams {
			lt := t.Limits
			if lt.RequestsPerMinute != 0 || lt.Concurrent != 0 || lt.TokensPerWindow != 0 {
				anyTeam = true
			}
		}
		if !anyTeam {
			return fmt.Errorf("limits.enabled but nothing is limited: set limits.default " +
				"or an allowance on a team")
		}
	}
	return nil
}

// Build constructs the limiter.
func (c *Config) Limiter() *limit.Limiter {
	if !c.Limits.Enabled {
		return nil
	}
	window := time.Duration(c.Limits.Window)
	per := map[string]limit.Limits{}
	for _, t := range c.Teams {
		lt := t.Limits
		if lt.RequestsPerMinute != 0 || lt.Concurrent != 0 || lt.TokensPerWindow != 0 {
			per[t.Name] = lt.to(window)
		}
	}
	return limit.New(c.Limits.Default.to(window), per)
}
