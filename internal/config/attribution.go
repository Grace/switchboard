package config

import (
	"crypto/subtle"
	"fmt"
	"regexp"
)

// Attribution turns one gateway identity back into many billable ones.
//
// A provider attributes spend to the IAM principal that called it. Behind a
// gateway that is always the gateway's own role, so every team's usage arrives
// as one line on the bill. AWS's answer for proxies is to assume a role per
// caller, passing the caller as the session name and the attributes as session
// tags, which surface in Cost and Usage Report 2.0 under an `iamPrincipal/`
// prefix once activated as cost allocation tags.
//
// switchboard cannot invent an identity it was never given, so `teams` is both
// the key list and the chargeback roster — one roster, two uses.
//
// They are not, however, one switch. Requiring callers to authenticate is
// independent of assuming a role per caller: a deployment serving only local
// models has nothing to attribute to a provider bill and every reason to demand
// a credential. Enabled turns on role assumption; RequireCaller turns on
// authentication; neither implies the other.
type Attribution struct {
	// Enabled turns per-caller role assumption on.
	Enabled bool `json:"enabled"`
	// RoleARN is the role switchboard assumes on behalf of each caller. Its
	// trust policy must allow the gateway's own principal to sts:AssumeRole
	// and sts:TagSession.
	RoleARN string `json:"role_arn,omitempty"`
	// TagKey is the session tag carrying the team. Activate it as a cost
	// allocation tag in Billing before it appears in Cost Explorer.
	TagKey string `json:"tag_key,omitempty"`
	// SessionDuration bounds the assumed credentials. Shorter means more STS
	// calls; credentials are cached and refreshed before expiry either way.
	SessionDuration Duration `json:"session_duration,omitempty"`
	// RequireCaller rejects unattributed requests instead of serving them
	// against the gateway's own role. Fail closed: an unattributed request is
	// spend nobody is accountable for.
	RequireCaller bool `json:"require_caller"`
}

// Team is one attribution unit and the keys that authenticate as it.
type Team struct {
	Name string   `json:"name"`
	Keys []string `json:"keys"`
	// Limits overrides the default allowance for this team.
	Limits TeamLimits `json:"limits,omitempty"`
}

// AWS constrains both, and a violation is a runtime error from STS rather than
// anything switchboard can recover from — so it is a config error instead.
var (
	sessionNameOK = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)
	tagValueOK    = regexp.MustCompile(`^[\w\s+=.:/@-]{1,256}$`)
)

func (a *Attribution) validate(teams []Team, oidcEnabled bool) error {
	// The roster is checked whenever one exists. It used to be skipped entirely
	// unless provider attribution was on, which meant a four-character key in a
	// local-only deployment was accepted in silence.
	if err := validateRoster(teams, a.Enabled); err != nil {
		return err
	}

	// Authentication stands alone. What it needs is not attribution but some
	// way to recognise a caller at all.
	if a.RequireCaller && !oidcEnabled && !anyTeamHasKeys(teams) {
		return fmt.Errorf("attribution.require_caller is set but nothing can " +
			"authenticate a caller: declare teams with keys, or enable oidc")
	}

	if !a.Enabled {
		return nil
	}
	if a.RoleARN == "" {
		return fmt.Errorf("attribution.enabled requires attribution.role_arn")
	}
	if a.TagKey == "" {
		a.TagKey = "team"
	}
	if a.SessionDuration == 0 {
		a.SessionDuration = Duration(15 * 60 * 1e9) // 15m
	}
	if len(teams) == 0 {
		return fmt.Errorf("attribution.enabled but no teams declared; there would be nothing to attribute to")
	}
	for _, t := range teams {
		if len(t.Keys) == 0 && !oidcEnabled {
			return fmt.Errorf("team %q has no keys, so nothing can authenticate as it", t.Name)
		}
	}
	return nil
}

func anyTeamHasKeys(teams []Team) bool {
	for _, t := range teams {
		if len(t.Keys) > 0 {
			return true
		}
	}
	return false
}

// validateRoster checks the team list itself. forSTS additionally applies the
// naming rules that exist only because a team name becomes an STS session name
// and a session tag value — constraints with no meaning for a deployment that
// never calls AWS, and which should not be imposed on one.
func validateRoster(teams []Team, forSTS bool) error {
	seenName := map[string]bool{}
	seenKey := map[string]bool{}
	for _, t := range teams {
		if t.Name == "" {
			return fmt.Errorf("a team has no name")
		}
		if forSTS {
			if !sessionNameOK.MatchString(t.Name) {
				return fmt.Errorf("team %q: name must match [\\w+=,.@-]{2,64} — it becomes the STS session name", t.Name)
			}
			if !tagValueOK.MatchString(t.Name) {
				return fmt.Errorf("team %q: name is not a valid session tag value", t.Name)
			}
		}
		if seenName[t.Name] {
			return fmt.Errorf("team %q declared twice", t.Name)
		}
		seenName[t.Name] = true

		for _, k := range t.Keys {
			if len(k) < 16 {
				return fmt.Errorf("team %q: keys must be at least 16 characters", t.Name)
			}
			if seenKey[k] {
				return fmt.Errorf("a key is shared by two teams; attribution would be ambiguous")
			}
			seenKey[k] = true
		}
	}
	return nil
}

// TeamForKey returns the team a presented key authenticates as.
//
// The comparison is constant-time and every key is checked, so the time taken
// does not depend on how far down the list the match was, or whether there was
// one.
func TeamForKey(teams []Team, key string) (string, bool) {
	var found string
	for _, t := range teams {
		for _, k := range t.Keys {
			if subtle.ConstantTimeCompare([]byte(k), []byte(key)) == 1 {
				found = t.Name
			}
		}
	}
	return found, found != ""
}
