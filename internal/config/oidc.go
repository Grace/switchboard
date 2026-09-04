package config

import (
	"fmt"
	"net/url"
	"time"

	"github.com/Grace/switchboard/internal/oidc"
)

// OIDC trusts an identity provider instead of a shared secret.
//
// Static team keys answer "which team is this" and nothing else. A token
// answers "which person, from which team, and is that still true" — and it
// expires on its own, which is the part a key rotation policy keeps promising.
type OIDC struct {
	Enabled bool `json:"enabled"`
	// Issuer is the provider's base URL. Discovery and key fetching both
	// derive from it, and a key set hosted anywhere else is refused.
	Issuer string `json:"issuer,omitempty"`
	// Audience must appear in the token's aud claim. Leave empty to skip the
	// check only if something else already scopes who can reach the gateway.
	Audience string `json:"audience,omitempty"`
	// TeamClaim names the claim carrying the team. Defaults to "groups".
	TeamClaim string `json:"team_claim,omitempty"`
	// Skew tolerates clock drift between the provider and this host.
	Skew Duration `json:"skew,omitempty"`
	// CacheTTL bounds how long a fetched key set is used before refetching.
	CacheTTL Duration `json:"cache_ttl,omitempty"`
}

func (o *OIDC) validate(teams []Team) error {
	if !o.Enabled {
		return nil
	}
	u, err := url.Parse(o.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("oidc.issuer must be an https URL, got %q", o.Issuer)
	}
	if len(teams) == 0 {
		return fmt.Errorf("oidc.enabled but no teams declared: the team claim is " +
			"matched against the roster, so every team a token can name must be listed")
	}
	if o.Audience == "" {
		return fmt.Errorf("oidc.audience is required: without it any token this " +
			"issuer minted for any application would be accepted here")
	}
	return nil
}

// Build constructs a verifier from the configuration.
func (o OIDC) Build() (*oidc.Verifier, error) {
	if !o.Enabled {
		return nil, nil
	}
	return oidc.New(oidc.Config{
		Issuer:    o.Issuer,
		Audience:  o.Audience,
		TeamClaim: o.TeamClaim,
		Skew:      time.Duration(o.Skew),
		CacheTTL:  time.Duration(o.CacheTTL),
	})
}
