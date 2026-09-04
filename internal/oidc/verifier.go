package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Verifier validates ID tokens from one issuer.
//
// Keys are fetched from the issuer's published JWKS and cached. A token naming
// a key we have not seen triggers one refresh — issuers rotate, and refusing
// every token until a TTL expires would turn a routine rotation into an
// outage — but that refresh is rate limited, so a stream of tokens carrying
// invented key ids cannot be used to hammer the issuer through us.
type Verifier struct {
	issuer    string
	audience  string
	jwksURL   string
	teamClaim string
	skew      time.Duration
	ttl       time.Duration

	client *http.Client
	now    func() time.Time

	mu          sync.RWMutex
	keys        []publicKey
	fetchedAt   time.Time
	lastRefresh time.Time
}

// Config describes one trusted issuer.
type Config struct {
	Issuer    string
	Audience  string
	TeamClaim string
	Skew      time.Duration
	CacheTTL  time.Duration
	Client    *http.Client
}

// New builds a verifier. It does not reach the network: discovery happens on
// first use, so a gateway starts even when the identity provider is briefly
// unreachable.
func New(cfg Config) (*Verifier, error) {
	u, err := url.Parse(cfg.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("issuer must be an https URL, got %q", cfg.Issuer)
	}
	if cfg.TeamClaim == "" {
		cfg.TeamClaim = "groups"
	}
	if cfg.Skew == 0 {
		cfg.Skew = 60 * time.Second
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = time.Hour
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Verifier{
		issuer:    strings.TrimSuffix(cfg.Issuer, "/"),
		audience:  cfg.Audience,
		teamClaim: cfg.TeamClaim,
		skew:      cfg.Skew,
		ttl:       cfg.CacheTTL,
		client:    client,
		now:       time.Now,
	}, nil
}

// Verify checks a token and returns its claims.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	kid, err := peekKid(token)
	if err != nil {
		return nil, err
	}

	key, ok := v.lookup(kid)
	if !ok {
		if err := v.refresh(ctx); err != nil {
			return nil, fmt.Errorf("no key %q, and refreshing failed: %w", kid, err)
		}
		if key, ok = v.lookup(kid); !ok {
			return nil, fmt.Errorf("issuer publishes no key %q", kid)
		}
	}

	return verify(token, key, options{
		issuer:   v.issuer,
		audience: v.audience,
		skew:     v.skew,
		now:      v.now,
	})
}

// Team extracts the attribution unit from a verified token.
//
// The claim may be a string or an array; identity providers disagree, and
// which one a deployment gets is not the deployment's fault.
func (v *Verifier) Team(c *Claims) (string, bool) {
	raw, ok := c.Raw[v.teamClaim]
	if !ok {
		return "", false
	}
	switch x := raw.(type) {
	case string:
		if x == "" {
			return "", false
		}
		return x, true
	case []any:
		for _, item := range x {
			if s, ok := item.(string); ok && s != "" {
				return s, true
			}
		}
	}
	return "", false
}

func (v *Verifier) lookup(kid string) (publicKey, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if len(v.keys) == 0 || v.now().Sub(v.fetchedAt) > v.ttl {
		return publicKey{}, false
	}
	for _, k := range v.keys {
		if k.kid == kid {
			return k, true
		}
	}
	// A JWKS with a single key and a token with no kid is common in small
	// deployments and unambiguous.
	if kid == "" && len(v.keys) == 1 {
		return v.keys[0], true
	}
	return publicKey{}, false
}

// refresh re-fetches the JWKS, at most once per minute.
func (v *Verifier) refresh(ctx context.Context) error {
	v.mu.Lock()
	if v.now().Sub(v.lastRefresh) < time.Minute && !v.fetchedAt.IsZero() {
		v.mu.Unlock()
		return fmt.Errorf("key set refreshed recently; not refetching")
	}
	v.lastRefresh = v.now()
	jwksURL := v.jwksURL
	v.mu.Unlock()

	if jwksURL == "" {
		var err error
		if jwksURL, err = v.discover(ctx); err != nil {
			return err
		}
	}

	keys, err := v.fetchKeys(ctx, jwksURL)
	if err != nil {
		return err
	}

	v.mu.Lock()
	v.keys, v.fetchedAt, v.jwksURL = keys, v.now(), jwksURL
	v.mu.Unlock()
	return nil
}

// discover reads the issuer's OpenID configuration. The jwks_uri it names must
// live on the issuer's own host: an issuer that points elsewhere is either
// misconfigured or being impersonated, and following it would let a
// compromised discovery document redirect trust.
func (v *Verifier) discover(ctx context.Context) (string, error) {
	doc := v.issuer + "/.well-known/openid-configuration"
	body, err := v.get(ctx, doc)
	if err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}

	var meta struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	if strings.TrimSuffix(meta.Issuer, "/") != v.issuer {
		return "", fmt.Errorf("discovery document claims issuer %q, not %q", meta.Issuer, v.issuer)
	}

	u, err := url.Parse(meta.JWKSURI)
	if err != nil || u.Scheme != "https" {
		return "", fmt.Errorf("jwks_uri %q is not an https URL", meta.JWKSURI)
	}
	issuerURL, _ := url.Parse(v.issuer)
	if u.Host != issuerURL.Host {
		return "", fmt.Errorf("jwks_uri host %q is not the issuer's %q", u.Host, issuerURL.Host)
	}
	return meta.JWKSURI, nil
}

func (v *Verifier) fetchKeys(ctx context.Context, jwksURL string) ([]publicKey, error) {
	body, err := v.get(ctx, jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetching keys: %w", err)
	}
	return parseJWKS(body)
}

func (v *Verifier) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", u, resp.Status)
	}
	// A key set is kilobytes. Anything larger is not one.
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// peekKid reads the key id without trusting anything else in the token. This
// is only a lookup hint: nothing is believed until the signature verifies.
func peekKid(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed token: want 3 segments, got %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("malformed header: %w", err)
	}
	var h header
	if err := json.Unmarshal(raw, &h); err != nil {
		return "", fmt.Errorf("malformed header: %w", err)
	}
	return h.Kid, nil
}
