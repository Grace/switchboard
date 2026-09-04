package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func jwkFor(k *rsa.PrivateKey, kid string) jwk {
	return jwk{
		Kty: "RSA", Kid: kid, Use: "sig",
		N: base64.RawURLEncoding.EncodeToString(k.PublicKey.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.PublicKey.E)).Bytes()),
	}
}

// idp is a stand-in identity provider serving discovery and a key set.
type idp struct {
	*httptest.Server
	keys             atomic.Value // jwks
	jwksHits         atomic.Int64
	issuerOverride   string
	jwksHostOverride string
}

func newIDP(t *testing.T, ks ...jwk) *idp {
	t.Helper()
	p := &idp{}
	p.keys.Store(jwks{Keys: ks})

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		iss := p.URL
		if p.issuerOverride != "" {
			iss = p.issuerOverride
		}
		jwksURI := p.URL + "/keys"
		if p.jwksHostOverride != "" {
			jwksURI = p.jwksHostOverride
		}
		json.NewEncoder(w).Encode(map[string]string{"issuer": iss, "jwks_uri": jwksURI})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		p.jwksHits.Add(1)
		json.NewEncoder(w).Encode(p.keys.Load().(jwks))
	})

	p.Server = httptest.NewTLSServer(mux)
	t.Cleanup(p.Close)
	return p
}

func verifierFor(t *testing.T, p *idp) *Verifier {
	t.Helper()
	v, err := New(Config{
		Issuer: p.URL, Audience: "switchboard", TeamClaim: "groups",
		Client: p.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return fixedNow }
	return v
}

func tokenFor(t *testing.T, k *rsa.PrivateKey, kid, iss string, over map[string]any) string {
	t.Helper()
	c := claimsMap(over)
	c["iss"] = iss
	return signRS256(t, k, map[string]any{"alg": "RS256", "kid": kid}, c)
}

func TestVerifierDiscoversAndVerifies(t *testing.T) {
	k := rsaKey(t)
	p := newIDP(t, jwkFor(k, "k1"))
	v := verifierFor(t, p)

	c, err := v.Verify(context.Background(), tokenFor(t, k, "k1", p.URL, map[string]any{
		"groups": []string{"platform", "search"},
	}))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if c.Subject != "user-42" {
		t.Errorf("sub = %q", c.Subject)
	}
	team, ok := v.Team(c)
	if !ok || team != "platform" {
		t.Errorf("Team = %q, %v", team, ok)
	}
}

func TestTeamClaimMayBeAString(t *testing.T) {
	k := rsaKey(t)
	p := newIDP(t, jwkFor(k, "k1"))
	v := verifierFor(t, p)

	c, err := v.Verify(context.Background(), tokenFor(t, k, "k1", p.URL, map[string]any{"groups": "billing"}))
	if err != nil {
		t.Fatal(err)
	}
	if team, ok := v.Team(c); !ok || team != "billing" {
		t.Errorf("Team = %q, %v", team, ok)
	}
}

func TestMissingTeamClaimIsReported(t *testing.T) {
	k := rsaKey(t)
	p := newIDP(t, jwkFor(k, "k1"))
	v := verifierFor(t, p)

	c, _ := v.Verify(context.Background(), tokenFor(t, k, "k1", p.URL, nil))
	if _, ok := v.Team(c); ok {
		t.Error("a token with no groups claim must not resolve a team")
	}
}

// Key rotation must not be an outage: a token naming a key we have not seen
// triggers exactly one refresh.
func TestUnknownKeyTriggersRefresh(t *testing.T) {
	old := rsaKey(t)
	p := newIDP(t, jwkFor(old, "old"))
	v := verifierFor(t, p)

	if _, err := v.Verify(context.Background(), tokenFor(t, old, "old", p.URL, nil)); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	before := p.jwksHits.Load()

	// The issuer rotates.
	fresh := rsaKey(t)
	p.keys.Store(jwks{Keys: []jwk{jwkFor(old, "old"), jwkFor(fresh, "new")}})
	v.lastRefresh = time.Time{} // allow an immediate refresh

	if _, err := v.Verify(context.Background(), tokenFor(t, fresh, "new", p.URL, nil)); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if p.jwksHits.Load() <= before {
		t.Error("an unknown kid should have caused a refetch")
	}
}

// And a stream of invented key ids must not become a way to hammer the issuer
// through us.
func TestRefreshIsRateLimited(t *testing.T) {
	k := rsaKey(t)
	p := newIDP(t, jwkFor(k, "k1"))
	v := verifierFor(t, p)

	if _, err := v.Verify(context.Background(), tokenFor(t, k, "k1", p.URL, nil)); err != nil {
		t.Fatal(err)
	}
	before := p.jwksHits.Load()

	for i := 0; i < 20; i++ {
		tok := tokenFor(t, k, fmt.Sprintf("invented-%d", i), p.URL, nil)
		if _, err := v.Verify(context.Background(), tok); err == nil {
			t.Fatal("an invented kid must not verify")
		}
	}
	if got := p.jwksHits.Load() - before; got > 1 {
		t.Errorf("20 unknown kids caused %d refetches; should be at most 1", got)
	}
}

// A discovery document that names someone else's issuer, or points its key set
// at another host, is either misconfigured or an impersonation. Following it
// would let a compromised document redirect trust.
func TestDiscoveryMustAgreeWithTheIssuer(t *testing.T) {
	k := rsaKey(t)

	p := newIDP(t, jwkFor(k, "k1"))
	p.issuerOverride = "https://someone-else.example.com"
	v := verifierFor(t, p)
	if _, err := v.Verify(context.Background(), tokenFor(t, k, "k1", p.URL, nil)); err == nil {
		t.Error("a discovery document claiming another issuer must be refused")
	}

	p2 := newIDP(t, jwkFor(k, "k1"))
	p2.jwksHostOverride = "https://attacker.example.com/keys"
	v2 := verifierFor(t, p2)
	if _, err := v2.Verify(context.Background(), tokenFor(t, k, "k1", p2.URL, nil)); err == nil {
		t.Error("a jwks_uri on another host must be refused")
	} else if !strings.Contains(err.Error(), "host") {
		t.Errorf("the refusal should name the reason, got %v", err)
	}
}

func TestIssuerMustBeHTTPS(t *testing.T) {
	for _, iss := range []string{"http://login.example.com", "not-a-url", "", "ftp://x"} {
		if _, err := New(Config{Issuer: iss}); err == nil {
			t.Errorf("issuer %q must be refused", iss)
		}
	}
}

func TestTokenFromAnotherIssuerIsRefused(t *testing.T) {
	k := rsaKey(t)
	p := newIDP(t, jwkFor(k, "k1"))
	v := verifierFor(t, p)

	tok := tokenFor(t, k, "k1", "https://evil.example.com", nil)
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("a correctly signed token from another issuer must be refused")
	}
}

func TestUnreachableIssuerIsAnErrorNotAPass(t *testing.T) {
	k := rsaKey(t)
	p := newIDP(t, jwkFor(k, "k1"))
	v := verifierFor(t, p)
	p.Close() // the identity provider goes away

	if _, err := v.Verify(context.Background(), tokenFor(t, k, "k1", p.URL, nil)); err == nil {
		t.Fatal("an unreachable issuer must fail closed")
	}
}

func TestDefaultsAreSane(t *testing.T) {
	v, err := New(Config{Issuer: "https://login.example.com/"})
	if err != nil {
		t.Fatal(err)
	}
	if v.issuer != "https://login.example.com" {
		t.Errorf("trailing slash should be normalised, got %q", v.issuer)
	}
	if v.teamClaim != "groups" || v.skew == 0 || v.ttl == 0 {
		t.Errorf("defaults not applied: %+v", v)
	}
}
