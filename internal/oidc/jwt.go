package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// header is the first segment. `alg` is read only to be checked against what
// the key implies — it never selects the verification path.
type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`

	// Present only so their presence can be refused. A token that carries its
	// own key is asking to be trusted on its own authority.
	JWK any    `json:"jwk"`
	JKU string `json:"jku"`
	X5U string `json:"x5u"`
}

// Claims is the subset of an ID token this cares about.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  audience `json:"aud"`
	Expiry    int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	Email     string   `json:"email"`

	// Raw keeps every claim so a deployment can map teams from whichever one
	// its identity provider populates.
	Raw map[string]any `json:"-"`
}

// audience is a string or an array of strings, per RFC 7519.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("aud is neither a string nor an array of strings")
	}
	*a = many
	return nil
}

func (a audience) contains(s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// verify checks a compact JWS against one key and returns its claims.
//
// The algorithm comes from the key, not the token. That single choice is what
// makes algorithm confusion impossible here: an attacker who rewrites `alg` to
// HS256 and signs with the RSA public key produces a token this code tries to
// verify as RSA, which fails, because the key is an RSA key and nothing the
// token says can change that.
func verify(token string, key publicKey, opts options) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed token: want 3 segments, got %d", len(parts))
	}

	rawHeader, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("malformed header: %w", err)
	}
	var h header
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return nil, fmt.Errorf("malformed header: %w", err)
	}
	if h.JWK != nil || h.JKU != "" || h.X5U != "" {
		return nil, fmt.Errorf("token carries its own key material (jwk/jku/x5u); refused")
	}

	// The key decides the algorithm. The header is then required to agree,
	// which costs nothing and closes the door twice.
	var wantAlg string
	signingInput := []byte(parts[0] + "." + parts[1])
	sig, err := decodeSegment(parts[2])
	if err != nil {
		return nil, fmt.Errorf("malformed signature: %w", err)
	}
	sum := sha256.Sum256(signingInput)

	switch {
	case key.rsa != nil:
		wantAlg = "RS256"
		if h.Alg != wantAlg {
			return nil, fmt.Errorf("token declares alg %q but the key is RSA", h.Alg)
		}
		if err := rsa.VerifyPKCS1v15(key.rsa, crypto.SHA256, sum[:], sig); err != nil {
			return nil, fmt.Errorf("signature does not verify")
		}
	case key.ec != nil:
		wantAlg = "ES256"
		if h.Alg != wantAlg {
			return nil, fmt.Errorf("token declares alg %q but the key is EC", h.Alg)
		}
		if len(sig) != 64 {
			return nil, fmt.Errorf("signature does not verify")
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(key.ec, sum[:], r, s) {
			return nil, fmt.Errorf("signature does not verify")
		}
	default:
		return nil, fmt.Errorf("key %q has no usable public key", key.kid)
	}

	rawClaims, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("malformed claims: %w", err)
	}
	var c Claims
	if err := json.Unmarshal(rawClaims, &c); err != nil {
		return nil, fmt.Errorf("malformed claims: %w", err)
	}
	if err := json.Unmarshal(rawClaims, &c.Raw); err != nil {
		return nil, fmt.Errorf("malformed claims: %w", err)
	}

	if err := c.validate(opts); err != nil {
		return nil, err
	}
	return &c, nil
}

type options struct {
	issuer   string
	audience string
	skew     time.Duration
	now      func() time.Time
}

// validate checks the claims that decide whether a correctly signed token is
// actually for us, now. A valid signature only proves the issuer minted it.
func (c *Claims) validate(o options) error {
	now := o.now()

	if c.Issuer != o.issuer {
		return fmt.Errorf("token issuer %q is not %q", c.Issuer, o.issuer)
	}
	if o.audience != "" && !c.Audience.contains(o.audience) {
		return fmt.Errorf("token audience %v does not include %q", []string(c.Audience), o.audience)
	}
	if c.Subject == "" {
		return fmt.Errorf("token has no subject")
	}
	if c.Expiry == 0 {
		return fmt.Errorf("token has no expiry")
	}
	if now.After(time.Unix(c.Expiry, 0).Add(o.skew)) {
		return fmt.Errorf("token expired at %s", time.Unix(c.Expiry, 0).UTC().Format(time.RFC3339))
	}
	if c.NotBefore != 0 && now.Add(o.skew).Before(time.Unix(c.NotBefore, 0)) {
		return fmt.Errorf("token is not valid until %s", time.Unix(c.NotBefore, 0).UTC().Format(time.RFC3339))
	}
	if c.IssuedAt != 0 && now.Add(o.skew).Before(time.Unix(c.IssuedAt, 0)) {
		return fmt.Errorf("token was issued in the future")
	}
	return nil
}
