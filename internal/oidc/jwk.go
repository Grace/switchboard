// Package oidc verifies OIDC ID tokens against an issuer's published keys.
//
// This is a deliberately narrow implementation: verification only, RS256 and
// ES256 only, no JWE, no key agreement, no signing. The cryptography itself is
// the standard library's; what lives here is parsing and policy.
//
// The design decision that matters is in verify(): the algorithm is chosen from
// the *key's* type, never from the token's own `alg` header. Algorithm
// confusion — presenting a token signed HS256 using the RSA public key as the
// HMAC secret — is the attack that defeats most hand-written verifiers, and it
// is impossible here by construction rather than by remembering to check.
// jwt_test.go constructs that attack, and the others, and asserts each is
// refused.
package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// jwk is one key from an issuer's JWKS. Fields not needed for verification are
// deliberately absent: anything this does not parse cannot influence it.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// publicKey is a verification key with the algorithm its type implies. The
// pairing is fixed here so no other code has to decide it.
type publicKey struct {
	kid string
	rsa *rsa.PublicKey
	ec  *ecdsa.PublicKey
}

func b64uint(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("empty value")
	}
	return new(big.Int).SetBytes(b), nil
}

// parse converts a JWK into a usable key, refusing anything it does not fully
// understand rather than guessing.
func (k jwk) parse() (publicKey, error) {
	if k.Use != "" && k.Use != "sig" {
		return publicKey{}, fmt.Errorf("key %q is for %q, not signing", k.Kid, k.Use)
	}

	switch k.Kty {
	case "RSA":
		n, err := b64uint(k.N)
		if err != nil {
			return publicKey{}, fmt.Errorf("key %q: modulus: %w", k.Kid, err)
		}
		e, err := b64uint(k.E)
		if err != nil {
			return publicKey{}, fmt.Errorf("key %q: exponent: %w", k.Kid, err)
		}
		if !e.IsInt64() || e.Int64() < 3 {
			return publicKey{}, fmt.Errorf("key %q: implausible exponent", k.Kid)
		}
		// 2048 bits is the floor every mainstream issuer meets; below it the
		// key is either a mistake or a downgrade.
		if n.BitLen() < 2048 {
			return publicKey{}, fmt.Errorf("key %q: %d-bit modulus is too small", k.Kid, n.BitLen())
		}
		return publicKey{kid: k.Kid, rsa: &rsa.PublicKey{N: n, E: int(e.Int64())}}, nil

	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		default:
			return publicKey{}, fmt.Errorf("key %q: unsupported curve %q", k.Kid, k.Crv)
		}
		x, err := b64uint(k.X)
		if err != nil {
			return publicKey{}, fmt.Errorf("key %q: x: %w", k.Kid, err)
		}
		y, err := b64uint(k.Y)
		if err != nil {
			return publicKey{}, fmt.Errorf("key %q: y: %w", k.Kid, err)
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		if !curve.IsOnCurve(x, y) {
			return publicKey{}, fmt.Errorf("key %q: point is not on the curve", k.Kid)
		}
		return publicKey{kid: k.Kid, ec: pub}, nil

	default:
		return publicKey{}, fmt.Errorf("key %q: unsupported key type %q", k.Kid, k.Kty)
	}
}

func parseJWKS(b []byte) ([]publicKey, error) {
	var set jwks
	if err := json.Unmarshal(b, &set); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, fmt.Errorf("jwks contains no keys")
	}
	var out []publicKey
	for _, k := range set.Keys {
		pk, err := k.parse()
		if err != nil {
			// One unusable key must not blind us to the rest: issuers publish
			// encryption keys and future algorithms alongside signing keys.
			continue
		}
		out = append(out, pk)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("jwks contains no usable signing keys")
	}
	return out, nil
}
