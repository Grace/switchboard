package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

// --- minting helpers -----------------------------------------------------

var fixedNow = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

func defaultOpts() options {
	return options{
		issuer:   "https://login.example.com",
		audience: "switchboard",
		skew:     30 * time.Second,
		now:      func() time.Time { return fixedNow },
	}
}

func seg(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func claimsMap(over map[string]any) map[string]any {
	c := map[string]any{
		"iss": "https://login.example.com",
		"sub": "user-42",
		"aud": "switchboard",
		"exp": fixedNow.Add(time.Hour).Unix(),
		"iat": fixedNow.Add(-time.Minute).Unix(),
	}
	for k, v := range over {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	return c
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func rsaPub(k *rsa.PrivateKey) publicKey {
	return publicKey{kid: "k1", rsa: &k.PublicKey}
}

func signRS256(t *testing.T, k *rsa.PrivateKey, hdr map[string]any, claims map[string]any) string {
	t.Helper()
	input := seg(hdr) + "." + seg(claims)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func signES256(t *testing.T, k *ecdsa.PrivateKey, hdr, claims map[string]any) string {
	t.Helper()
	input := seg(hdr) + "." + seg(claims)
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// --- the happy paths -----------------------------------------------------

func TestValidRS256Verifies(t *testing.T) {
	k := rsaKey(t)
	tok := signRS256(t, k, map[string]any{"alg": "RS256", "kid": "k1", "typ": "JWT"}, claimsMap(nil))

	c, err := verify(tok, rsaPub(k), defaultOpts())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.Subject != "user-42" {
		t.Errorf("sub = %q", c.Subject)
	}
	if c.Raw["sub"] != "user-42" {
		t.Errorf("raw claims should be preserved for team mapping, got %v", c.Raw)
	}
}

func TestValidES256Verifies(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tok := signES256(t, k, map[string]any{"alg": "ES256", "kid": "k1"}, claimsMap(nil))

	if _, err := verify(tok, publicKey{kid: "k1", ec: &k.PublicKey}, defaultOpts()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestAudienceMayBeAnArray(t *testing.T) {
	k := rsaKey(t)
	tok := signRS256(t, k, map[string]any{"alg": "RS256", "kid": "k1"},
		claimsMap(map[string]any{"aud": []string{"other", "switchboard"}}))
	if _, err := verify(tok, rsaPub(k), defaultOpts()); err != nil {
		t.Fatalf("an aud array containing us must be accepted: %v", err)
	}
}

// --- the attacks ---------------------------------------------------------
//
// Each of these constructs a token an attacker would actually send. They are
// the reason this package is small enough to read.

// The oldest one. A token that declares it needs no signature.
func TestRejectsAlgNone(t *testing.T) {
	k := rsaKey(t)
	hdr := seg(map[string]any{"alg": "none", "kid": "k1"})
	body := seg(claimsMap(nil))
	for _, tok := range []string{hdr + "." + body + ".", hdr + "." + body + ".AAAA"} {
		if _, err := verify(tok, rsaPub(k), defaultOpts()); err == nil {
			t.Fatal("alg:none must be refused")
		}
	}
}

// Algorithm confusion, and the reason the algorithm comes from the key. The
// attacker takes the RSA public key — which is public — and uses its bytes as
// an HMAC secret, hoping the verifier trusts the header and calls HMAC.
func TestRejectsHS256SignedWithTheRSAPublicKey(t *testing.T) {
	k := rsaKey(t)
	pubBytes := k.PublicKey.N.Bytes()

	hdr := seg(map[string]any{"alg": "HS256", "kid": "k1"})
	body := seg(claimsMap(nil))
	input := hdr + "." + body
	m := hmac.New(sha256.New, pubBytes)
	m.Write([]byte(input))
	tok := input + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))

	if _, err := verify(tok, rsaPub(k), defaultOpts()); err == nil {
		t.Fatal("algorithm confusion must be refused")
	} else if !strings.Contains(err.Error(), "HS256") {
		t.Errorf("the refusal should name the declared algorithm, got %v", err)
	}
}

// A token that carries its own key is asking to be trusted on its own
// authority. jwk, jku and x5u are all that request in different clothes.
func TestRejectsSelfSuppliedKeyMaterial(t *testing.T) {
	k := rsaKey(t)
	attacker := rsaKey(t)

	for name, hdr := range map[string]map[string]any{
		"jwk": {"alg": "RS256", "kid": "k1", "jwk": map[string]any{"kty": "RSA", "n": "x", "e": "AQAB"}},
		"jku": {"alg": "RS256", "kid": "k1", "jku": "https://attacker.example/keys.json"},
		"x5u": {"alg": "RS256", "kid": "k1", "x5u": "https://attacker.example/cert.pem"},
	} {
		tok := signRS256(t, attacker, hdr, claimsMap(nil))
		if _, err := verify(tok, rsaPub(k), defaultOpts()); err == nil {
			t.Errorf("%s header must be refused", name)
		}
	}
}

func TestRejectsTokenSignedByAnotherKey(t *testing.T) {
	real := rsaKey(t)
	attacker := rsaKey(t)
	tok := signRS256(t, attacker, map[string]any{"alg": "RS256", "kid": "k1"}, claimsMap(nil))

	if _, err := verify(tok, rsaPub(real), defaultOpts()); err == nil {
		t.Fatal("a token signed by an unknown key must be refused")
	}
}

func TestRejectsTamperedClaims(t *testing.T) {
	k := rsaKey(t)
	tok := signRS256(t, k, map[string]any{"alg": "RS256", "kid": "k1"}, claimsMap(nil))

	parts := strings.Split(tok, ".")
	parts[1] = seg(claimsMap(map[string]any{"sub": "admin"}))
	if _, err := verify(strings.Join(parts, "."), rsaPub(k), defaultOpts()); err == nil {
		t.Fatal("editing the claims must invalidate the signature")
	}
}

// A valid signature only proves the issuer minted it. These decide whether it
// is for us, and for now.
func TestRejectsClaimsThatAreNotForUsOrNotNow(t *testing.T) {
	k := rsaKey(t)
	cases := map[string]map[string]any{
		"expired":           {"exp": fixedNow.Add(-time.Hour).Unix()},
		"not yet valid":     {"nbf": fixedNow.Add(time.Hour).Unix()},
		"issued in future":  {"iat": fixedNow.Add(time.Hour).Unix()},
		"wrong issuer":      {"iss": "https://evil.example.com"},
		"wrong audience":    {"aud": "someone-else"},
		"no subject":        {"sub": nil},
		"no expiry":         {"exp": nil},
		"audience not ours": {"aud": []string{"a", "b"}},
	}
	for name, over := range cases {
		tok := signRS256(t, k, map[string]any{"alg": "RS256", "kid": "k1"}, claimsMap(over))
		if _, err := verify(tok, rsaPub(k), defaultOpts()); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}

// Skew is allowed, but bounded.
func TestClockSkewIsToleratedWithinTheLimit(t *testing.T) {
	k := rsaKey(t)
	tok := signRS256(t, k, map[string]any{"alg": "RS256", "kid": "k1"},
		claimsMap(map[string]any{"exp": fixedNow.Add(-10 * time.Second).Unix()}))

	if _, err := verify(tok, rsaPub(k), defaultOpts()); err != nil {
		t.Errorf("10s past expiry with 30s skew should pass: %v", err)
	}

	tok = signRS256(t, k, map[string]any{"alg": "RS256", "kid": "k1"},
		claimsMap(map[string]any{"exp": fixedNow.Add(-5 * time.Minute).Unix()}))
	if _, err := verify(tok, rsaPub(k), defaultOpts()); err == nil {
		t.Error("5 minutes past expiry must not be excused by 30s of skew")
	}
}

func TestRejectsMalformedTokens(t *testing.T) {
	k := rsaKey(t)
	for name, tok := range map[string]string{
		"empty":           "",
		"two segments":    "a.b",
		"four segments":   "a.b.c.d",
		"bad base64":      "!!!.@@@.###",
		"header not json": base64.RawURLEncoding.EncodeToString([]byte("nope")) + ".e30.AA",
	} {
		if _, err := verify(tok, rsaPub(k), defaultOpts()); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}

// --- key parsing ---------------------------------------------------------

func TestRejectsWeakOrMalformedKeys(t *testing.T) {
	cases := map[string]jwk{
		"unsupported type":  {Kty: "oct", Kid: "k"},
		"unsupported curve": {Kty: "EC", Kid: "k", Crv: "P-521", X: "AA", Y: "AA"},
		"encryption key":    {Kty: "RSA", Kid: "k", Use: "enc", N: "AA", E: "AQAB"},
		"tiny modulus":      {Kty: "RSA", Kid: "k", N: base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes()), E: "AQAB"},
		"empty modulus":     {Kty: "RSA", Kid: "k", N: "", E: "AQAB"},
	}
	for name, k := range cases {
		if _, err := k.parse(); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}

func TestRejectsECPointNotOnCurve(t *testing.T) {
	k := jwk{
		Kty: "EC", Kid: "k", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes()),
		Y: base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes()),
	}
	if _, err := k.parse(); err == nil {
		t.Fatal("a point off the curve must be refused")
	}
}

func TestJWKSParsingSkipsUnusableKeysButNeedsOne(t *testing.T) {
	k := rsaKey(t)
	good := jwk{
		Kty: "RSA", Kid: "good",
		N: base64.RawURLEncoding.EncodeToString(k.PublicKey.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.PublicKey.E)).Bytes()),
	}
	set, _ := json.Marshal(jwks{Keys: []jwk{{Kty: "oct", Kid: "unusable"}, good}})
	keys, err := parseJWKS(set)
	if err != nil {
		t.Fatalf("an issuer publishing a key we cannot use must not blind us to the rest: %v", err)
	}
	if len(keys) != 1 || keys[0].kid != "good" {
		t.Errorf("keys = %+v", keys)
	}

	onlyBad, _ := json.Marshal(jwks{Keys: []jwk{{Kty: "oct", Kid: "unusable"}}})
	if _, err := parseJWKS(onlyBad); err == nil {
		t.Error("a JWKS with no usable signing key must be an error")
	}
	if _, err := parseJWKS([]byte(`{"keys":[]}`)); err == nil {
		t.Error("an empty JWKS must be an error")
	}
}
