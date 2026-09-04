# SSO

*Static keys answer "which team is this". A token answers "which person, from
which team, and is that still true" — and expires on its own, which is the part
a key rotation policy keeps promising.*

## Configuration

```json
{
  "oidc": {
    "enabled": true,
    "issuer": "https://login.example.com",
    "audience": "switchboard",
    "team_claim": "groups",
    "skew": "60s",
    "cache_ttl": "1h"
  },
  "teams": [
    { "name": "platform" },
    { "name": "search", "keys": ["sk-switchboard-search-…"] }
  ]
}
```

Callers present the token as a bearer:

```sh
curl http://gateway:11435/v1/chat/completions \
  -H "authorization: Bearer $ID_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"model":"claude-opus","messages":[{"role":"user","content":"hi"}]}'
```

switchboard fetches the issuer's key set, verifies the signature, checks the
claims, reads the team from `team_claim`, and records both the team and the
subject.

**Static keys keep working.** They are tried first, because they are a local
comparison — a deployment using only keys should never start depending on an
identity provider being reachable. A team with no `keys` is authenticated by
token only, which is how you migrate one team at a time.

**The roster is still the allowlist.** A token naming a team that is not in
`teams` is refused. The identity provider decides who someone is; it does not
decide which teams exist here. Without that, any group name the provider happens
to emit would become a billable team and a session tag on your AWS bill.

**`audience` is required.** Without it, any token that issuer minted for any
application would be accepted here.

## What this changes downstream

The audit log gains a `subject` alongside `team`, so an entry identifies a
person rather than a shared credential. That is the difference between "someone
on the search team ran this" and "this person did", which is what NIST AU-3 and
an incident review both actually ask for.

## On rolling our own

This verifies tokens with about 250 lines over the standard library rather than
a JOSE dependency. That is a deliberate choice and it deserves the scrutiny it
invites, so here is exactly what was decided.

**Scope is verification only** — RS256 and ES256, no signing, no JWE, no key
agreement. Most of a JOSE library is spec surface this does not need, and every
piece of it is attack surface.

**The algorithm comes from the key, never from the token.** This is the decision
that matters. Algorithm confusion — presenting a token signed `HS256` using the
RSA public key as the HMAC secret — defeats verifiers that dispatch on the
token's `alg` header. Here the key's type selects the verification path, and the
header is then required to agree. The attack is impossible by construction
rather than handled by remembering to check.

**Tokens carrying their own key material are refused.** `jwk`, `jku` and `x5u`
headers are parsed only so their presence can be rejected.

**Each attack is a test.** `internal/oidc/jwt_test.go` constructs `alg: none`, a
token signed HS256 with the RSA public key, self-supplied key material, a token
signed by a different key, edited claims, expired and not-yet-valid tokens,
wrong issuer, wrong audience, missing subject, missing expiry, and a point off
the curve — and asserts each is refused. A reviewer can read the implementation
and the tests that pin it in an afternoon, which is not true of a dependency.

**Key handling is conservative.** RSA moduli under 2048 bits are refused, EC
points are checked to be on the curve, keys marked for encryption are ignored,
and a key set with nothing usable is an error rather than an empty allowlist.

**Discovery cannot redirect trust.** The discovery document must name the issuer
we asked for, and its `jwks_uri` must be on the issuer's own host.

**Rotation is not an outage, and is not a lever.** A token naming an unknown key
id triggers one refetch, so a routine rotation works immediately — but that
refetch is rate limited, so a stream of tokens carrying invented key ids cannot
be used to hammer your identity provider through this gateway.

### What it does not do

No HS256 — shared-secret tokens are not SSO. No encrypted tokens. No P-384 or
P-521. No userinfo lookup, no token exchange, no refresh handling: this
validates a bearer token, it does not run a login flow.

If your review requires a vetted JOSE library instead, that is a reasonable
position and this is one file to swap.
