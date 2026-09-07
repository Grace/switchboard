"""Restricted canonical policy format shared with the Go verifier."""
import base64
import json
import re
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$", re.ASCII)

def validate_policy(p: dict, tenant: str, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else now
    if set(p) != {"schema", "tenant", "version", "issued_at", "expires_at", "routes"}:
        raise ValueError("invalid policy fields")
    if any(type(p[k]) is not int for k in ("schema", "version", "issued_at", "expires_at")):
        raise ValueError("policy numbers must be integers")
    if p["schema"] != 1 or p["tenant"] != tenant or not ID.fullmatch(tenant):
        raise ValueError("invalid tenant/schema")
    if not 1 <= p["version"] <= 9007199254740991:
        raise ValueError("invalid version")
    if not 1 <= p["issued_at"] <= now + 60 or not max(now, p["issued_at"]) < p["expires_at"] <= p["issued_at"] + 604800:
        raise ValueError("invalid policy lifetime (maximum seven days)")
    routes = p["routes"]
    if type(routes) is not list or not 1 <= len(routes) <= 4:
        raise ValueError("one to four routes required")
    seen = set()
    for route in routes:
        if type(route) is not dict or set(route) != {"provider", "model"}:
            raise ValueError("invalid route fields")
        if route["provider"] not in ("openai", "anthropic", "gemini", "bedrock") or route["provider"] in seen:
            raise ValueError("invalid or repeated provider")
        if not isinstance(route["model"], str) or not ID.fullmatch(route["model"]):
            raise ValueError("invalid model identifier")
        seen.add(route["provider"])
    return p

def canonical(p: dict) -> bytes:
    return json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")

def sign(p: dict, key_id: str, seed: bytes) -> dict:
    validate_policy(p, p["tenant"])
    if not ID.fullmatch(key_id):
        raise ValueError("invalid signing key ID")
    payload = canonical(p)
    sig = Ed25519PrivateKey.from_private_bytes(seed).sign(b"switchboard-policy-v1\n" + key_id.encode("ascii") + b"\n" + payload)
    return {"key_id": key_id, "payload": base64.b64encode(payload).decode(), "signature": base64.b64encode(sig).decode()}
