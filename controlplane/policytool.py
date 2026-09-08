"""Sign a routing policy without a control plane.

The gateway restores a signed policy from ``data_dir/policy.json`` at startup and
its readiness consults only that local copy. Nothing else in the data plane needs
the control plane for a first request. Until this existed, reaching one meant
Postgres, migrations, two database roles, a tenant, an admin principal and a
running API, purely to reach the seven lines of ``policy.sign`` that touch none of
them.

This is deliberately not part of the gateway binary. The gateway enforces a
policy it cannot itself edit, and shipping a signer inside the data plane would
undermine that claim even as a command that never runs while serving.

    python -m controlplane.policytool \\
      --tenant acme-prod --key-id key-2026-09 \\
      --route openai:gpt-4o-mini --route anthropic:claude-haiku-4-5-20251001 \\
      --out /data/policy.json

The seed is read from SWITCHBOARD_POLICY_SEED, or stdin with --seed-stdin, so it
does not land in the process table or a shell history file.
"""
import argparse
import base64
import json
import os
import sys
import time

from .policy import sign


def build(tenant: str, version: int, routes: list[str], lifetime: int) -> dict:
    parsed = []
    for r in routes:
        provider, _, model = r.partition(":")
        if not model:
            raise SystemExit(f"route {r!r} must be provider:model, for example openai:gpt-4o-mini")
        parsed.append({"provider": provider, "model": model})
    now = int(time.time())
    return {
        "schema": 1,
        "tenant": tenant,
        "version": version,
        "issued_at": now,
        # Bounded at seven days by validate_policy. A policy that has expired is
        # refused, and readiness goes 503, so the expiry is a real operational
        # commitment rather than a formality.
        "expires_at": now + lifetime,
        "routes": parsed,
    }


def read_seed(from_stdin: bool) -> bytes:
    raw = sys.stdin.read() if from_stdin else os.environ.get("SWITCHBOARD_POLICY_SEED", "")
    if not raw.strip():
        raise SystemExit(
            "no signing seed: set SWITCHBOARD_POLICY_SEED to its base64 value, or pass --seed-stdin"
        )
    try:
        seed = base64.b64decode(raw.strip(), validate=True)
    except Exception as e:
        raise SystemExit(f"seed is not valid base64: {e}")
    if len(seed) != 32:
        raise SystemExit(f"seed is {len(seed)} bytes; an ed25519 seed is 32")
    return seed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m controlplane.policytool",
        description="Sign a routing policy for a gateway running without a control plane.",
    )
    ap.add_argument("--tenant", required=True, help="must match the gateway's configured tenant")
    ap.add_argument("--key-id", required=True, help="must match a key in the gateway's trusted_keys")
    ap.add_argument(
        "--route", action="append", required=True, metavar="PROVIDER:MODEL",
        help="repeat for failover order; the first is preferred. One to four, no repeated provider.",
    )
    ap.add_argument("--version", type=int, default=1,
                    help="must exceed the version already stored, or the gateway refuses the rollback")
    ap.add_argument("--lifetime", type=int, default=604800,
                    help="seconds until expiry, maximum 604800 (seven days)")
    ap.add_argument("--seed-stdin", action="store_true", help="read the base64 seed from stdin")
    ap.add_argument("--out", help="write here instead of stdout, for example /data/policy.json")
    a = ap.parse_args(argv)

    envelope = sign(build(a.tenant, a.version, a.route, a.lifetime), a.key_id, read_seed(a.seed_stdin))
    text = json.dumps(envelope, indent=2) + "\n"
    if a.out:
        # 0600: the envelope is not secret, but it decides where prompts go, and
        # a writable policy file is a routing decision anyone can change.
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        print(f"wrote {a.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
