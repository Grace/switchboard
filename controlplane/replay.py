"""Reconstruct a routing decision: which policy was live, and why this provider.

    python -m controlplane.replay --request-id 9b8341eecc1919f3cccc6dbabed7a83b \\
      --tenant acme-prod

The gateway records the policy version on every event, and the control plane
keeps every signed policy envelope by ``(tenant, version)`` permanently. Those
are two tables in the same database, so proving where a request went is a join
rather than a service: this reads ``telemetry`` for the event, ``policies`` for
the envelope that was in force, and prints what the routing loop would have seen.

That is enough to answer the question without storing any content. A policy also
forbids a repeated provider, so ``(version, provider)`` determines the model as
well -- the route is fully recoverable from the version plus the provider that
answered, and neither had to be guessed at.

Content is a separate matter. When ``capture_ttl_seconds`` is set the gateway
writes the prompt and completion to its own local disk, and ``--capture-dir``
points this at that directory to include them. Those records never reach the
control plane and never reach telemetry, so this is the only way to see them and
it requires access to the machine that served the request.

DATABASE_URL is read from the environment, as the control plane itself does.
"""
import argparse
import base64
import json
import os
import sys

import psycopg
from psycopg.rows import dict_row


def fetch(dsn: str, tenant: str, request_id: str):
    """The event, and the policy envelope that was live when it was served.

    Two statements rather than one join, because the event may name a policy
    version the policies table does not have -- a gateway running a policy file
    directly, with no control plane behind it, is a supported mode. Splitting
    them makes that case say "the policy is not here" rather than returning no
    rows and implying the request never happened.
    """
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        # Row-level security is forced on telemetry and policies, and the runtime
        # role only sees rows matching app.tenant. Without this the queries below
        # return nothing and the report would say the request never happened,
        # which is a considerably worse answer than an error. The control plane
        # does the same at controlplane/app.py:147.
        conn.execute("SELECT set_config('app.tenant', %s, false)", (tenant,))
        ev = conn.execute(
            "SELECT id, event, received_at FROM telemetry"
            " WHERE tenant_id = %s AND event->>'request_id' = %s"
            " ORDER BY received_at DESC LIMIT 1",
            (tenant, request_id),
        ).fetchone()
        if ev is None:
            return None, None
        version = ev["event"].get("policy_version")
        if not version:
            return ev, None
        pol = conn.execute(
            "SELECT version, envelope, created_at FROM policies"
            " WHERE tenant_id = %s AND version = %s",
            (tenant, version),
        ).fetchone()
        return ev, pol


def policy_document(envelope) -> dict:
    """The policy document out of a signed envelope.

    An envelope is ``{key_id, payload, signature}`` where payload is base64 of
    the canonical JSON the signature covers -- not a nested object. Reading it
    any other way silently yields no routes, and a report with no routes will
    then announce that the provider which answered is not in the policy, which
    is a confident falsehood rather than a missing field. That is worth a
    dedicated function.

    Nothing here verifies the signature. This is a read-only explanation; a
    caller who needs the envelope authenticated should use the gateway's own
    verification path rather than trust a report.
    """
    payload = envelope.get("payload")
    if not payload:
        return {}
    try:
        # Canonical JSON is signed as base64 without guaranteed padding.
        raw = base64.b64decode(payload + "=" * (-len(payload) % 4))
        return json.loads(raw)
    except Exception:
        return {}


def routes_of(envelope) -> list[dict]:
    return policy_document(envelope).get("routes", [])


def reconstruct(ev, pol) -> dict:
    """The routing decision, as data, from an event row and a policy row.

    One implementation, because there are two callers: this module's CLI and the
    control plane's GET /v1/replay/{id}. They were briefly separate -- the
    endpoint re-derived the consistency verdict, the model inference and the
    undecodable-envelope case -- with a test suite each and nothing comparing
    them, so the two could have disagreed about what happened to a request and
    no test would have noticed.
    """
    e = ev["event"] or {}
    served = e.get("provider")
    out = {
        "request_id": e.get("request_id"),
        "received_at": ev["received_at"],
        "status": e.get("status"),
        "attempts": e.get("attempts"),
        "provider": served,
        "policy_version": e.get("policy_version"),
        "trace_id": e.get("trace_id"),
        "routes": [],
        "consistent": None,
        "model": None,
        "policy_error": None,
    }
    if pol is None:
        return out

    out["policy_version_signed_at"] = pol["created_at"]
    routes = routes_of(pol["envelope"])
    out["routes"] = routes
    if not routes:
        # An envelope that cannot be decoded must not be reported as a policy
        # with no routes: that would make every request look inconsistent with
        # its own policy, which is a confident falsehood rather than a gap.
        out["policy_error"] = "envelope payload could not be decoded"
        return out
    if served:
        out["consistent"] = served in {r.get("provider") for r in routes}
        if out["consistent"]:
            # A policy forbids a repeated provider, so the provider determines
            # the model and nothing had to store it.
            out["model"] = next(r.get("model") for r in routes if r.get("provider") == served)
    return out


def report(ev, pol, capture=None) -> str:
    d = reconstruct(ev, pol)
    e = ev["event"]
    out = [
        f"request        {e.get('request_id')}",
        f"received       {ev['received_at']}",
        f"status         {e.get('status')}",
        f"attempts       {e.get('attempts')}",
        f"provider       {e.get('provider') or '(never reached one)'}",
        f"policy version {e.get('policy_version') or '(not recorded)'}",
    ]
    if e.get("trace_id"):
        out.append(f"trace          {e['trace_id']}")

    out.append("")
    if pol is None:
        out.append(
            "policy         not found in the policies table. Either this gateway ran a policy\n"
            "               file directly with no control plane behind it, or the event predates\n"
            "               policy_version being recorded."
        )
    else:
        routes = d["routes"]
        if not routes:
            # Refusing to guess. An unreadable envelope reported as an empty
            # route list would make every request look inconsistent with its own
            # policy, which is the most misleading thing this tool could say.
            out.append(
                f"policy v{pol['version']} signed {pol['created_at']}, but its payload could not\n"
                "               be decoded. No claim is made about the route order."
            )
            return "\n".join(out)
        out.append(f"policy v{pol['version']} signed {pol['created_at']}, route order:")
        served = e.get("provider")
        for i, r in enumerate(routes):
            mark = "  <- answered" if r.get("provider") == served else ""
            out.append(f"  {i + 1}. {r.get('provider')}:{r.get('model')}{mark}")

        # The check worth doing. A provider outside the policy's route list means
        # either a bug or a policy that rotated mid-flight, and both are things
        # someone would rather find out here than not at all.
        if served and d["consistent"] is False:
            out.append("")
            out.append(
                f"  WARNING: {served} answered but is not in policy v{pol['version']}.\n"
                "  Either the policy rotated while the request was in flight, or the route\n"
                "  was not the one this version describes. Worth understanding either way."
            )
        elif served:
            # Providers are unique within a policy, so the model follows from the
            # provider without having been stored.
            out.append("")
            out.append(f"  consistent: {served} is in this policy, serving {d['model']}")

    if capture is not None:
        out += ["", "captured content:"]
        for label, key in (("prompt", "prompt"), ("completion", "completion"), ("text", "text")):
            v = capture.get(key)
            if v:
                body = v if isinstance(v, str) else json.dumps(v, indent=2)
                out.append(f"  {label}:")
                out += ["    " + line for line in body.splitlines()]
        if capture.get("fault"):
            out.append(f"  fault: {capture['fault']}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m controlplane.replay",
        description="Reconstruct which policy routed a request, and where it went.",
    )
    ap.add_argument("--request-id", required=True, help="the X-Request-ID the gateway returned")
    ap.add_argument("--tenant", required=True, help="tenant the gateway is configured for")
    ap.add_argument(
        "--capture-dir",
        help="a gateway's data_dir/capture, to include the prompt and completion. Only present "
        "when capture_ttl_seconds was set on the gateway that served the request, and only on "
        "that machine.",
    )
    a = ap.parse_args(argv)

    dsn = os.environ.get("DATABASE_URL", "").strip()
    if not dsn:
        raise SystemExit("replay: set DATABASE_URL to the control plane database")

    ev, pol = fetch(dsn, a.tenant, a.request_id)
    if ev is None:
        raise SystemExit(
            f"replay: no event for request {a.request_id} in tenant {a.tenant}.\n"
            "  Telemetry is delivered asynchronously and is dropped rather than retried forever,\n"
            "  so a very recent request may not have arrived and a very old one may be absent."
        )

    capture = None
    if a.capture_dir:
        path = os.path.join(a.capture_dir, a.request_id + ".json")
        try:
            with open(path) as f:
                capture = json.load(f)
        except FileNotFoundError:
            print(
                f"replay: no capture at {path}; capture is off by default and TTL-bounded",
                file=sys.stderr,
            )
    print(report(ev, pol, capture))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
