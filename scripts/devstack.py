#!/usr/local/bin/python3
"""Local development bootstrap.

Collapses the manual first-run sequence — keypair, database role, tenant,
principals, signed policy, gateway config — into three commands the compose
stack calls in order. It is for local use only: it prints tokens to stdout and
writes them to disk, which is exactly what a deployment must never do.

  keys     generate Ed25519 signing material and the bearer tokens, as shell env
  dbinit   apply migrations and create the least-privileged runtime login
  init     provision tenant and principals, publish a signed policy, write config

Reuses controlplane.migrate and scripts.bootstrap rather than reimplementing
migration or tenant provisioning.
"""
import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def _b64(raw):
    return base64.b64encode(raw).decode()


def cmd_keys(args):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    private = Ed25519PrivateKey.generate()
    seed = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    # 43 base64 chars from 32 bytes, comfortably over the 32-byte minimum the
    # gateway and control plane both enforce on bearer tokens.
    out = {
        "POLICY_KEY_ID": args.key_id,
        "POLICY_SIGNING_SEED": _b64(seed),
        "POLICY_PUBLIC_KEY": _b64(public),
        "BOOTSTRAP_ADMIN_TOKEN": secrets.token_urlsafe(32),
        "CONTROL_TOKEN": secrets.token_urlsafe(32),
        "LOCAL_TOKEN": secrets.token_urlsafe(32),
        "APP_DB_PASSWORD": secrets.token_urlsafe(24),
        "TENANT": args.tenant,
    }
    for k, v in out.items():
        print("%s=%s" % (k, v))


def _migration_dsn():
    """Prefer a complete DSN, otherwise compose one from parts.

    Composing it here rather than in a shell wrapper is what lets the image be
    distroless: there is no `sh` in it to interpolate the password into a URL.
    """
    dsn = os.environ.get("MIGRATION_DATABASE_URL")
    if dsn:
        return dsn
    host = os.environ["DBHOST"]
    password = urllib.parse.quote(os.environ["PGPASSWORD"], safe="")
    user = os.environ.get("DBUSER", "switchboard_owner")
    name = os.environ.get("DBNAME", "switchboard")
    ssl = os.environ.get("DBSSLMODE", "verify-full")
    root = os.environ.get("DBSSLROOTCERT", "/etc/ssl/rds/global-bundle.pem")
    return ("postgresql://%s:%s@%s:5432/%s?sslmode=%s&sslrootcert=%s"
            % (user, password, host, name, ssl, root))


def cmd_dbinit(args):
    import psycopg
    from psycopg import sql

    admin = _migration_dsn()
    # Migrations must run as an owner that can create roles and tables; the
    # runtime login is deliberately a different, weaker principal.
    subprocess.run([sys.executable, "-m", "controlplane.migrate"], check=True,
                   env={**os.environ, "MIGRATION_DATABASE_URL": admin})

    password = os.environ["APP_DB_PASSWORD"]
    with psycopg.connect(admin, autocommit=True) as db:
        exists = db.execute("SELECT 1 FROM pg_roles WHERE rolname='switchboard_rt'").fetchone()
        # Role DDL takes no bind parameters, so the password is quoted as a
        # literal by psycopg.sql rather than interpolated by hand.
        secret = sql.Literal(password)
        if exists is None:
            db.execute(sql.SQL("CREATE ROLE switchboard_rt LOGIN PASSWORD {}").format(secret))
        else:
            db.execute(sql.SQL("ALTER ROLE switchboard_rt PASSWORD {}").format(secret))
        # switchboard_app carries the table grants and is NOLOGIN by design.
        db.execute("GRANT switchboard_app TO switchboard_rt")
        db.execute("GRANT CONNECT ON DATABASE switchboard TO switchboard_rt")
        db.execute("GRANT USAGE ON SCHEMA public TO switchboard_rt")
    print("dbinit: migrations applied; switchboard_rt granted switchboard_app")


def _request(method, url, token, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token)
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=10) as r:
        raw = r.read()
        return json.loads(raw) if raw else None


def _wait_for(url, attempts=60):
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return
        except Exception:
            pass
        time.sleep(1)
    raise SystemExit("timed out waiting for " + url)


def _principal_exists(digest):
    import psycopg
    try:
        dsn = _migration_dsn()
    except KeyError:
        return False
    with psycopg.connect(dsn) as db:
        row = db.execute(
            "SELECT 1 FROM principals WHERE token_hash=%s AND NOT revoked", (digest,)
        ).fetchone()
        return row is not None


def cmd_init(args):
    control = os.environ.get("CONTROL_URL", "http://127.0.0.1:8000")
    tenant = os.environ["TENANT"]
    admin_token = os.environ["BOOTSTRAP_ADMIN_TOKEN"]
    control_token = os.environ["CONTROL_TOKEN"]

    _wait_for(control + "/healthz")

    # Tenant + a seven-day admin principal. Idempotent across reruns: a second
    # run hits the tenants primary key, which is not an error worth failing on.
    provision = subprocess.run(
        [sys.executable, "-m", "scripts.bootstrap", tenant],
        env=os.environ.copy(), capture_output=True, text=True)
    if provision.returncode != 0 and "duplicate key" not in provision.stderr:
        sys.stderr.write(provision.stderr)
        raise SystemExit("tenant provisioning failed")

    # The API stores only the hash; the raw token stays on this side.
    digest = hashlib.sha256(control_token.encode()).hexdigest()
    # token_hash is unique, and the control plane deliberately collapses every
    # unhandled exception into an opaque 503, so a duplicate insert is
    # indistinguishable from a real fault over HTTP. Check the table directly
    # instead of trying to read intent out of the status code.
    if _principal_exists(digest):
        print("init: agent principal already present")
    else:
        agent = _request("POST", control + "/v1/principals", admin_token, {
            "token_hash": digest,
            "role": "agent",
            "expires_at": int(time.time()) + 7 * 86400,
        })
        print("init: agent principal %s" % agent["id"])

    now = int(time.time())
    policy = {
        "schema": 1,
        "tenant": tenant,
        "version": int(os.environ.get("POLICY_VERSION", "1")),
        "issued_at": now,
        "expires_at": now + 3600,
        "routes": [{"provider": "openai", "model": "mock-model"}],
    }
    try:
        envelope = _request("PUT", control + "/v1/policy", admin_token, policy)
        print("init: policy v%d signed by %s" % (policy["version"], envelope["key_id"]))
    except urllib.error.HTTPError as e:
        if e.code != 409:
            sys.stderr.write(e.read().decode() + "\n")
            raise
        print("init: policy version already published")

    config = {
        "listen": "127.0.0.1:8080",
        "tenant": tenant,
        "data_dir": "/data",
        "control_url": control,
        "control_token_env": "CONTROL_TOKEN",
        "local_token_env": "LOCAL_TOKEN",
        "trusted_keys": {os.environ["POLICY_KEY_ID"]: os.environ["POLICY_PUBLIC_KEY"]},
        "providers": {
            "openai": {"url": os.environ.get("MOCK_URL", "http://127.0.0.1:9090"),
                       "key_env": "OPENAI_API_KEY"}
        },
        "concurrency": 32,
        "rate": 50,
        "burst": 100,
        "retry_rate": 5,
        "max_attempts": 3,
        "timeout_seconds": 60,
        "queue_size": 4096,
        "spool_bytes": 67108864,
        "otlp_url": "",
        # Required for plain http to loopback; the gateway refuses it otherwise.
        "allow_local_http": True,
        # Local only. pprof exposes memory contents, including provider keys and
        # prompt text; this stack already keeps its signing seed and tokens in
        # plaintext, so it is the right place for it and the wrong place for
        # anything real.
        "enable_pprof": True,
    }
    with open(args.config, "w") as f:
        json.dump(config, f, indent=2)
        f.write("\n")
    print("init: wrote %s" % args.config)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    k = sub.add_parser("keys", help="generate signing material and tokens")
    k.add_argument("--key-id", default="dev-local")
    k.add_argument("--tenant", default="dev-tenant")
    k.set_defaults(func=cmd_keys)

    d = sub.add_parser("dbinit", help="apply migrations and create the runtime login")
    d.set_defaults(func=cmd_dbinit)

    i = sub.add_parser("init", help="provision tenant, principals, policy and config")
    i.add_argument("--config", default="/config/config.json")
    i.set_defaults(func=cmd_init)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
