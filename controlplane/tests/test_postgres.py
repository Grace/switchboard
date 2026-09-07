"""Integration tests require a disposable Postgres cluster. CI runs these mandatorily."""
import hashlib
import os
import secrets
import time
import uuid
import pytest

psycopg = pytest.importorskip("psycopg")
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from fastapi.testclient import TestClient
from controlplane.app import create_app
from controlplane.migrate import migrate

@pytest.fixture(scope="module")
def setup():
    dsn = os.getenv("TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("TEST_DATABASE_URL is required for Postgres integration")
    migrate(dsn)
    migrate(dsn)  # Re-running migrations is a no-op with matching checksums.
    tokens = {}
    with psycopg.connect(dsn, autocommit=True) as db:
        for tenant in ("tenant-a", "tenant-b"):
            db.execute("INSERT INTO tenants(id) VALUES(%s)", (tenant,))
            for role in ("admin", "publisher", "viewer", "agent"):
                token = secrets.token_hex(32)
                tokens[tenant, role] = token
                db.execute("INSERT INTO principals(id,tenant_id,token_hash,role,expires_at) VALUES(%s,%s,%s,%s,now()+interval '1 day')",
                           (uuid.uuid4(), tenant, hashlib.sha256(token.encode()).hexdigest(), role))
    # SET ROLE verifies RLS behavior even when test DSN is a superuser.
    def configure(db):
        db.execute("SET ROLE switchboard_app")
        db.commit()
    pool = ConnectionPool(dsn, min_size=1, max_size=4, configure=configure, kwargs={"row_factory": dict_row})
    with TestClient(create_app(pool=pool, seed=secrets.token_bytes(32), key_id="test")) as client:
        yield client, tokens, pool
    pool.close()

def auth(tokens, tenant="tenant-a", role="admin"):
    return {"Authorization": "Bearer " + tokens[tenant, role]}

def policy(version=1):
    now = int(time.time())
    return {"schema": 1, "tenant": "tenant-a", "version": version, "issued_at": now,
            "expires_at": now+3600, "routes": [{"provider": "openai", "model": "test"}]}

def test_policy_rbac_tenant_and_rollback(setup):
    c,t,_ = setup
    assert c.put("/v1/policy",json=policy(),headers=auth(t,role="viewer")).status_code == 403
    assert c.put("/v1/policy",json=policy(),headers=auth(t)).status_code == 200
    assert c.put("/v1/policy",json=policy(),headers=auth(t)).status_code == 409
    assert c.get("/v1/policy",headers=auth(t,"tenant-b")).status_code == 404
    assert c.put("/v1/policy",json=policy(2),headers=auth(t,"tenant-b")).status_code == 422
    assert c.get("/v1/policy").status_code == 401

def test_telemetry_dedup_and_isolation(setup):
    c,t,pool = setup
    body={"id":uuid.uuid4().hex,"request_id":uuid.uuid4().hex,"trace_id":uuid.uuid4().hex,
          "span_id":"a"*16,"provider":"openai","status":200,"attempts":1,"start_ns":1,"end_ns":2}
    for _ in range(2):
        assert c.post("/v1/telemetry",json=body,headers=auth(t,role="agent")).status_code == 200
    assert c.post("/v1/telemetry",json=body,headers=auth(t,role="viewer")).status_code == 403
    assert len(c.get("/v1/telemetry",headers=auth(t)).json()) == 1
    assert c.get("/v1/telemetry",headers=auth(t,"tenant-b")).json() == []
    with pool.connection() as db:
        assert db.execute("SELECT count(*) AS n FROM telemetry").fetchone()["n"] == 0

def test_revocation_and_audit(setup):
    c,t,_=setup
    token=secrets.token_hex(32)
    r=c.post("/v1/principals",json={"token_hash":hashlib.sha256(token.encode()).hexdigest(),"role":"viewer","expires_at":int(time.time())+300},headers=auth(t))
    assert r.status_code==201
    h={"Authorization":"Bearer "+token}
    assert c.get("/v1/telemetry",headers=h).status_code==200
    assert c.delete("/v1/principals/"+r.json()["id"],headers=auth(t)).status_code==204
    assert c.get("/v1/telemetry",headers=h).status_code==401
    assert len(c.get("/v1/audit",headers=auth(t)).json())>=2
