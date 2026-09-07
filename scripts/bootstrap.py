"""Offline tenant provisioning. No token or signing material is printed."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import os
import uuid
import psycopg
from controlplane.policy import ID

parser=argparse.ArgumentParser()
parser.add_argument("tenant")
args=parser.parse_args()
if not ID.fullmatch(args.tenant):
    parser.error("invalid tenant identifier")
token=os.environ["BOOTSTRAP_ADMIN_TOKEN"]
if len(token)<32:
    raise SystemExit("bootstrap token must have at least 32 bytes of random entropy")
with psycopg.connect(os.environ["MIGRATION_DATABASE_URL"]) as db:
    db.execute("INSERT INTO tenants(id) VALUES(%s)",(args.tenant,))
    db.execute("INSERT INTO principals(id,tenant_id,token_hash,role,expires_at) VALUES(%s,%s,%s,'admin',%s)",
               (uuid.uuid4(),args.tenant,hashlib.sha256(token.encode()).hexdigest(),datetime.now(timezone.utc)+timedelta(days=7)))
print("Tenant provisioned; bootstrap admin expires in seven days.")
