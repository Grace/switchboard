"""Transactional, advisory-locked migrations with checksum drift detection."""
import hashlib
import os
from pathlib import Path
import psycopg

def migrate(dsn: str):
    with psycopg.connect(dsn, connect_timeout=10) as db:
        db.execute("SELECT pg_advisory_xact_lock(736248100)")
        db.execute("CREATE TABLE IF NOT EXISTS schema_migrations(name text PRIMARY KEY, checksum text NOT NULL)")
        applied = dict(db.execute("SELECT name,checksum FROM schema_migrations").fetchall())
        for path in sorted((Path(__file__).parent / "migrations").glob("*.sql")):
            body = path.read_text()
            digest = hashlib.sha256(body.encode()).hexdigest()
            if path.name in applied:
                if applied[path.name] != digest:
                    raise RuntimeError("migration checksum mismatch")
                continue
            db.execute(body)
            db.execute("INSERT INTO schema_migrations VALUES(%s,%s)", (path.name, digest))

if __name__ == "__main__":
    migrate(os.environ["MIGRATION_DATABASE_URL"])
