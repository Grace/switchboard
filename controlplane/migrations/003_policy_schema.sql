-- The signed policy document carries its own schema version, but only inside
-- the base64 payload the signature covers, so nothing could select on it.
--
-- That made a schema bump a fleet-wide outage rather than a rollout: GET
-- /v1/policy served the newest policy per tenant unconditionally, and a gateway
-- that cannot verify a document rejects it (policy.go hard-rejects schema != 1),
-- keeps serving from its cached copy, and goes 503 when that expires. The
-- symptom arrives up to seven days after the change that caused it, on every
-- sidecar at once, and the publish that caused it looked like it worked.
--
-- Denormalised at publish time rather than derived in SQL: the PUT handler has
-- already parsed and validated the document, so it knows the schema, and
-- base64-decoding a signed payload inside a query to recover a number the
-- writer already had would be the wrong place to spend it.
--
-- Existing rows are schema 1 because that is the only schema that has ever been
-- accepted -- policy.py and policy.go both reject anything else -- so the
-- backfill is a statement of fact rather than a guess.
ALTER TABLE policies ADD COLUMN IF NOT EXISTS schema int NOT NULL DEFAULT 1;

-- Serves the negotiation query: newest version at or below the schema a
-- gateway says it can verify.
CREATE INDEX IF NOT EXISTS policies_tenant_schema_version
  ON policies (tenant_id, schema, version DESC);
