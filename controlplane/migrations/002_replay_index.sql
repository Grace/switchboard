-- GET /v1/replay/{id} and controlplane/replay.py both look an event up by the
-- request id inside the JSONB payload. Neither existing index can serve that:
-- the primary key is (tenant_id, id) and telemetry_received_at covers the
-- timestamp, so the predicate on event->>'request_id' scanned the tenant's
-- entire telemetry history and evaluated the extraction per row.
--
-- That is acceptable at development volume and is a customer-facing endpoint
-- degrading with the size of a table nothing prunes, which is the shape of
-- problem that is cheap now and expensive after the first large customer.
--
-- Expression index rather than a generated column: the extraction is exactly
-- what both callers write, so the planner matches it without either of them
-- changing.
CREATE INDEX IF NOT EXISTS telemetry_request_id
  ON telemetry (tenant_id, (event->>'request_id'));
