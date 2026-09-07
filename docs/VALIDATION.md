# Validation performed

Date: 2026-09-07. Host toolchain: Go 1.24.1 on macOS ARM64; bundled Python 3.12 with cryptography. Release Docker/CI definitions target Go 1.26 and Python 3.12. Local builds are validation artifacts, not approved deployment binaries.

## Passed locally

- `go vet ./...`.
- `SWITCHBOARD_IN_MEMORY_TESTS=1 go test -race -coverprofile=coverage.out ./...`: 24 top-level Go tests plus table subtests passed. Gateway package statement coverage: **75.4%**. The command-line main package has **0% test coverage**; it is compile-checked only.
- Cross-compilation of the Go command to Linux AMD64 and Linux ARM64 with CGO disabled.
- Three Python `unittest` policy tests, including Ed25519 signature verification of the fixture shared with Go.
- Python syntax parsing for all control-plane/scripts/tests sources, and JSON parsing for configuration, task and Terraform JSON files.
- Shell syntax validation of the GitHub publication helper.

Go scenarios include normal streaming for all three adapters; stream truncation and bounded SSE parsing; unsupported tool responses; configuration and trace-context checks; policy tampering, canonicalization, rotation, rollback and expired-cache recovery; no replay after acceptance/transport ambiguity; cancellation; auth, rate and concurrency limits; circuit probe behavior; retry budgets; control-plane-down routing; disk replay/acknowledgement; saturated queue admission; and OTLP delivery during control-plane failure.

## Not passed or not run here

Real socket tests could not bind a local port (`operation not permitted`). The in-process transport exercises handler/adapter/retry paths but does not validate TCP, real HTTP flushing, TLS or timeout behavior. CI uses the real socket transport by default.

Python dependency downloads failed due restricted network/DNS; escalation was rejected. The installed environment lacks FastAPI/Psycopg/Postgres. Full control-plane API, migration, RLS, revocation and deduplication tests are included in `controlplane/tests/test_postgres.py` and required by CI with a disposable Postgres service; **they were not executed locally**.

Docker failed its environment check. Terraform is unavailable. Container builds/scans, dependency audit, Terraform provider validation/planning, live-provider requests, cloud deployment, load/soak testing and end-to-end graceful shutdown have **not** been verified. JSON syntax checks do not establish Terraform validity.

GitHub access failed, and elevated network access was rejected by the session's automatic approval policy. No remote repository or remote CI run was created. The delivered local repository, source ZIP and Git bundle are ready for publication from an authorized terminal.
