# Security and key rotation

## Trust boundaries

One customer task is one trust domain. The gateway binds only to a loopback IP and requires an application bearer token. Other containers in that task share its network namespace; do not colocate untrusted workloads. Metrics and health endpoints assume this task boundary. Gateway credentials never reach the control plane. Configuration, trust keys, disk cache and binaries must be writable only by deployment operators/the sidecar as appropriate.

All configured remote endpoints require HTTPS; an explicit option allows HTTP only to localhost/loopback for local tests or a same-task Collector. Redirects are rejected. Provider response bodies, prompts, completions and bearer values are not logged or included in product telemetry. Metadata includes request/trace IDs, provider, attempt count, status and timestamps. Local trace context is accepted but request IDs are always regenerated.

The control plane stores SHA-256 hashes of high-entropy random bearer tokens, not passwords. A password-derived token is unsafe and unsupported. Roles and tenant membership come from Postgres on each call. Public endpoint handlers never accept an arbitrary tenant header. Table queries explicitly filter tenant, with forced RLS on policies/telemetry/audit as a second layer. The runtime database login must be a member only of `switchboard_app`, not migration owner, superuser or `BYPASSRLS`. The authentication function can read credential hashes but exposes only principal ID, tenant and role. Security-definer functions fix their search path and revoke public execution.

RLS guards accidental missing filters; it is not isolation from a fully compromised runtime database session, which can change its own `app.tenant` setting. For that threat model use separate database credentials/databases or an external authorization proxy per tenant. Similarly, a compromised signing control plane can sign malicious routing policies within the gateway's locally constrained provider URLs. Signatures protect distribution integrity, not a compromised signer.

## Policy format

Envelope fields: `key_id`, base64 `payload`, base64 Ed25519 `signature`. Signed bytes are:

```text
switchboard-policy-v1\n<key_id>\n<canonical payload bytes>
```

Schema 1 is a restricted canonical JSON subset: only named integer fields, ASCII identifier strings, arrays of known route objects, lexicographically sorted object keys, no whitespace. UTF-8 Unicode identifiers, floats, unknown fields, duplicate keys, extra whitespace and alternate key order are rejected by the Go verifier's canonical byte comparison. Routes preserve order. The Python signer and Go verifier share a fixture verified by both languages. This is not a general-purpose RFC 8785 implementation and must not be extended to arbitrary JSON without revisiting canonicalization.

Keys are pinned out of band in the immutable deployment configuration. The signer receives a 32-byte Ed25519 seed from a secrets system, base64 encoded. Sidecars receive only public keys. Keep signing credentials separate from provider credentials and agent credentials.

## Rotation procedure

1. Generate a new signing seed using a cryptographically secure generator inside your approved secret-management workflow. Store it without printing it; export only its public key.
2. Deploy gateways with both old and new public keys under distinct key IDs. Confirm rollout and cache persistence.
3. Update the control-plane signing seed and key ID, roll its tasks, and publish a strictly newer policy for every tenant. During mixed control-plane rollout, either trusted key may sign; tenant version locking serializes publication.
4. Confirm every gateway has the new policy version. Retire the old public key only after old cached documents can be replaced, including disconnected tasks. Removing a key while a task has only its old cached document intentionally makes startup fail closed.
5. For emergency compromise, remove the affected trust key and deploy a fresh higher-version policy signed by another key. Cache rollback detection persists only as long as its data volume; protect volumes and backups from unauthorized rollback.

Never reuse a policy version with changed content. To roll configuration back, publish the desired old routes as a new higher version. Policies expire within seven days; schedule renewal operationally before expiry. This repository does not automatically renew policies.

## Secrets handling

For agent/operator commands, use `asm-exec` with dynamic references. For example:

```sh
DATABASE_URL='{{resolve:secretsmanager:switchboard/control:SecretString:database_url}}' \
POLICY_SIGNING_SEED='{{resolve:secretsmanager:switchboard/control:SecretString:signing_seed}}' \
POLICY_KEY_ID=key-2026-09 \
asm-exec -- python -m uvicorn controlplane.app:app --host 127.0.0.1 --port 8000 --no-access-log
```

Do not run commands that print resolved environment variables or secret-bearing connection strings. `asm-exec` is an external AWS skill/runtime tool, not vendored here. ECS uses its native `secrets` injection at task startup: specify secret ARNs, never values. The ECS execution role retrieves them; the gateway task role does not need Secrets Manager access. Restrict execution-role resources and KMS decrypt permissions. Rotated injected credentials require replacement tasks.

Keep migration credentials separate from runtime database credentials. Supply the RDS CA certificate and use `sslmode=verify-full` and `sslrootcert` for remote Postgres connections. Do not use the RDS master login as the application login.

## Release security work

Pin deployment images by digest after a clean build and scan. Base Docker image tags, GitHub action major tags and transitive Python packages are not fully locked in this release; generate reviewed locks and provenance before customer deployment. CI includes a Python dependency audit, but its result has not been obtained in this environment. No independent penetration test or AWS IAM review has been completed.
