# Security and key rotation

## Trust boundaries

One customer task is one trust domain. The gateway binds only to a loopback IP and requires an application bearer token. Other containers in that task share its network namespace; do not colocate untrusted workloads. Metrics and health endpoints assume this task boundary. Gateway credentials never reach the control plane. Configuration, trust keys, disk cache and binaries must be writable only by deployment operators/the sidecar as appropriate.

All configured remote endpoints require HTTPS; an explicit option allows HTTP only to localhost/loopback for local tests or a same-task Collector. Redirects are rejected. Provider response bodies, prompts, completions and bearer values are not logged or included in product telemetry. Metadata includes request/trace IDs, provider, attempt count, status and timestamps. Local trace context is accepted but request IDs are always regenerated.

The control plane stores SHA-256 hashes of high-entropy random bearer tokens, not passwords. A password-derived token is unsafe and unsupported. Roles and tenant membership come from Postgres on each call. Public endpoint handlers never accept an arbitrary tenant header. Table queries explicitly filter tenant, with forced RLS on policies/telemetry/audit as a second layer. The runtime database login must be a member only of `switchboard_app`, not migration owner, superuser or `BYPASSRLS`. The authentication function can read credential hashes but exposes only principal ID, tenant and role. Security-definer functions fix their search path and revoke public execution.

RLS guards accidental missing filters; it is not isolation from a fully compromised runtime database session, which can change its own `app.tenant` setting. For that threat model use separate database credentials/databases or an external authorization proxy per tenant. Similarly, a compromised signing control plane can sign malicious routing policies within the gateway's locally constrained provider URLs. Signatures protect distribution integrity, not a compromised signer.

## Idempotency and content at rest

Provider response bodies, prompts and completions are not logged and are not in product telemetry.
**Enabling `idempotency_ttl_seconds` changes what is at rest**, and that is the one place this
statement needs qualifying: an idempotency entry stores the request body hash and the response
content so a duplicate key can be answered without calling the provider again.

Entries are written to `<data_dir>/idempotency`, mode 0600, bounded by `idempotency_bytes` and
expiring with the TTL. While the feature is on, the data directory holds customer content and
deserves the same protection as the signing seed: encrypted storage, restricted mounts, and no
sharing with untrusted containers in the task.

It is off by default. A change to what a deployment stores should be chosen, not inherited from an
upgrade.

### Replay capture (added 2026-09-08)

`capture_ttl_seconds` is a second and larger qualification of the sentence above, added
deliberately rather than slipped in. Idempotency stores content as a side effect of answering a
duplicate; **capture stores it as the whole purpose**. When it is on, every request writes a record
holding the prompt as received and the completion as returned, together with the routing context
needed to explain where it went: policy version, provider, model, attempts and fault.

What does not change, and is the reason this is a qualification rather than a reversal:

- **Nothing is transmitted.** Records are written to `<data_dir>/capture` and are never attached to
  an event, never exported over OTLP, and never sent to the control plane. The statement about
  product telemetry above remains true exactly as written.
- **Nothing exists unless asked for.** `capture_ttl_seconds` defaults to zero, zero means the store
  is never constructed, and a default deployment does not create the directory.

What does change while it is on: prompts and completions are on that machine's disk for the TTL.
Records are mode 0600 in a 0700 directory, bounded by `capture_bytes` in total and 8 MiB each, swept
every minute and again at startup so a restart is also a compaction. An oversized record is refused
rather than truncated, because a half-written prompt reads as a complete one. A full store refuses
new writes rather than evicting old ones.

The gateway logs a **warning**, not an info line, at every startup while capture is on, naming the
directory and the TTL. An operator should be able to see that they have this on without reading a
config file.

Turning it on takes on the corresponding obligations: encrypted storage, restricted mounts, a
retention position, and an answer for deletion requests. The TTL is a bound, not a policy.

## Runtime profiling

`enable_pprof` exposes Go runtime profiles at `/debug/pprof/`. It is **off by default and
authenticated when on**, which is deliberately stricter than `/metrics`.

The difference is what each exposes. `/metrics` publishes counters, which are safe to read from
anywhere inside the task boundary. A heap profile publishes whatever is in memory: provider API keys,
which the gateway reads from its environment into request headers, along with prompt and completion
text. Other containers in the task share the gateway's network namespace, so an unauthenticated
pprof would let the colocated application read provider credentials out of the gateway process. That
is exactly what the local-token design exists to prevent, so pprof requires the same bearer token as
`/v1/chat/completions`.

Enable it to diagnose a specific problem and turn it off afterwards. Anyone holding the local token
can read the heap while it is on, so the token's blast radius is larger with pprof enabled than
without it.

## Policy format

Envelope fields: `key_id`, base64 `payload`, base64 Ed25519 `signature`. Signed bytes are:

```text
switchboard-policy-v1\n<key_id>\n<canonical payload bytes>
```

Schema 1 is a restricted canonical JSON subset: only named integer fields, ASCII identifier strings, arrays of known route objects, lexicographically sorted object keys, no whitespace. UTF-8 Unicode identifiers, floats, unknown fields, duplicate keys, extra whitespace and alternate key order are rejected by the Go verifier's canonical byte comparison. Routes preserve order. The Python signer and Go verifier share a fixture verified by both languages. This is not a general-purpose RFC 8785 implementation and must not be extended to arbitrary JSON without revisiting canonicalization.

Keys are pinned out of band in the immutable deployment configuration. The signer receives a 32-byte Ed25519 seed from a secrets system, base64 encoded. Sidecars receive only public keys. Keep signing credentials separate from provider credentials and agent credentials.

## Rotation procedure

1. Generate a new signing seed using a cryptographically secure generator inside your approved secret-management workflow. Store it without printing it; export only its public key, which `gateway -public-key` derives by reading the base64 seed on stdin:

   ```sh
   gateway -public-key < seed.b64
   ```

   The seed is read from stdin rather than an argument so it does not reach the process table or a shell history file. Deriving a public key is not signing: the gateway binary still cannot produce a policy it would accept.
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
