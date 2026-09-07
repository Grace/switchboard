# Deployment

## Preparation

The modules create billable resources when you run Terraform. Nothing was provisioned while producing this repository. Use a separate reviewed root configuration with a remote encrypted state backend, locking, explicit AWS region and standard tags. Run `terraform init`, `terraform validate`, then review a saved plan before apply.

Use private subnets across at least two Availability Zones. Customer tasks need controlled outbound HTTPS to provider APIs and the control plane. Control-plane tasks need Postgres access and outbound access as required by your deployment. ECR/Logs/Secrets endpoints or NAT are needed for task startup. Do not expose the gateway's port 8080 outside the task.

## Postgres and control plane

1. `deploy/terraform/postgres` creates an encrypted Multi-AZ RDS PostgreSQL instance, private subnet group, client-SG-only port 5432 access, forced TLS, 14-day backups and deletion protection. Choose an engine version available in your region. Pass existing KMS key and subnet/security-group IDs. RDS manages the master password; only its secret ARN is output. The final snapshot name must be unique if you later replace a previously deleted deployment.
2. From a trusted migration runner, apply `python -m controlplane.migrate` with `MIGRATION_DATABASE_URL` resolved through `asm-exec`. Use a dedicated database/cluster. Migrations create the `switchboard_app` role, schemas, RLS and security-definer helpers. They run under a transaction/advisory lock and reject changed migration checksums.
3. Create a separate runtime login in your approved database credential workflow, with no superuser, role-creation, database-creation or RLS bypass privileges. Grant it `switchboard_app`. Store its full connection string with `sslmode=verify-full` and a CA path in the control-plane secret. Migration credentials must not be installed in the long-running service.
4. Provision the first tenant with `MIGRATION_DATABASE_URL` and `BOOTSTRAP_ADMIN_TOKEN` passed as dynamic references: `asm-exec -- python -m scripts.bootstrap acme-prod`. It inserts only the digest of the pre-created bootstrap token; the token is not printed. The bootstrap admin expires after seven days. Use it to register normal role credentials and then revoke it.
5. Build `Dockerfile.controlplane`; create a derivative image containing the public RDS CA bundle at the path in the connection string. Scan and pin by digest. Do not embed a connection string or signing seed in the image.
6. `deploy/terraform/controlplane` registers the task and runs two Fargate replicas against an **existing** target group, cluster, execution/task roles, private subnets and task security groups. Pass `DATABASE_URL` and `POLICY_SIGNING_SEED` in `secret_arns`, plus `policy_key_id`. It does not run migrations at every application startup.
7. Attach the target group to an existing ALB HTTPS listener with an ACM certificate. Target type must be `ip`, port 8000, health path `/readyz`; only the ALB SG may reach the control tasks. Configure edge rate limiting/WAF and an appropriate ALB idle timeout. The application itself has concurrency/body/pool bounds, but does not implement a distributed control-plane rate limiter.
8. Publish a tenant policy using `PUT /v1/policy` as an admin/publisher. See the body format below. Register an `agent` principal for the sidecar, independently of the local application credential.

```json
{
  "schema": 1,
  "tenant": "acme-prod",
  "version": 1,
  "issued_at": 1800000000,
  "expires_at": 1800003600,
  "routes": [{"provider":"openai","model":"YOUR_APPROVED_MODEL"}]
}
```

Replace timestamps with current Unix seconds and approved model identifiers. These illustrative values are not a bootstrap policy. Publish and verify before starting dependent applications, or let the gateway sync at startup. An initial control-plane outage with no cached policy fails readiness; existing valid caches remain usable.

## Customer sidecar

1. Copy `config.example.json` to an ignored `config.json`. Set tenant, control URL, public verification keys and the provider subset you actually configure. Remove unused providers so startup does not require their credentials. Local and control tokens are distinct, high-entropy secrets.
2. Build `Dockerfile.gateway`, then a tenant-specific derivative image:

```dockerfile
FROM your-registry/switchboard-gateway@sha256:REVIEWED_DIGEST
COPY config.json /etc/switchboard/config.json
```

3. Pin that image digest in `deploy/task-definition.json` or consume `deploy/terraform`'s `container_definition` output in your existing task. The task example includes a small reviewed init container to set the writable volume's ownership. Replace its image placeholder with a digest-pinned image. The init runs only `chown`/`chmod`; the gateway itself runs as UID/GID 65532 with all Linux capabilities dropped and a read-only root filesystem.
4. Provide execution-role access to exactly the secret ARNs and relevant KMS keys, ECR pull and log writing. No runtime task-role AWS permissions are required for the default gateway. The app receives the local token as its OpenAI SDK credential, never provider credentials. Add a `HEALTHY` dependency on `switchboard`.
5. Use `awsvpc`, Fargate Linux platform 1.4.0 or a supported later platform, and allocate task CPU/memory for all containers. App requests go to `http://127.0.0.1:8080/v1`; configure SDK retries to zero. The sidecar uses `/gateway --healthcheck`, which needs no shell, curl or wget.
6. Add the Collector as a same-task container if wanted. Set `otlp_url` to `http://127.0.0.1:4318/v1/traces` and `allow_local_http` to true. `deploy/collector.yaml` scrapes the loopback Prometheus endpoint and exports traces/metrics to your configured backend. Review resource limits and exporter authentication independently.

## Durability choice

The task example uses ephemeral storage. Its policy/spool survive a container restart within the task but disappear on task replacement. This is **not lossless telemetry across task termination**. The bounded memory queue may also lose admitted events on abrupt process death. Metrics count observed queue/disk drops; a killed process cannot count events it never persisted.

For persistent cache/spool across task replacement, mount an encrypted EFS access point at `/data`, enforce UID/GID 65532, enable transit encryption and IAM authorization, and restrict mount-target TCP 2049 to the task SG. Grant only `ClientMount`/`ClientWrite` for that access point. Omit the chown init when EFS access-point ownership supplies permissions.

**One data directory must have exactly one running gateway.** A process file lock enforces that boundary. Use a stable independently managed task slot/access point per sidecar and stop the old owner before starting its replacement. Do not point a rolling/scaled ECS service's replicas at the same directory. EFS orchestration/scavenging for arbitrarily scaled replicas is not included; retain the default ephemeral deployment only if its telemetry-loss semantics are acceptable.

## Operations and rollback

Alert on policy refresh errors/approaching expiry, inference errors, rejections, dropped telemetry, export errors and spool growth. Poll authenticated `/runtime` for policy expiry. A control-plane outage is nonfatal only until the cached policy expires. Replace secret-injected tasks after rotation. Test draining with a long stream and prove app-stop ordering before release.

Keep Postgres point-in-time recovery and restore drills. Retain telemetry with a scheduled trusted maintenance job; tables are not automatically partitioned. Delete old telemetry in small batches after your agreed retention period, and retain audit/policy records according to customer requirements. Runtime role cannot delete audit data.

Roll back an image by redeploying the previous digest only if schema compatibility has been checked. Roll back routing by publishing a **higher** policy version. Do not edit old migration files or restore old policy-cache snapshots over newer versions. Use forward migrations; automated destructive down migrations are intentionally absent.
