# Terraform modules — reference only, no longer maintained

These modules work and CI still validates their syntax, but **CloudFormation is
now the source of truth** for deploying Switchboard. See `deploy/cloudformation/`.

## Why

Switchboard is distributed through AWS Marketplace, which ingests CloudFormation
templates, ECS task definitions and Helm charts. It does not ingest Terraform.
Maintaining two definitions of the same nine resources guarantees they drift
apart, and a stale definition that still applies produces infrastructure quietly
different from what the documentation describes.

Freezing rather than deleting keeps these available as a working reference for
anyone deploying with Terraform, and preserves the design as written, without
obliging them to track CloudFormation changes.

## What that means in practice

- **Not updated** alongside `deploy/cloudformation/`. Assume they lag.
- Still syntax-checked by the `terraform` CI job, which catches accidental damage
  cheaply.
- Anything relying on them should verify against the CloudFormation templates,
  which are the definitions that ship to customers.

## What is here

| Path | Provisions |
|---|---|
| `postgres/` | RDS Postgres, subnet group, security group and ingress, parameter group |
| `controlplane/` | CloudWatch log group, ECS task definition, Fargate service |
| `main.tf` | Not a deployable module. Emits a `container_definition` for the sidecar that a caller merges into their own task definition |
| `example.tf.txt` | Shows that merge. Deliberately not a `.tf` file, so it is excluded from `fmt` and `validate` |

The CloudFormation equivalents are `controlplane.yaml` for an existing network
and `quickstart.yaml` for an account with nothing to attach to. Neither reproduces
`main.tf`'s fragment-composition pattern, because CloudFormation has no way to
merge a partial container definition into a task definition somebody else owns —
the sidecar ships as a task-definition template instead.
