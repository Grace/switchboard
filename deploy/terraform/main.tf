terraform {
  required_version = ">= 1.6, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}

# Composable sidecar output: caller adds it to an existing awsvpc task.
# Build a tenant-specific image containing ONLY config.json and public trust keys.
# Credentials remain references in the ECS secrets array.
variable "name" { type = string }
variable "region" { type = string }
variable "image" {
  type = string
  validation {
    condition = can(regex("@sha256:[0-9a-f]{64}$", var.image))
    error_message = "Use an immutable image digest."
  }
}
variable "secret_arns" {
  type = map(string)
  description = "Environment name to full Secrets Manager ARN (optionally with :json-key:: suffix). Never plaintext."
  validation {
    condition = alltrue([for v in values(var.secret_arns) : can(regex("^arn:[^:]+:secretsmanager:", v))])
    error_message = "Only Secrets Manager references are accepted."
  }
}
variable "log_kms_key_arn" { type = string }
variable "cpu" {
  type = number
  default = 256
}
variable "memory" {
  type = number
  default = 256
}

resource "aws_cloudwatch_log_group" "gateway" {
  name = "/ecs/${var.name}/switchboard"
  retention_in_days = 30
  kms_key_id = var.log_kms_key_arn
}
locals {
  container = {
    name = "switchboard"
    image = var.image
    essential = true
    user = "65532:65532"
    cpu = var.cpu
    memory = var.memory
    readonlyRootFilesystem = true
    stopTimeout = 120
    linuxParameters = { capabilities = { drop = ["ALL"] } }
    secrets = [for name, arn in var.secret_arns : { name = name, valueFrom = arn }]
    mountPoints = [{ sourceVolume = "switchboard-data", containerPath = "/data", readOnly = false }]
    dependsOn = [{ containerName = "switchboard-init", condition = "SUCCESS" }]
    healthCheck = { command = ["CMD", "/gateway", "--healthcheck"], interval = 15, timeout = 5, retries = 3, startPeriod = 60 }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group = aws_cloudwatch_log_group.gateway.name
        awslogs-region = var.region
        awslogs-stream-prefix = "gateway"
        mode = "non-blocking"
        max-buffer-size = "4m"
      }
    }
  }
}
output "container_definition" { value = local.container }
output "volume_name" { value = "switchboard-data" }
output "application_dependency" { value = { containerName = "switchboard", condition = "HEALTHY" } }
output "execution_role_secret_resources" {
  value = distinct([for arn in values(var.secret_arns) : join(":", slice(split(":", arn), 0, 7))])
}
