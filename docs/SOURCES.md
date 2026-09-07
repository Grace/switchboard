# Implementation references

Reviewed during implementation, 2026-09-07:

- [OpenAI Chat Completions](https://developers.openai.com/api/reference/cli/resources/chat/subresources/completions)
- [Anthropic streaming](https://platform.claude.com/docs/en/build-with-claude/streaming)
- [Gemini content generation](https://ai.google.dev/api/generate-content)
- [OTLP specification](https://opentelemetry.io/docs/specs/otlp/)
- [ECS EFS volumes](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_EFSVolumeConfiguration.html)
- [ECS EFS best practices](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/efs-best-practices.html)
- [RDS managed credentials](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-secrets-manager.html)
- [RDS PostgreSQL TLS](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/PostgreSQL.Concepts.General.SSL.html)
- [Terraform RDS resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance)
- [FastAPI dependency](https://pypi.org/project/fastapi/), [Uvicorn](https://pypi.org/project/uvicorn/), [Psycopg](https://pypi.org/project/psycopg/), [cryptography](https://pypi.org/project/cryptography/)

These sources establish wire-format and configuration guidance. They do not substitute for running this implementation against the target services.
