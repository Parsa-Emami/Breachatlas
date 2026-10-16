# BreachAtlas — Component Architecture v7

## Runtime/components
- Laravel 13
- React graph/timeline UI
- PostgreSQL 18
- OpenSearch derived search/timeline
- S3-compatible object store
- rootless Podman analyzer workers
- Valkey
- OpenTelemetry

## Dependency direction
`Web/CLI -> HTTP/Application -> Domain <- Ports <- Infrastructure Adapters`

Specialized workers/engines consume versioned commands/contracts; they do not reach into Laravel tables except through explicit repositories or service APIs owned by the responsible module.

## Cross-cutting
Transactional outbox, idempotent jobs, correlation IDs, OpenTelemetry, structured audit, rate/resource limits, health/readiness and graceful shutdown are mandatory.
