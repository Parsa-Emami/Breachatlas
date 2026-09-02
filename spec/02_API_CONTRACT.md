# BreachAtlas — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## HTTP conventions
- Prefix `/api/v1`; JSON UTF-8; explicit content type.
- Resource IDs are opaque UUID/ULID-style identifiers and authorization is re-evaluated after lookup.
- Cursor pagination for unbounded collections.
- Mutation request/response schemas are versioned in OpenAPI; unknown security-sensitive fields are rejected where ambiguity is dangerous.
- Stable error codes follow the common error standard.

| Method | Route | Purpose | Gate |
|---|---|---|---|
| `POST` | `/cases` | Create case | auth + validation + idempotency where side-effecting |
| `POST` | `/cases/{case}/evidence` | Stream evidence upload | auth + validation + idempotency where side-effecting |
| `GET` | `/evidence/{evidence}/verify` | Recompute/verify manifest integrity | auth + validation + idempotency where side-effecting |
| `POST` | `/analyzers/{plugin}/runs` | Run isolated analyzer against read-only evidence | auth + validation + idempotency where side-effecting |
| `GET` | `/cases/{case}/timeline` | Query derived timeline | auth + validation + idempotency where side-effecting |
| `POST` | `/cases/{case}/exports` | Build portable verifiable export | auth + validation + idempotency where side-effecting |

## Compatibility
Additive compatible changes may ship in v1. Removing/renaming/changing semantics requires deprecation + migration and normally a new API major. Golden request/response fixtures run in CI.
