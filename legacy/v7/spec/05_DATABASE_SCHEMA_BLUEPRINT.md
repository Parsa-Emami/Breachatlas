# BreachAtlas — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Authoritative relational tables
- `cases`
- `evidence`
- `evidence_manifests`
- `custody_events`
- `analyzer_plugins`
- `analyzer_runs`
- `derived_artifacts`
- `entities`
- `relationships`
- `timeline_events`
- `hypotheses`
- `findings`
- `legal_holds`
- `export_packages`
- `outbox_messages`
- `audit_events`

## Universal columns
Where applicable: opaque primary ID, owning scope ID, aggregate/version number, created/updated instant, creator/updater actor where meaningful. Sensitive fields are explicit rather than hidden in generic JSON blobs. JSONB is reserved for versioned documents/extensible metadata with JSON Schema and migration plan.

## Constraints
Use database unique/foreign/check constraints for correctness that must survive concurrency. Soft deletion is not a substitute for retention/legal-hold semantics. Outbox rows are inserted in the same transaction as authoritative state changes.

## Index proof
Every nontrivial index is linked to a measured query plan/workload. CI integration tests use real PostgreSQL; production query regressions are captured with representative fixtures before v1.
