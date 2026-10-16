# BreachAtlas — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Database
Use expand/backfill/verify/switch/contract. Backfills are resumable and checkpointed. Mixed N-1/N application versions are supported for the documented rolling-upgrade window or deployment is explicitly stop-the-world with operator warning.

## Contracts
OpenAPI/event/plugin schema compatibility tests compare the candidate against latest stable. Consumers get a deprecation window before removal.

## Derived stores
Upgrade logic never mutates only the derived store. If projection schema changes, introduce a new projection version, rebuild in parallel, verify checkpoint/digest, then switch readers.

## Rollback
Rollback cannot rely on restoring a stale database snapshot after new writes. Prefer forward repair; if code rollback is supported, schema remains backward-compatible through the rollback window.
