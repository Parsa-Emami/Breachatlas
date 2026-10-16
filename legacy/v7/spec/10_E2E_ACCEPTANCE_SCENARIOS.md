# BreachAtlas — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Golden E2E scenarios
1. Upload -> hash -> seal -> verify evidence
2. Append custody events and verify chain
3. Run isolated CSV/JSON analyzer -> derived timeline
4. Drop OpenSearch and rebuild timeline
5. Apply legal hold then reject deletion
6. Export manifest + hashes + signature then offline verify

For every golden scenario record expected authoritative state, emitted event IDs/types, audit action, projection state, critical metrics and cleanup state. Run from a clean environment with deterministic synthetic fixtures. At least one scenario must fail mid-flight and then converge after restart/retry/reconciliation.
