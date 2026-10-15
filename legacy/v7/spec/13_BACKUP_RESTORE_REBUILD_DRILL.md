# BreachAtlas — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Drill procedure
1. Create deterministic synthetic dataset and record manifest/digests.
2. Back up authoritative DB + irreplaceable object metadata/content.
3. Destroy a disposable deployment.
4. Restore into a clean environment using only documented secrets/provider bootstrap.
5. Delete derived search/graph/cache/projection stores.
6. Rebuild them from authority.
7. Run integrity/count/hash/relationship checks and golden E2E read workflows.
8. Measure RPO/RTO and publish result with version/hardware.
9. Record failure and remediation in a DR report artifact.

A scheduled drill is mandatory before stable v1 and after any material storage/backup architecture change.
