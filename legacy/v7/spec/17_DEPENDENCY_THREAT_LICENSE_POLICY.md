# BreachAtlas — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

Dependencies are evaluated on necessity, license compatibility, maintenance/security history, transitive footprint, privilege/network needs and replaceability. High-privilege dependencies/tools stay behind adapters and are invoked with minimum permissions. Lock files are committed. Release images are digest-pinned.

Copyleft dependencies that could affect distribution architecture receive explicit legal/license review; do not copy third-party rule/signature/data corpora unless their license and attribution permit the intended distribution. Dataset/model redistribution is separately checked.

Automated dependency updates must still pass contract/integration/fuzz/security suites; a green compilation is insufficient.
