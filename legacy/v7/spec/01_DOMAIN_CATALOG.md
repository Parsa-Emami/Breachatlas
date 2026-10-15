# BreachAtlas — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Domain objects
- `Case`
- `Evidence`
- `EvidenceManifest`
- `CustodyEvent`
- `AnalyzerPlugin`
- `AnalyzerRun`
- `DerivedArtifact`
- `Entity`
- `Relationship`
- `TimelineEvent`
- `Hypothesis`
- `Finding`
- `LegalHold`
- `ExportPackage`

## Aggregate rules
- Aggregate mutations occur through application commands, never controller/model convenience writes.
- Aggregate version is checked on conflicting writes.
- Invariants are tested with illegal-transition/negative cases.
- Domain objects do not import Laravel/Eloquent/vendor SDKs.

## Frozen v1 invariants
1. Evidence content address/digest is fixed after sealing.
2. Custody event is append-only and actor/time/reason linked.
3. Analyzer sees read-only evidence and writes only new derived artifact storage.
4. Legal hold overrides normal retention/deletion.
5. Timestamp stores original representation, timezone/offset, normalized UTC, precision and confidence when known.
