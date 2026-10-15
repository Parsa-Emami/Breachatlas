# BreachAtlas — Definitive Sequential Roadmap v7

**Portfolio order:** 10 / 10
**Complexity:** Very high
**Planning estimate:** 14–22 focused weeks (not a promise; recalibrate after Phase 1)

**Why this order:** Evidence handling and chain-of-custody claims demand the most discipline. Build last, after hashing, isolation, projection and audit primitives are proven elsewhere.

## First executable proof
Case → evidence hash/seal → custody event → isolated analyzer → derived artifact → OpenSearch projection → drop/rebuild → sealed export verification.

## Rules for this repository
- One phase at a time; no implementation work for phase N+1 before phase N exit evidence is merged.
- Contract/schema changes precede dependent implementation.
- Every retryable operation is idempotent.
- Every derived store/projection has a rebuild path.
- Negative and failure tests are part of the feature, not post-release hardening.
- Status claims must be evidence-backed.

## Phase 0 — Case/evidence model

**Implementation deliverables**
- Case/actor/evidence domain
- Content-addressed evidence identity
- Classification/retention/legal-hold states
- Immutable custody event model

**Required verification**
- domain invariant tests
- cross-case auth tests
- custody immutability tests

**Definition of Done**
- Evidence identity and custody history cannot be silently rewritten after creation.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 1 — Streaming upload/hash/seal

**Implementation deliverables**
- Stream to quarantine/object store
- Hash during upload with length checks
- Finalize immutable seal metadata
- Abort/cleanup partial uploads

**Required verification**
- partial upload tests
- hash mismatch tests
- large stream tests

**Definition of Done**
- Only fully received, hash-verified objects become sealed evidence; partials never appear as valid evidence.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 2 — Custody/legal hold

**Implementation deliverables**
- Signed/attributable custody events
- Legal hold prevents deletion/retention expiry
- Transfer/checkout state rules
- Clock/source metadata

**Required verification**
- hold enforcement
- invalid transition tests
- audit completeness

**Definition of Done**
- Deletion is impossible while legal hold is active and custody transitions are append-only.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 3 — Analyzer sandbox contract

**Implementation deliverables**
- Analyzer plugin contract
- Rootless/no-network default
- Read-only evidence mount
- Resource/time limits and cleanup

**Required verification**
- malicious analyzer tests
- egress denial
- crash cleanup

**Definition of Done**
- Analyzers cannot modify source evidence or escape defined runtime/network boundaries.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 4 — Timeline normalization

**Implementation deliverables**
- Normalize timestamps with source/timezone/precision
- Preserve raw value alongside normalized value
- Stable derived event IDs
- Explicit confidence/ambiguity

**Required verification**
- timezone/DST fixtures
- reorder/duplicate tests

**Definition of Done**
- Timeline ordering never destroys original timestamp evidence and ambiguous times remain marked ambiguous.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 5 — OpenSearch projection/rebuild

**Implementation deliverables**
- Projection schema/version
- Bulk idempotent indexing
- Alias-based rebuild/switch
- Source of truth remains PostgreSQL/object evidence

**Required verification**
- drop/rebuild test
- mapping migration tests

**Definition of Done**
- OpenSearch can be deleted and rebuilt without loss of authoritative case/evidence/custody data.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 6 — Investigation graph/hypotheses

**Implementation deliverables**
- Derived entity/relationship graph
- Hypotheses separated from observed facts
- Analyst rationale/audit
- Rebuildable projections

**Required verification**
- fact-vs-hypothesis tests
- projection rebuild

**Definition of Done**
- UI/API never presents analyst hypothesis as raw observed evidence.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 7 — Portable export/verifier

**Implementation deliverables**
- Manifest with hashes and schemas
- Export selected evidence/custody/timeline
- Offline verifier
- Deterministic bundle layout

**Required verification**
- tamper tests
- cross-machine verify
- partial bundle tests

**Definition of Done**
- Any modified/missing file in an export is detected offline without needing the BreachAtlas server.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 8 — Scale/retention/public v1

**Implementation deliverables**
- Large evidence benchmark
- Retention/destruction workflow with legal-hold checks
- Recovery drills
- Signed release/SBOM

**Required verification**
- object-store failure tests
- restore drill
- clean install

**Definition of Done**
- Public v1 demonstrates verifiable export, derived-store rebuild, legal-hold enforcement and documented evidence-handling limits.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Public v1 invariant
The project is not called production-ready merely because all phases are coded. `PUBLIC-V1-GO` requires the repository release gate, clean-install proof, security/recovery evidence and signed/verifiable release artifacts.
