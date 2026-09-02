# ADR 0003 — BreachAtlas reference decision

**Status:** Accepted for v1

## Decision
PostgreSQL is authoritative for cases/evidence/custody/legal holds. OpenSearch is a fully rebuildable timeline/search projection.

## Consequences
Implementation and tests must preserve this boundary. An alternative is allowed only through the relevant port/adapter when it preserves authority, public contracts, security invariants and migration semantics.

## Revisit trigger
Measured benchmark, security evidence, maintenance/licensing change or operational incident demonstrates the reference choice no longer satisfies the declared workload/threat model. Revisit via a new superseding ADR; never silently rewrite history.
