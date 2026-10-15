# ADR 0005 — BreachAtlas reference decision

**Status:** Accepted for v1

## Decision
AnalyzerPlugin v1 is an OCI image pinned by digest, no-network by default, read-only evidence mount, bounded resources and structured output manifest.

## Consequences
Implementation and tests must preserve this boundary. An alternative is allowed only through the relevant port/adapter when it preserves authority, public contracts, security invariants and migration semantics.

## Revisit trigger
Measured benchmark, security evidence, maintenance/licensing change or operational incident demonstrates the reference choice no longer satisfies the declared workload/threat model. Revisit via a new superseding ADR; never silently rewrite history.
