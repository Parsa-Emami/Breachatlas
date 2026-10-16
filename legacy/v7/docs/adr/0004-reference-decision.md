# ADR 0004 — BreachAtlas reference decision

**Status:** Accepted for v1

## Decision
Timeline events retain original timestamp string/value, timezone/offset if known, normalized UTC, precision, source clock and confidence/ambiguity metadata.

## Consequences
Implementation and tests must preserve this boundary. An alternative is allowed only through the relevant port/adapter when it preserves authority, public contracts, security invariants and migration semantics.

## Revisit trigger
Measured benchmark, security evidence, maintenance/licensing change or operational incident demonstrates the reference choice no longer satisfies the declared workload/threat model. Revisit via a new superseding ADR; never silently rewrite history.
