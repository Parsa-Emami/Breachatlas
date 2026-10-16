# BreachAtlas — Failure & Recovery Proof v7

## Mandatory injected failures
- hash mismatch
- interrupted upload
- object store outage
- analyzer crash
- OpenSearch loss
- timezone ambiguity
- legal hold/delete conflict
- export corruption

## Pass criteria
For every failure: no invariant violation; no unauthorized bypass; no unbounded retry storm; orphan resources are reconciled; user-visible state becomes correct; telemetry identifies cause; retry/cancel/manual recovery is documented; recovery test is automated where feasible.
