# BreachAtlas — State Machines v7

- **Case:** `OPEN -> INVESTIGATING -> CONTAINED -> REMEDIATED -> CLOSED`
- **Evidence:** `UPLOADING -> VERIFYING -> SEALED -> HELD | RETENTION_ELIGIBLE -> DELETED_TOMBSTONE`
- **AnalyzerRun:** `QUEUED -> RUNNING -> COMPLETE | FAILED | QUARANTINED`

Transitions are domain commands with authorization, optimistic version check where applicable, audit event and invariant tests. Illegal transitions fail closed and are observable.
