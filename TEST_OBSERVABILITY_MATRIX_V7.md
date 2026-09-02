# BreachAtlas — Test & Observability Matrix v7

| Layer | Mandatory proof |
|---|---|
| Domain | invariant + illegal transition + property tests |
| Persistence | real DB integration + transaction rollback |
| Async | duplicate/idempotency + retry + dead-letter/cancel |
| Contracts | schema compatibility + golden examples |
| Authorization | object/resource isolation + privilege downgrade/revoke |
| Engine | deterministic fixtures + timeout/cancellation/resource budget |
| Failure | all cases in `FAILURE_RECOVERY_PROOF_V7.md` |
| Observability | one trace spans entry -> domain -> worker/engine -> store; redaction verified |
| Performance | workload baseline + saturation/backpressure |
| Recovery | restore/rebuild/reconciliation drill |

### Core metrics
`requests_total`, `request_duration`, `errors_total`, `jobs_queued`, `job_age`, `job_retries`, `dead_letters`, `engine_duration`, `reconciliation_lag`, datastore latency/errors plus project-specific business metrics.
