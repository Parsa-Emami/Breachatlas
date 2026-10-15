# ADR-0001 — BreachAtlas lean release architecture

Status: accepted planning decision, 2026-10-01. Supersedes all runtime/storage/bootstrap decisions in `legacy/v7`; business invariants remain applicable where the selected scope implements them. No released external clients exist in the supplied scaffold, so this is a planning reset, not a live DB migration.

## Why change

The v7 input has zero application source/manifests. Its Laravel/PostgreSQL/cache/secondary-engine baseline adds operational cost before proving a useful app. The owner's objective is personally usable software on a domain with minimum database-service administration. Online interaction is compatible with embedded durable storage; no correctness claim relies on volatile memory as authority.

## Selected composition

- Go private service/CLI
- SQLite case and custody metadata
- Content-addressed local evidence files
- React timeline UI

Distribution: `embedded-private`. Domain/application layer owns invariants; transport validates input and calls explicit use cases; storage/provider adapters implement ports. UI renders state and never guesses durable success. CLI and UI/report reader must agree on the same typed domain outputs. Static-hosted UI cannot provision Podman, capture traffic or run a secret provider in a browser.

## Authority and recovery

| Store | Ownership |
|---|---|
| SQLite | cases, sealed metadata, custody events, holds, notes and transactional jobs |
| Filesystem | immutable source evidence and derived files; read-only analyzers; separate backup |
| Memory/SQLite indexes | rebuildable timeline/search for documented small-case scope |

Removed compulsory services: Laravel, PostgreSQL, OpenSearch, Valkey, S3 server required. No hidden substitution with a self-built SQL server or full distributed event store. SQLite where present has no separate DB daemon, but durable disk, backup, schema evolution and correct constraints still matter. Optional external providers retain their own operational state and may increase total overhead.

## Initial capacity contract — targets, not measured

```json
{
  "active_analysts": 1,
  "evidence_file_max_mib": 100,
  "case_evidence_max_gib": 5,
  "analyzer_concurrency": 1,
  "timeline_events": 100000
}
```

private host هدف 2 vCPU / 2–4 GiB RAM و حداقل 20 GiB SSD به‌علاوهٔ ظرفیت evidence و backup.

Reject or visibly truncate workload beyond limit; no unbounded imports, recursive graph queries, unlimited retention or background queues. C28 benchmarks the target and overload case; publish only measured limits.

## Essential invariants

- Sealed source bytes never modified
- Legal hold takes precedence over deletion
- Raw timestamp and confidence survive normalization

## Trust and deployment boundary

- root میزبان می‌تواند فایل/SQLite را دستکاری کند؛ hash-chain به‌تنهایی immutability نیست
- هش integrity را بررسی می‌کند، منبع واقعی یا قابلیت قضایی را ثابت نمی‌کند
- legal hold باید با backup/retention سازگار باشد؛ پیش‌فرض حذف خودکار evidence خام نداریم

Private service mode requires persistent volume and access control. Public domain can serve a synthetic static demo; it does not imply public runtime admission. Single-host updates may have a maintenance window. No horizontal replicas sharing SQLite disk. Root operator is trusted for local file protection; external checkpoints only add independently verifiable tamper evidence, not magical host immutability.

## Migration and future expansion

Archive-only v7 contracts/bootstrap are not active compatibility promises. C04 defines current exact typed inputs/results; no generic OperationResult substitutes for domain payloads. Versioned file schemas get import/export migration fixtures before formats change. Reuse IDs/invariants, not unimplemented API shapes by default.

Add managed PostgreSQL only when multiple writers/hosts or tenant concurrency demonstrably need it. Add graph/search/telemetry services only after measured query/workload limits fail. Keep adapters so semantic identities and exports survive migration. SaaS requires separate tenant/RBAC/rate/retention/backup and cost decisions; do not silently promote the personal profile to public shared service.

## Rejected initial alternatives

- Uniform Laravel plus PostgreSQL and Valkey for all projects: heavier operations without a working product.
- Storing critical state only in JSON files or RAM: no safe concurrency/durable recovery protocol.
- Browser storage as sole guaranteed backup: origin changes/eviction/clearing may lose data.
- Rebuilding scanners, IdP or crypto primitives for feature parity: greater risk and weaker differentiation.
- Making all ten public services at once: insufficient capacity to maintain high-trust boundaries independently.

Any contrary implementation must add an ADR with evidence and update product/deployment/roadmap together before dependent code.
