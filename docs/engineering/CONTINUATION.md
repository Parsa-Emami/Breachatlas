# Current web delivery

ADR-0002-web-application.md and WEB_RUNBOOK.md supersede v0 statements about absent web source, CLI-only delivery and package locations. Root package.json owns apps/web. W01-W08 track web work separately from C01-C40. Existing RiskWeft source is preserved. Do not modify database schemas, migrations, .env files or Dockerfiles.

# Engineering and continuation contract — v0

This file is copied into each standalone repository. The uploaded repository is authoritative for what is implemented; prose is not implementation evidence.

## Order and progress

1. Read `START_HERE.md`, `product/project.json`, `plans/roadmap.json`, `plans/progress.json`, `docs/architecture/ADR-0001-lean-v0.md`.
2. Inspect the actual manifests, sources, tests, CI and git status before choosing work. Match previous implementations to acceptance criteria; never bootstrap into an existing populated folder.
3. Run `python3 scripts/plan.py validate` and `python3 scripts/plan.py next`. Validation checks planning consistency only. Review the first incomplete commit against the current code and any real evidence.
4. Implement the smallest dependency-ready commit. A commit plan may be split; record child IDs and carry the same requirement coverage. Do not make unrelated changes to match a quota of commits.
5. Run real relevant tests and update `plans/progress.json`. `verified` requires evidence with source tree identity, commands, exit codes, environment and observed results. Record blocked items with a concrete reason; proceed only on independent authorized work. Do not mark verified because a document exists.
6. If working from a ZIP, return changed/added files plus updated progress and evidence; preserve original directory paths. Commit titles are Conventional Commits. Actual git commit/push only when requested or within authorized repository workflow. No git SHA is invented for a ZIP.
7. Recompute delivery checksums when packaging. Tag `v0.0.0` denotes planning baseline; C01–C40 are future implementation intents. v1 follows verified release gate.

## Implementation rules

- Never change existing `.env` or `.env.*` without a later explicit instruction. Use runtime secret injection and documented config references; never commit credentials or recovery roots. Do not run archived bootstrap scripts.
- Choose supported toolchain versions from official upstream documentation at C02, record exact versions and dependency lockfiles. v7 version statements are historical, not trusted current install pins.
- Keep engine separate from UI/transport/storage adapters. No project imports source code from a sibling project. Extract shared package only after two working consumers prove need; pin its version.
- No Kubernetes, compulsory service mesh, mandatory Redis/Valkey or multiple databases for v1. Add a service only through an ADR with measured need and operation/recovery costs.
- Files and SQLite still store data. SQLite must be on local persistent disk with WAL/busy timeout/short transactions and supported backup API; do not expose file over NFS or share among replica hosts. One controlled write owner per logical state. Browser IndexedDB is storage, not a backup.
- Durable jobs and idempotency records commit with authoritative state in the same SQLite transaction where jobs exist. Memory queues cannot justify an acknowledged durable task. Retries are bounded and idempotent; events may be delivered more than once.
- Filesystem and SQL are not one transaction: stage bytes, hash/check limits, make bytes durable, atomically publish name/manifest then commit metadata with recovery intents. Reconcile orphan bytes and missing references after crash. Never announce seal before full integrity/durability checks.
- Hashes detect changed content; they do not establish issuer trust or prevent root from rewriting history. Use independently held signer trust and separately stored checkpoints for authenticity/tamper evidence. Describe the threat model honestly.
- No ML security/accuracy claims without dataset license/provenance, grouping/time splits, reviewed labels, baseline comparisons and real held-out evaluation. No rule/scanner zero findings means fully secure claim.
- Default no user payload execution. Rootless containers alone are not sufficient to offer untrusted multi-tenant execution. Keep lab/sensor/analyzer workers away from personal control-plane credentials.
- UI uses English first for international release, translatable strings, UTC plus explicit source timezone, responsive tables and accessible graph alternatives. Product UX omits build-internal technical details unless the user needs them.

## Readiness statuses

`PLAN_ONLY` -> `ENGINE_PROOF` -> `PERSONAL_READY` -> `PUBLIC_BETA` -> `PUBLIC_V1`.
These depend on evidence, not number of files or merged tasks. Multi-user SaaS and native app stores are separate extensions. Release demand can remain `UNVALIDATED` even if personal software is usable.
