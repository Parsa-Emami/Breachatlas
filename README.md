# BreachAtlas

> v7.0 status: **ARCHITECTURE-GO / BOOTSTRAP-GO / SOURCE-NOT-IMPLEMENTED**

This directory is a standalone GitHub repository starting point for BreachAtlas. It contains the frozen architecture/specification, valid HTTP/event/configuration contracts, GitHub governance/security controls, and project-specific source bootstrap commands.

## Runtime boundary
- Laravel 13 control plane/API
- React 19.2 latest patched + TypeScript
- Vite 8.x
- PostgreSQL 18.6 authoritative case/evidence state
- OpenSearch derived search/timeline
- S3-compatible object storage
- rootless Podman analyzers
- Valkey
- OpenTelemetry

## First executable proof
Case → evidence hash/seal → custody event → isolated analyzer → derived artifact → OpenSearch projection → drop/rebuild → sealed export verification.

## Start
```bash
make validate
# verify the GitHub owner/module namespace first
make bootstrap
```

Read `ROADMAP_V7.md`, `PROJECT_START_CHECKLIST_V7.md`, `ACCEPTANCE_GATES_V7.md`, and `GITHUB_REPOSITORY_SETUP_V7.md` before the first code commit.

## Evidence rule
Architecture readiness is not production readiness. “S-tier”, “secure”, “resilient”, or performance claims require executable test/observability/failure/recovery/benchmark/release evidence.

## v7 portfolio position
Recommended implementation order: **10 / 10**. Evidence handling and chain-of-custody claims demand the most discipline. Build last, after hashing, isolation, projection and audit primitives are proven elsewhere.
