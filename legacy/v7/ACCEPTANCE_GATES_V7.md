# BreachAtlas — Acceptance Gates v7

Every phase must satisfy all global gates plus its phase-specific Definition of Done in `ROADMAP_V7.md`.

## Global phase gates
- Build/lint/type-check succeeds from a clean checkout.
- Unit and integration tests for the phase pass.
- Contract validation passes.
- At least one negative/abuse/failure test exists for each security-critical boundary added in the phase.
- Telemetry has bounded cardinality and redaction checks.
- Migrations are reversible or have an explicit forward-only recovery procedure and backup requirement.
- Background jobs are retry/idempotency tested.
- No new critical/high dependency vulnerability is knowingly introduced without a documented exception.
- Documentation contains no capability claim ahead of implementation evidence.

## Release gate
- Fresh clone install is automated and tested on supported environment.
- SBOM and provenance are generated for release artifacts.
- Release checksum/signature verification instructions are tested.
- Threat model and abuse cases reflect the shipped code.
- Backup/restore or rebuild drill required by the architecture passes.
- Performance claims include benchmark workload/environment/results.
- Security disclosure policy and support scope are accurate.
