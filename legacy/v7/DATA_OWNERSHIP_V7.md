# BreachAtlas — Data Ownership v7

- **PostgreSQL:** case/evidence metadata/custody/holds/analyst state
- **ObjectStore:** immutable source and derived bytes
- **OpenSearch:** rebuildable timeline/search projection
- **Valkey:** jobs/cache only

## Universal rules
- cache is never authority
- derived projections have checkpoint + rebuild + staleness metric
- secrets/evidence follow project-specific retention and redaction
- deletion does not rewrite immutable audit/custody history
