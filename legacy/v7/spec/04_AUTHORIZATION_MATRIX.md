# BreachAtlas — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Roles
`viewer`, `analyst`, `evidence_custodian`, `case_lead`, `system_admin`

## Policy model
RBAC establishes coarse capability; resource policy enforces workspace/project/vault/case ownership and object state; high-risk operations add step-up/approval where declared by project rules. `system_operator`-like operational identities cannot automatically read protected business/secret/evidence content.

## Mandatory tests
- deny unauthenticated access except documented public health endpoints
- deny cross-scope IDOR for every resource endpoint
- deny privilege escalation by mass assignment
- re-evaluate authorization after role/grant/session revocation
- test list/search/export as well as direct GET
- audit privileged mutations with actor, target, reason/correlation

## Default
No controller may infer authorization from UI visibility. Policies default deny when subject/resource/action is incomplete.
