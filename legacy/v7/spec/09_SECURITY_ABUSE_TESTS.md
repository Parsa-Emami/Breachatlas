# BreachAtlas — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Project-specific abuse/security cases
- evidence path/archive parser attack
- analyzer escape/network access
- cross-case IDOR
- custody forgery
- stored-XSS in artifacts
- export tamper
- legal-hold bypass

## Common adversarial suite
Authentication/session abuse; authorization/IDOR; malicious archive/file names; SSRF where URLs exist; injection for SQL/search/graph/template/policy/query languages; stored/reflected XSS for user/tool output; rate/resource exhaustion; stale/replayed signed data; dependency/tool output treated as hostile; sensitive logging; CSRF where cookie auth exists; CORS/CSP/header checks.

All security-sensitive parser/compiler/crypto/policy boundaries receive negative tests. Critical findings block release; accepted residual risks require owner, reason, expiry/review date and documented compensating control.
