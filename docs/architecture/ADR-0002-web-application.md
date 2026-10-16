# ADR-0002 — BreachAtlas browser application foundation

Accepted 2026-10-15 under the owner's instruction that all ten projects are web applications. This decision supersedes CLI-only product delivery and any v0 claim that this repository contains no application source. ADR-0001 retains domain invariants and proposed engine/storage choices. The original v7 documents remain historical specifications; their bootstrap commands do not describe this web app.

React/TypeScript/Vite provides the browser entry point at `apps/web/src/main.tsx`. Root package.json/package-lock.json own web dependencies and use `apps/web/vite.config.ts`; no sibling repository or shared unpublished package is required. Node serves built static assets, validates configuration, restricts filesystem paths and supplies web-only health. It does not implement or proxy a domain service. This avoids making fake successful domain endpoints before real engine integration.

The selected delivery profile is `private-web`; optional CLI/sensor/scanner tools remain engine adapters. Attestara and CipherLint therefore have first-class browser workspaces rather than CLI-only distribution. Browser install metadata is supplied without sensitive offline caching. No application payload is stored by the shell.

RiskWeft already contains Laravel source in apps/control-plane at the reviewed Git baseline. That source takes precedence over ZIP assertions of zero source; it is retained byte-for-byte. Browser-local operation in ADR-0001 is a future product choice, not an instruction to delete the existing API. W06 must explicitly choose and test the retained API adapter or implement a browser domain adapter without silently discarding the existing API.

Domain C01-C40 evidence remains distinct from W01-W08 web work. C03 is partial while required engine/source acceptance remains unmet. No product readiness, security certification, host deployment or market-validation claim follows from a passing web build. No database schema, migration, existing environment file or Dockerfile is changed.

Independent hosting is documented with TLS proxy, unique project port 4310, a restricted systemd unit, artifact integrity and rollback. Configuration has a small nonsecret allowlist. Sensitive engine operations remain disabled until real identity/authorization, resource bounds and recovery tests pass. Shared multi-user SaaS, billing, production OIDC and engine-specific deployment are future domain work rather than enabled stubs.
