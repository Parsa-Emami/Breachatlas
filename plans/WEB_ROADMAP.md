# BreachAtlas: web application delivery roadmap

Date: 2026-10-15. Original 40 product intents are in COMMIT_ROADMAP.md. This web track does not certify those product intents.

| ID | Delivery | Status | Acceptance |
|---|---|---|---|
| W01 | Browser workspace and project roadmap | verified locally | Responsive workspace, local JSON preview, accessible navigation and filterable forty-task roadmap work. |
| W02 | Validated runtime and constrained web server | verified locally | Configuration fails closed; no engine admission, same-origin paths, health scopes, no-store configuration and path containment are tested. |
| W03 | Automated build and verification pipeline | verified locally | Pinned Actions build the application, run web tests and publish a web-only CI artifact. Remote run result is recorded separately. |
| W04 | Web release packaging and operator configuration | verified locally | Package contains runnable web server, assets, checksums and provenance; TLS proxy and hardened systemd templates are supplied, not deployed. |
| W05 | Reconcile web delivery with product plans | verified locally | All supplied forty product intents and requirements remain traceable. Existing code and protected configuration are preserved. |
| W06 | BreachAtlas engine integration | planned | Implement the first domain slice from IMPLEMENTATION_BLUEPRINT.md through the browser; return real typed results and failures. |
| W07 | Private identity and permission boundaries | planned | Establish project-scoped identity, object authorization, CSRF for cookie mutations, bounded work and redacted audit before enabling a private engine API. |
| W08 | Observed host deployment and recovery | planned | Provision an owned domain/TLS and approved private admission, install artifact, observe health, validate persistence/provider recovery and retain measured evidence. |

Engine profile: private-web. Engine stack retained: Go private service/CLI, SQLite case and custody metadata, Content-addressed local evidence files, React timeline UI.

W06 requires the exact first vertical slice in docs/architecture/IMPLEMENTATION_BLUEPRINT.md. W07/W08 are blockers for sensitive production use; a shell health response is not engine readiness.

No database schema, migration, environment configuration or Dockerfile change is part of this delivery.
