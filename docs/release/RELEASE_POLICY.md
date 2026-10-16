> Current OSS delivery/resources/storage/release policy is ADR-0003-open-source-local-first.md and DEFINITION_OF_DONE.md. The older planning context below is superseded where it conflicts; business invariants remain applicable.

# Delivery, domain and release policy — v0

## Distribution choice

Primary app means web app/PWA on a domain, with native CLI where appropriate. PWA installability varies by browser/platform; do not promise app-store availability. A later mobile-store release needs a platform ADR, signing, privacy declarations, review and testing; browser app can be used meanwhile. No domain, hosting account, app store or repository was created by this planning package.

## Personal host first

Use one subdomain per app, for example `<project>.example.com` (placeholder owned domain). Static apps can run on static hosting. Private services need a host with persistent local volume, HTTPS ingress and an existing identity/access provider or VPN. Do not deploy stateful SQLite/DuckDB apps to an ephemeral filesystem and assume data survives. Do not expose admin ports, engine sockets, DB files or object paths publicly. Bind backend to loopback/private interface; ingress is the sole intended network path. Identity proxy does not replace application object authorization.

Deploy one app at a time. Sharing a VPS is an option for low-risk private apps with separate users, volumes, cookies and secrets. Do not co-host honeypots, untrusted runners or lab workloads with vault/provider or sensitive evidence. Origin separation also reduces browser access between apps. Use host-only cookies, no broad parent-domain auth cookie, and independent trust material for high-risk projects.

## Public demonstration versus live service

- Synthetic bundled demo data only. Source/architecture/traffic/evidence/secret uploads are opt-in private operations; static viewers read locally.
- Disable hosted scans, lab creation, decoy control, secret reveal and arbitrary analyzer execution in public demo unless their own reviewed release profile explicitly permits them.
- For APIs: authenticated object-scoped authorization, CSRF where cookie-auth applies, rate/body/time limits, safe error messages and no secret logging. TLS, CSP and content escaping tested. Diagnostics have no sensitive payloads.
- App shell caching is allowed; secret/custody/sensitive server API responses use no-store and must never be included in a service-worker cache. Document behavior for logout, browser data clearing and origin changes.

## Lifecycle

| Stage | Required observed outcome |
|---|---|
| Engine proof | deterministic project UAT, typed contracts and negative cases |
| Personal ready | real install on chosen host/browser, supported recovery, workload bounds, sensitive data checks |
| Public beta | demo isolation, authentic artifact checks, privacy/support pages, external testing or explicit unvalidated-demand label |
| Public v1 | all mandatory gates passed, truthful limits, release install/upgrade and incident response ownership |
| Hosted multi-user | separate ADR plus tenants/object auth, quota abuse, billing/account lifecycle, concurrency and independent review |

## Backup, upgrade and rollback

Metadata backups use supported engine snapshot/backup mechanism, not a bare copy of live SQLite ignoring WAL. Evidence/data partitions are immutable and captured with a consistent manifest generation. OpenBao provider recovery material has separate custody. Restore in a separate environment and run project UAT. Plan target for private stateful apps: RPO <=24h and RTO <=4h; measure actual result before offering it. Browser apps depend on exported portable files; no export means no promised recovery.

Use versioned exported documents with pure migration fixtures. Stateful apps use expand/verify/switch and keep previous reader compatibility during documented rollback window. Single-host releases can use brief maintenance mode; do not claim HA. Restore of stale backup after new writes is not a safe ordinary rollback. Forward repair is preferred where format has moved; destructive changes require separate reviewed decision and fresh tested backup.

## Service ownership and sustainability

Before live public service record owner-supplied support channel, vulnerability disclosure route, hosting region, operational hours, retention/deletion/export rules and uptime expectations. Privacy and legal conclusions require jurisdiction/customer-specific review; no universal compliance claim. International accessibility also depends on provider availability, payment eligibility and region restrictions, verified before choosing a paid host.

Collect opt-in aggregated use feedback only. Default no raw payload telemetry, source code or architecture uploads. Do not add payments, permanent accounts, marketing email or analytics trackers to every MVP. Community CLI/static app first; hosted convenience/support later if pilots justify cost.

Operational signals: request error/latency where relevant, job age, cancellation, memory and disk pressure, backup age, trust/certificate expiry, provider health. Retention and alert budgets prevent unlimited disk growth. Operator must have a documented pause, incident, credential revoke, restore and forward-repair path.
