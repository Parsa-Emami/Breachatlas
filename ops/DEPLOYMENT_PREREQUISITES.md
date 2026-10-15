# BreachAtlas operational prerequisites

Selected mode: embedded-private. No deployment has been performed.

- private host هدف 2 vCPU / 2–4 GiB RAM و حداقل 20 GiB SSD به‌علاوهٔ ظرفیت evidence و backup.
- Runtime dependencies: Go private service/CLI, SQLite case and custody metadata, Content-addressed local evidence files, React timeline UI. Exact supported pins are resolved at C02; no version assumptions from v7.
- DNS/subdomain and HTTPS for a web app. Private access for stateful modes. Static mode needs no server project-data DB.
- Persistent local volumes for embedded stores; independent consistent backup and sufficient disk for raw data, derived files and temporary staging.
- No exposed DB/engine socket. Runtime secret references via platform injection, never committed env values. Identity provider trust and TLS expiry monitored where used.
- Static demo data only in public profile. Private sensors/labs/provider/evidence workers remain separate from public demo.
- Document export/restore and data portability; run UAT on target host before real sensitive data.

Capacity settings are in product/project.json. If target fails benchmark, reduce supported input limits and update docs. Ephemeral/serverless deployments of stateful profiles require separate persistent storage architecture and are not the default.

Costs: estimate domain + compute-hours + persistent GiB + backup GiB + egress + provider/support cost from chosen vendor at deployment time. No current hosting quote or paid plan is assumed. Online third-party management reduces administration, not necessarily cost or storage use.
