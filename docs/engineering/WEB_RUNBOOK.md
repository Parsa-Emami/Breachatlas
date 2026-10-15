# BreachAtlas web runbook

## Local checkout

Use Node 24.19.0 and npm 11.9.0 from the tested toolchain. From the repository root:

```sh
npm ci --ignore-scripts
npm run check
npx --no-install playwright install chromium
npm run test:browser
npm run dev
```

Browser checks may use an operator-provided Chromium executable through the `WEB_TEST_CHROMIUM` process variable. CI uses the Playwright-managed browser. This test override never changes application configuration.

Development URL: http://127.0.0.1:5173. To run the built shell separately:

```sh
npm run build
npm start -- --port 4310
```

Built URL: http://127.0.0.1:4310. Browser routing uses hashes and hosting at the origin root. There is no subpath deployment in this release. Change the public nonsecret configuration in `ops/web/runtime-config.json`; `apps/web/public/runtime-config.json` must mirror it for static hosts/development. The Node server validates its config at startup and the browser validates its own project identity. Do not put credentials in either file.

## What is runnable

The responsive React workspace, forty-step product roadmap, local bounded JSON structure preview, Node static server and its health endpoints are implemented. Preview uses tab memory, does not persist files and does not send them to the server. Reload clears the preview. This is not a domain import or a security assessment. The PWA manifest supplies install metadata; there is no service worker or offline claim. Cache rules retain only fingerprinted static assets; HTML and runtime configuration are no-store.

`GET /healthz` covers the web process; `GET /readyz` covers web assets and valid startup configuration. Neither proves engine/provider/database health. `/api` and all `/api/` routes return 503 while the engine is unavailable. No upload endpoint or authentication service is created. Engine admission cannot be enabled by a public config flag.

## Build an artifact

```sh
npm run package:web
cd dist/release
sha256sum -c SHA256SUMS.txt
node scripts/serve-web.mjs --root web --port 4310 --config ops/web/runtime-config.json
```

Package after build. `release.json` records the source commit and whether the working tree was dirty; build from a clean commit for a releasable provenance record. Node production serving needs no installed npm dependencies. CI uploads the web package; it does not publish a host or modify repository settings. Copy the complete `dist/release` tree to the chosen immutable release directory.

## Private Linux host

Prerequisites: operator-owned domain/DNS, valid TLS certificate/key, installed Node 24.19.0, Nginx, systemd, and an unprivileged `breachatlas-web` account. Reserve port 4310 for this project. Keep certificates outside the artifact and never commit a private key. Install releases under `/srv/breachatlas/releases/<source-commit>` and point `/srv/breachatlas/current` to the selected verified release. Ensure the service user has read/execute access to artifact directories. Match the actual Node binary path in the service file.

Use `ops/web/service.systemd` and render `ops/web/nginx.conf.template` with the real owned domain, TLS paths and reviewed operator network ranges. The proxy initially denies external traffic. Keep the deny-all default until private admission is configured and tested; do not treat an IP range as per-user authentication. Runtime APIs remain blocked until W06/W07. Validate the rendered Nginx configuration with `nginx -t` before reload. Install the service under `/etc/systemd/system/breachatlas-web.service`, then run:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now breachatlas-web
curl --fail http://127.0.0.1:4310/healthz
curl --fail http://127.0.0.1:4310/readyz
sudo journalctl -u breachatlas-web --since '10 minutes ago'
```

Test HTTPS access from an allowed operator and rejection from a disallowed network. Test that `/api/v1/not-implemented` stays unavailable. No domain, certificate, host or credentials were provisioned by the source commit.

## Update and rollback

Build/test/package from a clean source commit; verify SHA256SUMS before switching the current symlink. Retain the previous artifact; switch the symlink and restart the service in a maintenance window. Check both web probes and browser navigation. If either fails, restore the previous symlink and restart. The shell has no durable user data, so it has no data restore operation. Once domain storage/providers are integrated, add backup/restore and schema-compatibility evidence before updates; a frontend rollback does not roll back engine data.

## Engine integration and operations still required

Profile: `private-web`. Retained engine choices: Go private service/CLI, SQLite case and custody metadata, Content-addressed local evidence files, React timeline UI. Implement the first vertical slice in IMPLEMENTATION_BLUEPRINT.md and W06, then authenticated negative tests in W07. Route only explicitly supported endpoints through a same-origin authenticated service. Keep secrets exclusively on the server/provider. Add real engine readiness, bounded jobs, cancellation, redacted audit, operational metrics, alerts and retention/restore proof alongside the domain implementation. Public marketing/static demonstrations must use synthetic data; they cannot admit arbitrary runtime work.

For KeyHelix, no plaintext secrets may enter browser file preview; import only synthetic nonsecret metadata. For RiftRange/MirageMesh, orchestration/sensors stay on isolated private hosts. Existing RiskWeft Laravel source is preserved and has not been connected to this shell or certified by web tests.

## Reproduce source evidence

Run `python3 scripts/source_identity.py --check` against the committed checkout. The digest covers tracked and deliverable untracked files, excluding only the self-referential evidence JSON and SHA256SUMS.txt. Build/test output directories are ignored. Verification evidence records web-only checks and the exact tested runtime; it does not certify the domain engine.
