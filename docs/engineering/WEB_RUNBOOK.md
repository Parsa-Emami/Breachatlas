# BreachAtlas web and release runbook

## Unified local development and launch

Use Node 24.19+ and Go 1.24+ from the locked toolchain. From the repository root:

```sh
npm run setup
npm start
```

`npm run setup` prepares the environment:
1. Validates Node runtime.
2. Checks Go compiler and compiles `dist/bin/breachatlas` and `dist/bin/verify`.
3. Prepares web workspace data and builds web assets into `dist/web/`.

`npm start` invokes `scripts/start-local.mjs`, which supervises both the Go loopback engine (`127.0.0.1:8080`) and web workspace (`127.0.0.1:4173`). No second terminal is required. Both processes shut down cleanly upon receiving `SIGINT` or `SIGTERM`.

Check health:
```sh
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:4173/readyz
```

Browser checks may use an operator-provided Chromium executable through the `WEB_TEST_CHROMIUM` process variable. CI uses the Playwright-managed browser. This test override never changes application configuration.

Development URL: http://127.0.0.1:5173. To run the built shell separately:

```sh
npm run build
npm start -- --port 4310
```

Built URL: http://127.0.0.1:4310. Browser routing uses hashes and hosting at the origin root. There is no subpath deployment in this release. Change the public nonsecret configuration in `ops/web/runtime-config.json`; `apps/web/public/runtime-config.json` must mirror it for static hosts/development. The Node server validates its config at startup and the browser validates its own project identity. Do not put credentials in either file.

## What is runnable

The responsive React workspace, forty-step product roadmap, local bounded JSON structure preview, authenticated same-origin workflow endpoints (`/api/v1/workflow/*`), Go loopback engine (`bin/breachatlas`), standalone offline bundle verifier (`bin/verify`), and local bounded storage/custody/timeline/export/recovery subsystems are implemented. Preview uses tab memory unless explicitly submitted through the supported local workflow endpoints. `ops/web/runtime-config.json` retains fail-closed public configuration (`engineEnabled: false` for unauthenticated public shells; live supervisor enables loopback engine relay explicitly).

`GET /healthz` covers the web or engine process probe; `GET /readyz` covers web assets, valid startup configuration, and real loopback engine + storage/provider readiness. Unbound engine routes fail closed (`503`). Cache rules retain only fingerprinted static assets; HTML and runtime configuration are `no-store`.

## Build complete reproducible release artifact

Build and package the complete release (`bin/breachatlas`, `bin/verify`, `web/`, `source/breachatlas-source.tar.gz`, `source/BUILD_RECIPE.json`, `sbom.spdx.json`, `THIRD_PARTY_NOTICES.md`, `release.json`, and `SHA256SUMS.txt`):

```sh
bash scripts/package.sh
cd dist/release
sha256sum -c SHA256SUMS.txt
./bin/verify --version
./bin/breachatlas --version
node scripts/start-local.mjs --host 127.0.0.1 --port 4310 --enginePort 8080 --root web --config ops/web/runtime-config.json --engineBin bin/breachatlas --storageDir /tmp/breachatlas-data
```

You may also generate the source archive, build recipe, and SPDX SBOM standalone via:

```sh
node scripts/package-source.mjs --output dist/release
```

See [docs/release/ARTIFACTS.md](../release/ARTIFACTS.md) for the complete `dist/release/` layout, deterministic tar normalization rules, and atomic staging guarantees.

`release.json` records `scope: "complete-open-source"`, `engineReady: true`, `offlineVerifierReady: true`, the source commit, and whether the working tree was dirty; build from a clean commit for a releasable provenance record. Web-only artifacts (`engineReady: false`) are rejected for complete-product distribution. Production serving from `dist/release/` needs no installed npm dependencies. Copy the complete `dist/release` tree atomically to the chosen immutable release directory.

## Offline bundle verification

Exported evidence bundles (`bundle-manifest.json` + sealed blobs + custody checkpoints) can be verified completely offline with zero network or server connectivity using the packaged verifier binary:

```sh
./bin/verify --bundle /path/to/exported-bundle --json
```

Supply `--trusted-key <hex>` and `--require-signature` to require Ed25519 signature verification against a pinned analyst key.

## Private Linux host

Prerequisites: operator-owned domain/DNS, valid TLS certificate/key, installed Node 24.19.0, Nginx, systemd, and an unprivileged `breachatlas-web` account. Reserve ports `4310` (web relay) and `8080` (loopback engine) on `127.0.0.1` for this project. Keep TLS keys outside the artifact and never commit a private key. Install verified releases under `/srv/breachatlas/releases/<source-commit>` and point `/srv/breachatlas/current` to the selected verified release. Ensure `breachatlas-web` has read/execute permissions on release directories and write permission inside `/var/lib/breachatlas/data` (`StateDirectory=breachatlas`). Match the actual Node binary path in `ops/web/service.systemd`.

Use `ops/web/service.systemd` and render `ops/web/nginx.conf.template` with the real owned domain, TLS paths, and reviewed operator network ranges. The proxy passes the trusted local upstream authority in the `Host` header (`$proxy_host`), not an arbitrary external authority. Both `scripts/serve-web.mjs` and `bin/breachatlas` reject untrusted `Host` values, foreign `Origin` headers, `Sec-Fetch-Site: cross-site`, and forged identity headers. Keep both listeners on loopback; never publish `8080` externally or replace `$proxy_host` with `$host`. Keep the proxy `deny all` default until private admission CIDRs are reviewed and tested. Validate rendered Nginx configuration with `nginx -t` before reload. Install the service under `/etc/systemd/system/breachatlas-web.service`, then run:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now breachatlas-web
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:4310/readyz
sudo journalctl -u breachatlas-web --since '10 minutes ago'
```

Test HTTPS access from an allowed operator and verify rejection from disallowed networks.

## Update and rollback

Build/test/package from a clean source commit; verify `SHA256SUMS.txt` and `release.json` before switching `/srv/breachatlas/current`. Retain the previous verified release directory and take an authoritative bundle export backup before upgrading. Switch the symlink and restart `breachatlas-web` in a maintenance window. Verify `http://127.0.0.1:8080/healthz`, `http://127.0.0.1:4310/readyz`, offline `./bin/verify`, and browser workflow navigation.

If post-upgrade checks fail: stop `breachatlas-web`, restore the previous `/srv/breachatlas/current` symlink, verify `/var/lib/breachatlas/data` integrity (or restore from the verified exported bundle when required), and restart the service. Never overwrite newer accepted case/evidence state with an old backup without explicit tested recovery procedures.

## Engine integration and security boundaries

Profile: `open-source local-first`. Retained engine choices: Go private service/CLI (`bin/breachatlas`), standalone verifier (`bin/verify`), SQLite/WAL-compatible atomic JSON/content-addressed local evidence store, custody hash chain + Ed25519 checkpoints, and React timeline/workflow UI. All sensitive operations run strictly on loopback under fail-closed `Host`/`Origin`/header checks. Existing RiskWeft Laravel source is preserved cleanly and has not been modified.

## Reproduce source evidence

Run `python3 scripts/source_identity.py --check` against the committed checkout, or re-create the normalized source archive with `node scripts/package-source.mjs`. The source identity digest covers tracked and deliverable untracked files, excluding only self-referential evidence JSONs and `SHA256SUMS.txt`. Build/test output directories are ignored.
