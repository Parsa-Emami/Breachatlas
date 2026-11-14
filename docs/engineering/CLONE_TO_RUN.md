# BreachAtlas: clone to run

## Runnable today

Install Git, Node 24.19+ within Node 24 (npm bundled), and Go 1.24+.

```sh
git clone https://github.com/Parsa-Emami/Breachatlas.git
cd Breachatlas
npm run setup
npm start
```

Open http://127.0.0.1:4173. No owned public domain, external DNS, TLS certificate, or cloud account is required for local operation. `npm run setup` installs the committed web lockfile with lifecycle scripts disabled, builds the workspace, and compiles `dist/bin/breachatlas` and `dist/bin/verify`. `npm start` supervises the Go loopback engine (`127.0.0.1:8080`) and same-origin web relay (`127.0.0.1:4173`), enforcing `Host`, `Origin`, `Sec-Fetch-Site`, forged-header, and `Cache-Control` boundaries.

`npm run setup -- --check` shows preparation without changes. `--skip-install` builds using already installed dependencies. `npm run doctor` reports actual web/core state. `npm run release:check` exits 2 until all C01-C38 evidence is ready. Ctrl+C stops both supervised processes. Ports can be selected with `npm start -- --port 4301` when running multiple projects.

## Local-first guarantees and optional private hosting

- **Zero public domain required:** Local operation runs end-to-end on loopback (`127.0.0.1` / `localhost` / `[::1]`).
- **Default unexposed engine work:** Standalone web serving (`scripts/serve-web.mjs`) keeps `engineEnabled: false` and fails closed (`503`) on `/api/*`. Supervised local runs validate storage and provider prerequisites before reporting `/readyz` ready.
- **Optional private TLS ingress:** Operators with an owned domain and TLS certificate can configure `ops/web/nginx.conf.template` (deny-all default + `Host $proxy_host` -> `127.0.0.1:4310`) and `ops/web/service.systemd`. See [infra/deployment.md](../../infra/deployment.md) and [docs/engineering/WEB_RUNBOOK.md](WEB_RUNBOOK.md).
- **Complete reproducible packaging:** Run `bash scripts/package.sh` to build and verify `dist/release/` (binaries, web UI, reproducible source archive, SPDX SBOM, notices, and checksums).
- **User guide, security & licensing:** See [User Guide](../release/USER_GUIDE.md), [SECURITY.md](../../SECURITY.md), and [OPEN_SOURCE.md](../../OPEN_SOURCE.md) for data limits, local-first privacy, recovery, support, and private vulnerability reporting.

Local resources: none beyond the selected runtime. Hardware target: 2 vCPU / 4096 MiB RAM / 20480 MiB free disk plus real dataset/provider/backup space (measured bounds recorded in `docs/evidence/performance.json`). Full engine support initially targets Linux x86_64.

## Checks

```sh
npm run check
go test ./...
npx --no-install playwright install chromium
npm run test:browser
npm run test:clone
npm run doctor
```

`npm run test:clone` performs a real local Git clone of the staged/committed source, runs `npm run setup`, verifies standalone web readiness separately from engine readiness, checks missing-storage `503` fail-closed behavior, and executes the full 8-step reference workflow, offline `dist/bin/verify`, restart persistence, and bundle restore via Playwright Chromium.
