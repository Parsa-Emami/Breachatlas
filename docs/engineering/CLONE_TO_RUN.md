# BreachAtlas: clone to run

## Runnable today

Install Git and Node 24.19+ within Node 24 (npm bundled), then:

```sh
git clone https://github.com/Parsa-Emami/Breachatlas.git
cd Breachatlas
npm run setup
npm start
```

Open http://127.0.0.1:4173. Setup installs the committed web lockfile with lifecycle scripts disabled, stops on errors and builds the workspace. No Python, Go, Rust, PHP, database, cloud account or domain is needed for the current web shell. It previews JSON structure locally and browses the roadmap; it does not implement the full domain product.

`npm run setup -- --check` shows preparation without changes. `--skip-install` builds using already installed dependencies. `npm run doctor` reports actual web/core state. `npm run release:check` deliberately exits 2 until full evidence is ready. Ctrl+C stops the current web process. Ports can be selected with `npm start -- --port 4301` when running multiple projects.

## Full-product contract to implement

The same clone/setup/start sequence must prepare and supervise the actual Go engine and required self-hosted open-source resources by C30. No second undocumented terminal, paid account, sibling clone or owned public domain. C03 implements local lifecycle/health and C31 supplies verified convenience artifacts plus a documented source-build alternative. Downloads may be needed to prepare resources; user payloads are not sent to a compulsory proprietary service. No global runtime install, system trust change or user data deletion occurs implicitly.

Local resources: none beyond the selected runtime. Hardware target: 2 vCPU / 4096 MiB RAM / 20480 MiB free disk plus real dataset/provider/backup space. These are unmeasured targets until C28. Full engine support initially targets Linux x86_64; other hosts require their own actual C30/C33 evidence. Rootless workloads need Linux or a tested Linux/WSL2 host.

`local-demo` uses synthetic fixtures and isolated development providers; `local-private` requires real identity/permission, provider durability, revocation and restore evidence before sensitive use. A development provider mode never becomes a production vault/gateway by relabeling it.

## Checks

```sh
npm run check
npx --no-install playwright install chromium
npm run test:browser
npm run test:clone
npm run doctor
```

The current test:clone performs a real local Git clone of the staged/committed source, runs setup and verifies web readiness and disabled engine admission. C30 must extend it to the full tests/scenarios/clone-to-value.json workflow and real engine readiness. Current shell checks cannot certify domain functionality. See each C task for future engine commands and prerequisites. Optional hosting/package operations remain in WEB_RUNBOOK.md.
