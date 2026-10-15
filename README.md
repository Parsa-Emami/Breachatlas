# BreachAtlas

**Web application foundation · v0.0.1 · domain integration pending**

A browser workspace for case evidence, chain of custody and source-backed timelines.

```sh
npm ci --ignore-scripts
npm run check
npm run dev
```

Open http://127.0.0.1:5173. Node 24.19.0 is pinned in `.nvmrc`. Build production assets with `npm run build`; start the constrained local server with `npm start`. The responsive workspace can preview JSON locally and browse this project's forty-step product roadmap. It does not run the security engine or persist imported files.

Read [START_HERE.md](START_HERE.md), [web runbook](docs/engineering/WEB_RUNBOOK.md), [web roadmap](plans/WEB_ROADMAP.md), [product roadmap](plans/COMMIT_ROADMAP.md) and [web ADR](docs/architecture/ADR-0002-web-application.md). Product assessment: [فارسی](product/PRODUCT_REVIEW_FA.md). Original requirements and historical input remain available; v7 bootstrap is superseded.

The web workflow installs locked dependencies, builds, runs Node/browser tests and produces a web artifact. Checksums, source identity and dirty-tree status accompany packaging. Nginx/systemd templates are operator configuration, not a deployed service. `/readyz` is web-only and `/api/*` stays unavailable until real engine integration. The domain engine and production identity/persistence integration remain in the product plan.

No database schema, migration, existing `.env` configuration or Dockerfile change is included.
