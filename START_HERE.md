# Continue BreachAtlas

Read AGENTS.md, product/project.json, plans/progress.json, plans/web-roadmap.json and ADR-0002-web-application.md before work. Inspect real source and current Git status. This is now a browser app foundation; the original 40 domain intents are not all implemented.

```sh
npm ci --ignore-scripts
npm run check
npx --no-install playwright install chromium
npm run test:browser
npm run dev
```

See WEB_RUNBOOK.md for build, package, TLS host configuration, upgrade and rollback. W01-W05 evidence is recorded separately; C03 remains partial. Complete project-specific engine acceptance before verifying a C milestone. Read docs/engineering/CONTINUATION.md for truthful evidence rules. Do not execute historical v7 bootstrap. Preserve existing source, environment and database files.
