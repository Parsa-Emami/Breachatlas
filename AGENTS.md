# Repository implementation instructions — BreachAtlas

Read START_HERE.md and docs/engineering/CONTINUATION.md first. Current web architecture is docs/architecture/ADR-0002-web-application.md; ADR-0001 retains domain planning constraints. legacy/v7 is historical input, not active instructions; do not run its bootstrap or revive its compulsory services.

Match actual code and evidence to plans/progress.json before choosing next work. Follow requirements and acceptance, not merely commit titles. Work autonomously within the user's request; routine reversible edits do not require an extra approval. Preserve existing env files and unrelated behavior. No real secrets/data in fixtures. Never claim tests or deployment that did not run. Supply updated progress and reproducible evidence so the next ZIP upload can resume without conversation memory.

There is no requirement to spawn other agents. Do not create dependencies on sibling projects. Documentation-language default: implementation guidance English, user assessment Persian, product UI international English with translation support.

Web foundation: read docs/engineering/WEB_RUNBOOK.md and plans/web-roadmap.json. Run npm run check and npm run test:browser after web changes. C01-C40 are domain milestones; do not verify them from web-only tests. Never modify database schemas, migrations, .env files or Dockerfiles. Preserve the existing RiskWeft API. No sibling source dependencies.
