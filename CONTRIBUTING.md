# Contribution workflow

Read OPEN_SOURCE.md, AGENTS.md and ROADMAP.md. Use npm run setup and npm run plan -- next, then read that complete task card. Implement one real dependency-ready work unit with meaningful positive/negative tests. Preserve Apache-2.0, upstream attribution and DCO.md; no secrets/private data or license-unknown fixtures.

Run actual relevant engine checks and npm run check; browser changes also run test:browser and clone changes run test:clone. Record source/fixture identities, command exits and observed results, then update progress truthfully. Use focused Conventional Commits/PRs describing the concrete behavior, validation and remaining blockers. Do not disable checks, fake providers or change protected DB schema/migration/.env/Dockerfile files. Security reporting follows SECURITY.md.
