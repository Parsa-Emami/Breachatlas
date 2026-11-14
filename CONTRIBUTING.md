# Contributing to BreachAtlas

Thank you for contributing to BreachAtlas!

## Getting Started

1. Read [OPEN_SOURCE.md](OPEN_SOURCE.md), [AGENTS.md](AGENTS.md), and [ROADMAP.md](ROADMAP.md).
2. Run setup and inspect the next planned work unit:
   ```sh
   npm run setup
   npm run plan -- next
   ```
3. Read the returned `plans/commits/Cxx.md` card in full and implement one dependency-ready work unit with meaningful positive and negative tests.
4. Preserve [Apache-2.0](LICENSE), upstream attribution ([THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)), and [DCO.md](DCO.md). Never commit secrets, private incident data, or license-unknown fixtures.

## Verification Before Opening a PR

Run the relevant checks locally:
```sh
npm run validate:plan
go vet ./... && go test -race -count=1 ./...
npm run check
npm run test:browser
python3 scripts/validate_repo.py
```

For clone/setup changes, also run `npm run test:clone`. Record exact source/fixture identities, command exits, and observed results in `docs/evidence/Cxx.json` and update `plans/progress.json` truthfully.

## Boundaries & Security

- Do not disable checks, fake providers, or modify protected database schemas, migrations, `.env` files, or Dockerfiles.
- Use focused Conventional Commits describing the concrete behavior and validation.
- Report security vulnerabilities privately via [SECURITY.md](SECURITY.md).
