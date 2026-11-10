# BreachAtlas: Engine Tests & Clean-Checkout CI Verification

Updated for task **C06**: `ci(engine): verify the actual engine from a clean checkout`.

## Overview

BreachAtlas enforces real Go engine compilation, execution, and test collection on clean checkouts without shell-only substitutions or silent skips. Both local developer workflows and GitHub Actions (`.github/workflows/runtime.yml`) verify the selected Go engine, typed domain contracts, and local storage recovery guarantees.

## Pinned Toolchain

Per `docs/engineering/toolchain-lock.json` and `go.mod`:
- **Go**: `1.24.0` minimum (`go.mod` pinned; tested on `1.24.0` and `1.26.2`)
- **Node.js**: `24.19.0` (`.nvmrc`)
- **Providers**: None (local-first architecture per `ADR-0003`; standard library cryptography `crypto/ed25519`, `crypto/sha256`).

## Collected Test Directories & Packages

All engine and domain tests live in the following Go packages:

| Package | Directory | Coverage Scope |
|---|---|---|
| `github.com/Parsa-Emami/Breachatlas/cmd/breachatlas` | `./cmd/breachatlas` | HTTP loopback transport, `/healthz`, `/version`, `/readyz`, `/api/v1/health`, `/api/v1/evidence-manifests/validate`, Host header guards, deadline & shutdown handling |
| `github.com/Parsa-Emami/Breachatlas/tests` | `./tests` | Storage port (`C05` single-writer flock, atomic manifest commits, idempotency, interrupted/disk-full recovery, auth precedence, path containment) and C06 clean-checkout/integrity/signer/revision verification |

Additionally, cross-boundary contract and clone-to-run tests exercise the compiled binary through the local supervisor:

| Suite | Command | Coverage Scope |
|---|---|---|
| Web & Contract Tests | `npm test` (`tests/web/*.test.mjs`, `tests/contracts/*.test.mjs`) | Supervisor startup/shutdown, HTTP isolation, manifest validation over loopback against real `dist/bin/breachatlas` |
| Clean Checkout Clone Smoke | `npm run test:clone` (`scripts/clone-smoke.mjs`) | Real `git clone` into an isolated directory, `npm run setup`, and web/engine readiness probes |

## Local Verification Commands

Run the full engine verification suite from a clean or active checkout:

```bash
# 1. Build the actual Go engine binary and confirm version output
go build -o dist/bin/breachatlas ./cmd/breachatlas
dist/bin/breachatlas --version

# 2. Static analysis
go vet ./...

# 3. Run all Go engine & storage tests with race detection (no test cache)
go test -v -race -count=1 ./...

# 4. Run Node contract and web tests (also accessible via npm run check)
npm run check

# 5. Run clean checkout clone-to-run verification
npm run test:clone
```

Convenience npm script for the engine test suite:

```bash
npm run test:engine
```

## Fail-Closed CI Collection Policy

In `.github/workflows/runtime.yml`, CI runs `go test -v -race -count=1 -json ./...` and inspects the JSON test stream:
1. Any failing or skipped test (`"Action":"fail"` or `"Action":"skip"` on a named test) fails the job immediately.
2. Each required test package (`cmd/breachatlas` and `tests`) must record at least one passing package event and at least one executed subtest/test function.
3. Missing test directories, empty test files, or `[no test files]` on a required suite fail CI rather than producing a false green build.
