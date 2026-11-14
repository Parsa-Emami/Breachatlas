# BreachAtlas — Maintenance and Dependency Policy

## 1. Supported Branches and Release Tracks

- **`main` / `0.1.x` (`Linux x86_64`):** Active open-source maintenance branch with pinned Go (`1.26.2`) and Node.js (`24.19.0`) toolchains.
- **Reproducible Source Builds:** Every release includes `source/breachatlas-source.tar.gz`, `source/BUILD_RECIPE.json`, `sbom.spdx.json` (`SPDX-2.3`), and `SHA256SUMS.txt`.

## 2. Security Vulnerability Handling

- Vulnerability reporting, supported versions, and private disclosure follow [SECURITY.md](../../SECURITY.md).
- Maintainers target an initial acknowledgement within **3 business days** for private reports.

## 3. Dependency and License Policy

- **Permissive License Allowlist:** All shipped source and runtime dependencies must carry an approved permissive license (`Apache-2.0`, `MIT`, `BSD-3-Clause`, `BSD-2-Clause`, `ISC`, `MPL-2.0`, `Artistic-2.0`), enforced automatically by `SPDX-2.3` SBOM validation in `scripts/package-source.mjs` and `internal/release/package.go`.
- **Pinned Toolchains & Lockfiles:** `docs/engineering/toolchain-lock.json`, `package-lock.json`, and `go.mod` pin exact versions and digests; floating tags or unverified external downloads are rejected.
- **Upgrade & Rollback Safety:** Dependency updates and release promotions must pass `go test -race ./...`, `npm run check`, `npm run test:browser`, and `npm run test:clone` without weakening sealed-byte immutability or anti-rollback authority checks.
