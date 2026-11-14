#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[1/5] Validating roadmap and resource locks..."
node scripts/roadmap.mjs validate
node scripts/verify-resources.mjs

echo "[2/5] Building Go engine and standalone offline verifier..."
mkdir -p dist/bin
go build -trimpath -buildvcs=false -o dist/bin/breachatlas ./cmd/breachatlas
go build -trimpath -buildvcs=false -o dist/bin/verify ./cmd/verify
./dist/bin/breachatlas --version
./dist/bin/verify --version

echo "[3/5] Building web workspace assets..."
npm run build

echo "[4/5] Packaging complete open-source release into dist/release..."
node scripts/package-web.mjs

echo "[5/5] Verifying packaged checksums, SBOM, source archive, and binaries..."
(
  cd dist/release
  sha256sum -c SHA256SUMS.txt >/dev/null
  ./bin/breachatlas --version >/dev/null
  ./bin/verify --version >/dev/null
)

node -e '
const fs = require("node:fs");
const rel = JSON.parse(fs.readFileSync("dist/release/release.json", "utf8"));
if (rel.scope !== "complete-open-source" || rel.engineReady !== true || rel.offlineVerifierReady !== true) {
  throw new Error("Release verification failed: web-only or incomplete release artifact.");
}
const sbom = JSON.parse(fs.readFileSync("dist/release/sbom.spdx.json", "utf8"));
if (sbom.spdxVersion !== "SPDX-2.3" || !Array.isArray(sbom.packages) || sbom.packages.length < 10) {
  throw new Error("SPDX SBOM verification failed.");
}
console.log("Verified complete release package:", {
  scope: rel.scope,
  engineReady: rel.engineReady,
  offlineVerifierReady: rel.offlineVerifierReady,
  sbomPackages: sbom.packages.length,
  sourceCommit: rel.sourceCommit,
  dirty: rel.dirty
});
'
