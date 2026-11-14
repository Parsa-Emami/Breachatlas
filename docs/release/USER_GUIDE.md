# BreachAtlas User Guide

BreachAtlas is an open-source, local-first digital forensics and incident response (DFIR) workspace licensed under [Apache-2.0](../../LICENSE). All core capabilities run locally on loopback (`127.0.0.1`) with no mandatory cloud account, owned public domain, or paid entitlement.

## 1. Installation & Source Builds

### Prerequisites
- **OS (Observed Supported Platform):** `Linux x86_64`
- **Toolchain:** Git, Node.js `24.19+` (within Node 24, `npm` included), Go `1.24+` (verified on `1.26.2`)

### Clone, Build, and Run
```sh
git clone https://github.com/Parsa-Emami/Breachatlas.git
cd Breachatlas
npm run setup
npm start
```

`npm run setup` installs locked web dependencies with lifecycle scripts disabled, builds the web UI (`dist/web/`), and compiles both Go binaries:
- `dist/bin/breachatlas` — local loopback DFIR engine (`127.0.0.1:8080`)
- `dist/bin/verify` — standalone offline bundle verifier (requires no running server)

To build reproducible release artifacts (binaries, web assets, reproducible source tarball, `BUILD_RECIPE.json`, SPDX-2.3 SBOM, `THIRD_PARTY_NOTICES.md`, `SHA256SUMS.txt`, and Ed25519 provenance):
```sh
bash scripts/package.sh
```

## 2. Executing the 8-Step Reference Workflow

Open `http://127.0.0.1:4173/#workflow` (or navigate with `Tab` / `Enter` using keyboard-only controls and accessible table equivalents `Sealed Evidence Table` and `Workflow Timeline Table`):

1. **Upload & Seal (`1-2. Upload & Seal`)**: Streams evidence into isolated quarantine, computes SHA-256, records initial custody, and seals `0440` content-addressed bytes. Sealed source bytes are immutable.
2. **Chain of Custody (`3. Add Custody`)**: Appends attributable custody events (`actor`, `timestamp`, `reason`) linked by cryptographic hashes.
3. **Bounded Timeline (`4. Parse Bounded Timeline`)**: Parses JSON/CSV evidence in an isolated sandbox, preserving raw timestamps, timezone offsets, and confidence without fabricating UTC.
4. **Legal Hold (`5a. Place Legal Hold`, `5b`, `5c`)**: Places active holds that block concurrent deletion or retention expiration (`hold_active`, keeping sealed evidence intact).
5. **Signed Portable Export (`6. Export Signed Bundle`)**: Packages sealed evidence, custody, checkpoints, artifacts, and timeline into an Ed25519-signed bundle.
6. **Offline Verification (`7a. Verify Authentic Bundle`, `7b`)**: Verifies file checksums, custody roots, and signatures offline (`dist/bin/verify`). One modified byte, missing evidence, or an untrusted signer is rejected.
7. **Recovery & Restore (`8a. Recover Consistency`, `8b. Restore Bundle`)**: Rebuilds derived timeline indexes or restores from a verified bundle without modifying sealed source bytes or rewriting custody history.

## 3. Data, Limits, Privacy & Recovery

- **Published Limits:**
  - Workflow API request body bound: `256 KiB`
  - Streaming evidence upload bound: `4 GiB`
  - Diagnostic log ring buffer: `1000` entries (secrets redacted)
  - Hardware target: `2 vCPU / 4096 MiB RAM / 20480 MiB` free disk
- **Privacy:** Local-first by design. No telemetry, analytics, or external network calls are made by the core engine or web UI.
- **Recovery:** Derived timeline indexes can be rebuilt deterministically from sealed evidence and signed artifacts (`8a. Recover Consistency`), and cases can be restored from signed portable bundles (`8b. Restore Bundle`).

## 4. Licenses & Support

- **License:** [Apache-2.0](../../LICENSE); upstream dependency inventory and notices are in [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md).
- **Support & Issue Reporting:** Open reproducible bug reports (without real incident data or secrets) in the GitHub repository issue tracker.
- **Security Vulnerabilities:** Follow the private reporting route in [SECURITY.md](../../SECURITY.md).
