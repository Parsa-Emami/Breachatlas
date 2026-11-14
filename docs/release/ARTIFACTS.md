# BreachAtlas Release Artifacts Specification

Complete reproducible open-source release packaging for BreachAtlas (`N31` / `C31`).
Web-only packages (`engineReady: false`) are rejected for complete-product releases; a valid release artifact MUST bundle the compiled Go engine, standalone offline verifier, web UI, offline rules/contracts/toolchain manifests, reproducible source archive and build recipes, SPDX SBOM, complete upstream notices, SHA-256 checksums, and build provenance.

## Directory Layout (`dist/release/`)

```text
dist/release/
├── bin/
│   ├── breachatlas                  # Compiled Go loopback engine (go build -trimpath -buildvcs=false)
│   └── verify                       # Standalone zero-network offline bundle verifier
├── web/                             # Built Vite React workspace assets
├── scripts/
│   ├── serve-web.mjs                # Loopback static/API relay server
│   └── start-local.mjs              # Unified Go engine + web relay supervisor
├── apps/web/src/lib/
│   └── runtime-config.mjs           # Fail-closed public runtime configuration validator
├── ops/
│   ├── runtime-requirements.json    # Hardware, capacity, and toolchain bounds
│   ├── deployment-profiles.json     # Supported local/private host profile
│   └── web/
│       ├── brand.json               # Product metadata slug and identity
│       ├── nginx.conf.template      # Deny-all HTTPS reverse proxy template
│       ├── runtime-config.json      # Default fail-closed public configuration
│       └── service.systemd          # Sandboxed systemd supervisor unit
├── docs/
│   ├── engineering/
│   │   ├── toolchain-lock.json      # Pinned upstream runtimes and stdlib inventory
│   │   └── WEB_RUNBOOK.md           # Build, verification, host, and rollback runbook
│   └── release/
│       └── ARTIFACTS.md             # This specification
├── contracts/                       # OpenAPI 3.2.0, AsyncAPI 3.1.0, config/event/analyzer schemas
├── source/
│   ├── breachatlas-source.tar.gz    # Reproducible normalized tar+gzip archive of tracked git files
│   ├── BUILD_RECIPE.json            # Exact toolchain pins and deterministic build instructions
│   └── source-manifest.json         # Deterministic sorted SHA-256 inventory of archived source files
├── sbom.spdx.json                   # SPDX 2.3 Software Bill of Materials (npm + Go + contracts)
├── LICENSE                          # Apache-2.0 license
├── NOTICE                           # Attribution notice
├── THIRD_PARTY_NOTICES.md           # Complete dependency inventory & permissive license texts
├── README.md                        # Copy of docs/engineering/WEB_RUNBOOK.md
├── release.json                     # Machine-readable provenance and component verification record
└── SHA256SUMS.txt                   # Sorted SHA-256 checksums for every file in dist/release/
```

## Build & Verify Commands

Build and package the complete reproducible release:

```sh
bash scripts/package.sh
```

Or run individual stages:

```sh
npm run build
go build -trimpath -buildvcs=false -o dist/bin/breachatlas ./cmd/breachatlas
go build -trimpath -buildvcs=false -o dist/bin/verify ./cmd/verify
npm run package:web
```

Verify checksums, offline verifier, source archive, and SBOM integrity:

```sh
cd dist/release
sha256sum -c SHA256SUMS.txt
./bin/verify --version
./bin/breachatlas --version
```

## Reproducibility & Atomic Staging Guarantees

1. **Deterministic Tar/Gzip Source Archive:** `scripts/package-source.mjs` enumerates `git ls-files` in byte-sorted order, normalizes tar metadata (`mtime: 1970-01-01T00:00:00Z`, `uid: 0`, `gid: 0`, mode `0644`/`0755`), writes raw POSIX ustar headers without extended PAX timestamps, and compresses with deterministic zlib options.
2. **Deterministic Go Binaries:** Binaries compile with `-trimpath -buildvcs=false` and zero external Go module dependencies.
3. **Atomic Release Staging:** `scripts/package-web.mjs` and `internal/release` stage the full release inside an isolated staging directory (`dist/.release-staging-*`) and compute `release.json` and `SHA256SUMS.txt` before atomically swapping `dist/release`. If interrupted or killed at the staged-byte or manifest boundary, recovery removes stale staging directories and preserves the prior complete authoritative release.
4. **License & SBOM Gate:** Every component in `sbom.spdx.json` is validated against the approved permissive license set (`Apache-2.0`, `MIT`, `BSD-3-Clause`, `BSD-2-Clause`, `ISC`, `MPL-2.0`, `Artistic-2.0`). Unknown or restrictive licenses abort packaging before `dist/release` is published.
5. **Sealed Source Immutability:** Packaging reads tracked source bytes read-only and never modifies sealed evidence or repository working tree files outside `dist/`.
