# BreachAtlas — Local Privacy, Limits, and Service Policy

BreachAtlas is a local-first, open-source (`Apache-2.0`) digital forensics and incident response (DFIR) application.

- **No required hosted subscription:** All core features run locally without any cloud account, telemetry, or external license server.
- **No paid core features:** Evidence sealing, custody ledgers, timeline indexing, portable export, offline verification, and recovery are 100% open source.
- **No unearned SLA:** BreachAtlas is provided as-is under the `Apache-2.0` license with community/maintainer best-effort support via the repository issue tracker and `SECURITY.md`.

## 1. Local Data Locations

Under the configured local storage root (default `.local-data/`), BreachAtlas separates authoritative and derived data into distinct subdirectories:

- `quarantine/` — Bounded streaming intake staging before sealing.
- `sealstore/` — Content-addressed immutable sealed evidence blobs (`blobs/sha256/...`), atomic seal manifests (`manifests/`), and `seal-index.json`.
- `custody/` — Append-only hash-chained custody ledger.
- `checkpoints/` — Signed Ed25519 custody root checkpoints.
- `artifacts/` — Derived analyzer output manifests bound to sealed input hashes.
- `timeline/` — Deterministic derived event index (rebuildable from verified artifacts without modifying sealed bytes).
- `exports/` — Self-contained portable DFIR export bundles.
- `retention/` and `holds/` — Legal holds and immutable `DELETED_TOMBSTONE` audit records.
- `restore/` — Atomic bundle restoration staging and operation ledger.

## 2. Export, Deletion, Retention, Backup, and Recovery

- **Export & Offline Verification:** Portable bundles can be exported and verified offline using `dist/bin/verify` (`cmd/verify`) with zero network access.
- **Deletion & Retention:** Automatic raw-evidence TTL is forbidden (`ErrAutoRawTTLForbidden`). Active legal holds take strict precedence over deletion (`ErrHoldActive`). Authorized deletions emit immutable `DELETED_TOMBSTONE` records.
- **Backup & Recovery:** `RestoreStore.VerifyAndRebuildCase` rebuilds derived timeline indexes without rewriting custody history or mutating sealed bytes. Binary upgrades/rollbacks (`internal/release/upgrade.go`) preserve `DataDir` and refuse to overwrite newer accepted host data with old backups (`ErrNewerDataOverwriteForbidden`).

## 3. Published Operational Limits & Supported Profiles

- **Supported Host Profile:** `Linux x86_64` (loopback `127.0.0.1` local web + Go engine profile).
- **Published Bounds:**
  - Maximum HTTP JSON request body: `256 KiB`
  - Maximum evidence upload size: `4 GiB`
  - Bounded diagnostic ring buffer: `64` entries / `16384` bytes (`1000` log entry ceiling in user-facing runtime diagnostics)
