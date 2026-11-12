# BreachAtlas Restore & Consistency Verification Template

Use this template when verifying restoration of a portable DFIR export bundle (`internal/recovery.RestoreStore.RestoreFromBundle`) or cross-store consistency and derived timeline index rebuilding (`internal/recovery.RestoreStore.VerifyAndRebuildCase`) on a local-first host.

---

## 1. Prerequisites

- **Target Stores:**
  - `evidence.SealStore` (content-addressed sealed blobs and `.manifest.json` files)
  - `custody.LedgerStore` (append-only `.jsonl` custody chains)
  - `custody.FileCheckpointStore` (signed custody root checkpoints, when configured)
  - `artifacts.ArtifactStore` (derived analyzer manifests and output payloads)
  - `timeline.EventIndexStore` (derived timeline index rebuilt deterministically from verified artifacts)
  - `retention.RetentionStore` (optional; verified tombstones cross-checked against sealed manifests)
- **External Trust Anchors (when signature verification is enforced):**
  - Outside-bundle Ed25519 public keys keyed by `key_id` for bundle manifests, custody checkpoints, and derived artifact attestations.
- **Exclusive Lock:**
  - Open `recovery.OpenRestoreStore` with an exclusive `.restore.lock` (`flock`) before running restore or rebuild operations. Concurrent writers must fail closed with `ErrLockBusy`.

---

## 2. Mandatory Cross-Checks

Before committing any restored state or rebuilding derived indexes, verify all of the following invariants:

1. **Offline Bundle Verification (`export.VerifyBundle`):**
   - Bundle `bundle-manifest.json` digest matches canonical bundle bytes (`BundleDigest`).
   - Every entry in `FileChecksums` exists within the bundle directory (no path traversal, no symlinks) and matches its declared SHA-256.
   - If signature verification is required or trusted keys are provided, bundle Ed25519 signature validates against external trust.
2. **Evidence Manifest & Sealed Blob Consistency:**
   - Every sealed evidence blob matches `SealedManifest.SHA256`, `SealedManifest.SizeBytes`, and `ManifestDigest`.
   - If the target `SealStore` already contains `(case_id, evidence_id)`, the existing sealed blob and manifest must pass `evidence.VerifyStoreEvidence` and match the bundle's `SHA256`, `SizeBytes`, `MediaType`, and `CustodyRoot`. Any divergence fails closed with `ErrManifestConsistency`.
3. **Custody Chain & Signed Checkpoint Integrity:**
   - Custody `.jsonl` chains pass `Sequence` monotonicity, `PrevHash`, `EventDigest`, and `CustodyRoot` validation.
   - Checkpoint `Sequence` and `CustodyRoot` match the corresponding event in the custody ledger, and Ed25519 signatures validate against configured `TrustedCheckpointKeys`.
4. **Derived Artifact Provenance:**
   - Every `DerivedManifest` passes `artifacts.ValidateManifestStructure` and `artifacts.VerifyDerivedManifest`, and every `InputBinding` matches verified case sealed evidence (`SHA256`, `SizeBytes`).
   - Output payload bytes match `Output.SHA256`, `Output.SizeBytes`, `Output.RecordCount`, and `DerivedPayload` provenance metadata.

---

## 3. Custody & Sealed Source Immutability Rules

- **Sealed Source Bytes Never Modified (`SealedBytesModified == false`):**
  - Existing content-addressed blobs and sealed manifests are read-only inputs and are never overwritten, re-encoded, or truncated.
  - Pre- and post-operation SHA-256 snapshots of all sealed blobs must be identical (`ErrSealedBytesModified` on any drift).
- **No Custody Rewrite (`CustodyRewritten == false`):**
  - Pre-existing custody `.jsonl` chains are strictly append-only and never rewritten, truncated, or mutated during restore or index rebuild.
  - A restore candidate whose custody chain diverges from an existing local chain for `(case_id, evidence_id)` fails closed with `ErrCustodyRewriteForbidden`.
  - Missing custody chains are imported atomically (`.tmp` + `fsync` + `rename`) only when absent.

---

## 4. Derived Index Rebuild & Search Parity

- Rebuild `timeline.EventIndexStore` solely from verified `ArtifactStore` payloads and read-only `SealStore` inputs via `RebuildCaseIndex`.
- Missing or corrupted derived timeline index files (`timeline-index.json` / `cases/<case_id>.index.json`) must recover cleanly without touching sealed source bytes or custody ledgers.
- Verify rebuilt timeline entries preserve `RawTimestamp`, `TimezoneStatus`, DST ambiguity (`CandidateUTCs`), and `Confidence` verbatim, and produce deterministic `SearchResult.ResultDigest` parity with pre-loss queries.

---

## 5. Fault Boundaries, Replay, & Rollback Policy

- **Staged-Byte / Manifest Boundary:** Interruptions at `FailAfterStageBeforeCommit` or `FailBeforeManifestCommit` must leave target stores and `restore-manifest.json` in a complete prior authoritative state; reopening `RestoreStore` cleans partial files in `staging/`.
- **Idempotency & Resource Caps:** Replaying the same `OperationID` with identical parameters returns `IdempotentReplay: true` with zero duplicate side effects; reusing `OperationID` with conflicting parameters fails with `ErrRestoreConflict`. Exhausting `MaxRestoreBytes`, `MaxRetryCount`, or hitting disk-full fails closed (`ErrQuotaExceeded`, `ErrRetryLimitExceeded`, `ErrDiskFull`).
- **Rollback & Forward-Repair Rule:** Never overwrite newer accepted authoritative state with an older backup. If a restore or schema transition fails after staging, revert only uncommitted staging artifacts; if newer data has already been accepted, retain the latest valid bytes/export and compatible reader and apply tested forward repair.

---

## 6. Verification Record Template

```json
{
  "commit_id": "C26",
  "case_id": "<case_id>",
  "operation_id": "<operation_id>",
  "bundle_id": "<bundle_id>",
  "bundle_digest": "<sha256>",
  "verified_evidence_count": 0,
  "verified_artifact_count": 0,
  "rebuilt_timeline_entries": 0,
  "case_index_sha256": "<sha256>",
  "custody_rewritten": false,
  "sealed_bytes_modified": false,
  "raw_timestamps_preserved": true,
  "search_parity_verified": true,
  "command_exits": {
    "go_vet": 0,
    "go_test": 0
  }
}
```
