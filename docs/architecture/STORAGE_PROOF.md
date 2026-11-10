# BreachAtlas: Proof of Recoverable Local Authoritative Writes (C05)

## 1. Architectural Scope and ADR-0003 Compliance

BreachAtlas operates as a local-first, privacy-preserving incident investigation platform. Per ADR-0003, local service metadata and authoritative evidence storage do not require external cloud services, hosted databases, or compulsory SQL daemons. Instead, BreachAtlas implements a bounded, versioned manifest and immutable-file repository port located entirely on the host filesystem.

Task C05 proves the storage port invariants defined in ADR-0003:
- **Single local writer**: exclusive file-level concurrency control (`syscall.Flock`).
- **Bounded state**: hard storage quota and per-record size limits.
- **Staged, hash-checked durable bytes**: atomic two-phase write with cryptographic verification (`SHA-256`) and filesystem sync (`f.Sync`).
- **Atomic versioned manifest publication**: monotonic generation indexing with atomic rename (`os.Rename`) and directory flush (`dir.Sync`).
- **Post-commit acknowledgement**: clients are acknowledged strictly after durable publication.
- **Shared transaction idempotency & auth**: identity authorization occurs before idempotency resolution; stable operation IDs share the visible transaction to prevent duplicate side effects without leaking metadata to unauthenticated callers.
- **Crash and recovery resilience**: reconciliation of orphan staging artifacts and streaming verification of referential integrity across restarts.
- **Tamper resistance & path containment**: cryptographic authorization (Ed25519), strict path traversal containment (`ErrWidenedPath`), header integrity enforcement (`ErrForgedHeader`), external provider rejection (`ErrUnavailableProvider`), and absolute immutability of sealed source bytes.

## 2. Invariant Guarantees and Implementation Details

### Single Writer Exclusivity
Concurrency between engine instances or background jobs is strictly mediated by an advisory process lock file (`.lock`) located at the root of the storage directory.
- On initialization, `storage.Open()` acquires an exclusive, non-blocking lock via `syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)`.
- If another process holds the lock, the call fails immediately with `storage.ErrLockBusy`.
- Goroutine concurrency within the process is serialized through `sync.Mutex`.

### Bounded State and Quota Limits
Storage consumption is guarded before allocation:
- Global storage quota (`MaxStorageBytes`, default 20 GiB) rejects writes when committed state plus payload exceeds capacity (`ErrStorageQuotaExceeded`).
- Record size boundary (`MaxRecordBytes`, 100 MiB) rejects oversized payloads and malformed manifest claims (`ErrPayloadTooLarge`).

### Two-Phase Staging and Integrity Verification
Every write follows a strict staging cycle:
1. The payload is written into an isolated temporary staging file (`staging/<operation_id>_<timestamp>.tmp`).
2. A streaming SHA-256 hasher computes the payload digest in transit.
3. The computed digest is compared against the declared manifest SHA-256. Any discrepancy triggers immediate deletion of the staging file and returns `ErrDigestMismatch`.
4. The staging file is synced to disk via `f.Sync()`, followed by directory entry synchronization.
5. The verified payload is renamed into content-addressed immutable storage (`blobs/<sha256>`).

### Atomic Visible State Publication
Authoritative state is tracked in a versioned state manifest (`manifest.json`):
- Each state manifest increments a monotonic `Generation` counter and records committed operation IDs and evidence mappings.
- The new state manifest is written to a temporary staging file (`staging/manifest.<generation>.tmp`), flushed with `Sync()`, and atomically swapped into place via `os.Rename`.
- The root directory is synced (`dir.Sync()`) to commit the directory entry in the host filesystem.
- In-memory state transitions and client acknowledgements occur exclusively after durable persistence.

### Stable Operation IDs, Idempotency, and Authentication Precedence
- Every write request requires a stable `OperationID` that satisfies identifier rules (`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`).
- Identity authorization occurs strictly **before** idempotency lookup: an unauthenticated request cannot query committed operations or replay outcomes.
- If an authorized request presents an existing `OperationID`, the engine verifies parameter consistency (`CaseID`, `EvidenceID`, `SHA256`). If parameters conflict, `ErrOperationConflict` is returned. If parameters match, previously recorded commit metadata is returned with `IsReplay = true`, executing zero filesystem operations.

### Recovery and Orphan Staging Reconciliation
When opening or recovering an adapter instance (`Recover()`):
- The `staging/` directory is scanned for lingering `.tmp` files created by crashed or interrupted writes. All orphan files are pruned.
- The state manifest is verified against disk: every referenced blob must exist, match its recorded byte size, and pass streaming SHA-256 checksum verification without unbounded memory allocation.
- If a referenced blob is missing or altered, the engine detects corruption (`ErrMissingReference` or `ErrCorruptedReference`).
- If `manifest.json` contains malformed JSON or an unsupported schema version, recovery fails with typed `ErrCorruptedManifest`.

### Cryptographic Identity, Path Boundaries, and Sealed Source Bytes
Authoritative writes require cryptographic identity:
- Write requests supply an `Identity` token signed with an Ed25519 private key.
- The token binds `(OperationID, CaseID, EvidenceID, SHA256, ExpiresAt)`.
- Requests with missing credentials, expired timestamps, mismatched case scopes, forged signatures, replayed signatures across different operations, or forged escalation headers are rejected prior to sensitive operations.
- Identifiers are validated against path traversal (`..`, `/`, `\`); any widened path attempt fails with `ErrWidenedPath`.
- External or unavailable identity providers fail with `ErrUnavailableProvider`.
- Once evidence is committed under a `(CaseID, EvidenceID)` key, any attempt to overwrite or alter the sealed record is rejected with `ErrSealedBytesImmutable`.

### Projection Rebuildability
Authoritative storage serves as the single source of truth. Projections (case indexes, evidence inventories, timeline summaries) are non-authoritative read models that can be fully rebuilt from the committed state manifest via `RebuildProjection()`.

## 3. Verification and Evidence

The storage adapter and its recovery invariants are verified through:
1. `tests/storage_test.go`:
   - `TestC05FixturesAndNegativeCases`: exercises positive write, identity checks, scope isolation, signature validation, oversized payloads, digest mismatch, replayed identity, widened path, unavailable provider, forged headers, and immutability invariants against versioned fixtures in `tests/fixtures/breachatlas/C05/`.
   - `TestSingleWriterExclusivity`: validates flock contention and orderly handover.
   - `TestStableOperationIDsAndIdempotency`: proves identical replayed responses with unchanged state generation, authentication enforcement on replays, and conflicting parameter rejection.
   - `TestInterruptedWriteAndOrphanRecovery`: proves cleanup of orphan staging files and zero partial state visibility.
   - `TestDiskFullRecovery`: proves clean rollback when staging write encounters disk-full faults.
   - `TestMissingAndCorruptedReferenceDetection`: validates detection of deleted or tampered blobs.
   - `TestCorruptedManifestDetection`: validates rejection of malformed or version-incompatible manifests.
   - `TestWidenedPathTraversalRejection`: validates rejection of path escape attempts in operations and cases.
   - `TestBoundedStorageLimits`: validates quota enforcement.
   - `TestProjectionRebuild`: proves deterministic reconstruction of read projections.

Commands:
- `go test -v -race -count=1 ./...`
- `go vet ./...`
- `npm run validate:plan`
