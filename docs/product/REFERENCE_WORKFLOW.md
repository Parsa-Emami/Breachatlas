# BreachAtlas: Reference Workflow

**Status**: Planned domain acceptance contract; the current web foundation and JSON structure preview do not implement this workflow. Engine execution begins at C03; complete clean-host workflow, restart, and restore are proven at C30.

## Workflow Summary

The BreachAtlas reference workflow represents the open-source clone-to-value sequence for an independent DFIR analyst handling a case:

$$\text{Upload Synthetic Evidence} \longrightarrow \text{Seal} \longrightarrow \text{Add Custody} \longrightarrow \text{Parse Bounded Timeline} \longrightarrow \text{Legal Hold / Negative Test} \longrightarrow \text{Export} \longrightarrow \text{Verify on Clean Host} \longrightarrow \text{Recover Consistency}$$

1. **Upload Synthetic Evidence**: Stream synthetic log/artifact into the content-addressed case evidence store.
2. **Seal**: Calculate immutable SHA-256 digest, record size, media type, and timestamp; seal source bytes to prevent modification.
3. **Add Custody**: Record custody event into an append-only custody chain, calculating the updated custody root.
4. **Parse Bounded Timeline**: Extract chronological event records, preserving original raw timestamps, timezone offsets, and confidence metrics through normalization.
5. **Hold/delete negative test**: Place an active legal hold on the evidence artifact and verify that deletion/expiration attempts are rejected.
6. **Export**: Package case metadata, sealed manifests, custody log, and timeline into a portable, signed export bundle.
7. **Verify on Another Host with External Trust**: Verify the standalone bundle on an independent host without a running server or network connection using an external public trust key.
8. **Recover Consistency**: Validate store consistency and rebuild indexes from content-addressed evidence and immutable custody events.

## Domain Model & Invariants

### Primary Domain: `evidence-manifest`

| Field | Type | Description |
|---|---|---|
| `case_id` | string | Unique identifier of the DFIR investigation case (e.g. `case-2026-001`) |
| `evidence_id` | string | Unique identifier of the uploaded evidence item (e.g. `ev-2026-0001`) |
| `sha256` | string (hash) | Hex-encoded SHA-256 cryptographic digest of the source bytes |
| `size_bytes` | integer | Exact byte length of the evidence payload |
| `media_type` | string | MIME/media type identifying the format (e.g. `text/plain`, `application/octet-stream`) |
| `acquired_at` | string (timestamp) | ISO 8601 acquisition timestamp with timezone offset |
| `custody_root` | string (hash) | Hex-encoded root hash of the append-only custody log |

### Required Invariants

1. **Sealed source bytes never modified**: Once sealed, source bytes are content-addressed and immutable. Any modification causes integrity verification failure.
2. **Legal hold takes precedence over deletion**: Active legal holds prevent deletion, purges, and automated retention expiration.
3. **Raw timestamp and confidence survive normalization**: Normalizing timeline events must retain the original raw timestamp string, timezone offset, and source confidence score.

## User Acceptance Tests (UAT)

1. **Integrity Verification Failure on Tampered Bytes**
   - *FA*: `evidence را upload/seal کن؛ byte عوض‌شده verifier را شکست دهد`
   - *EN*: Upload and seal synthetic evidence; any modified byte causes the cryptographic verifier to reject the artifact with an integrity failure.
2. **Legal Hold Precedence over Deletion**
   - *FA*: `hold فعال اجازهٔ delete و expire ندهد`
   - *EN*: An active legal hold blocks delete and retention-expiration operations; requests return error and leave the item intact.
3. **Independent Offline Verification with External Trust**
   - *FA*: `export در دستگاه جدا بدون سرور با trust key مستقل بررسی شود و timezone خام حفظ شود`
   - *EN*: The export bundle verifies on a separate machine without an active server using an independent public trust key, preserving raw timestamps and timezone information.

## Machine Contract & Clean Host Execution

The exact machine-readable specification is frozen in `tests/scenarios/clone-to-value.json` with synthetic test fixtures in `tests/fixtures/breachatlas/C01/`.

Clean-host clone and bootstrap commands:
```bash
git clone https://github.com/Parsa-Emami/Breachatlas.git
cd Breachatlas
npm run setup
npm start
```

No customer interview, paid account, external pilot count, or market-validation claim is required.
