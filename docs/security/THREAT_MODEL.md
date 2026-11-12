# BreachAtlas Threat Model (Local-First Open-Source Profile)

## 1. Scope and Trust Boundaries

BreachAtlas operates as a single-host, loopback-bound digital forensics and incident response (DFIR) workspace (`ADR-0003`). No paid service, cloud control plane, or external identity provider is required or enabled in the core profile.

| Boundary | Components | Untrusted Inputs | Trust Guarantee |
|---|---|---|---|
| **TB1 — Browser Tab to Web Relay** | `apps/web/src/*` (`#workspace`, `#evidence`, `#timeline`, `#roadmap`) -> `scripts/serve-web.mjs` (`127.0.0.1:4173`) | Local JSON uploads, URL paths/hashes, HTTP `Host`, `Origin`, `Sec-Fetch-Site`, custom headers | Strict CSP (`default-src 'none'`), JSX text-only rendering, prototype-pollution/depth limits, loopback `Host` check, normalized-path cross-origin/cross-site and forged-header `403` rejection across all `/api*` routes and `/runtime-config.json`, symlink/dotfile static containment. |
| **TB2 — Web Relay to Go Engine HTTP** | `scripts/serve-web.mjs` -> `cmd/breachatlas` (`127.0.0.1:8080`) | Direct local loopback HTTP requests, JSON bodies on `/api/v1/*`, `Content-Type`, `Content-Length` | Loopback `--host` binding enforced, `isLoopbackAuthority(r.Host)`, all-values `Origin`/`Sec-Fetch-Site` check (blocking duplicate-header smuggling), forged proxy/identity header rejection (`403 forged_header`), strict `DisallowUnknownFields`, bounded body reads (`16 KiB` / `256 KiB`), read deadlines. |
| **TB3 — Engine Endpoints to Domain & Storage** | `internal/storage`, `internal/cases`, `internal/evidence`, `internal/custody`, `internal/holds`, `internal/analyzers`, `internal/artifacts`, `internal/timeline`, `internal/findings`, `internal/export`, `internal/retention`, `internal/recovery` | Operation identities, Ed25519 signatures, identifiers, raw evidence streams, analyzer configs, export bundles, timestamps | Fail-closed Ed25519 verification before state lookup/mutation, case-insensitive forged header rejection, single-writer `flock`, single-case evidence ownership, `0600` sealed blob immutability, `blobs/` path containment and symlink/traversal rejection, outbound network block in analyzer sandbox, epistemic separation of hypotheses. |
| **TB4 — Offline Verification Boundary** | `cmd/verify` (`internal/export/verify.go`) | Portable bundle directory on disk | Zero network calls, deterministic SHA-256 verification of every checksum, sealed blob, custody chain, signed checkpoint, and explicit unsigned vs trusted-signer classification. |

## 2. Protected Assets

1. **Sealed Source Evidence Bytes (`0600`):** Content-addressed blobs managed by `internal/evidence/seal.go` and `internal/storage/adapter.go`. Must never be mutated, overwritten, or auto-deleted by TTL.
2. **Evidence & Provenance Manifests:** Schema-versioned (`"1"`) metadata bound by SHA-256 digests and atomic rename publication.
3. **Custody Ledger & External Checkpoints:** Append-only hash-chained custody events (`internal/custody/events.go`) and externally signed Ed25519 custody roots with anti-rollback sequence enforcement (`internal/custody/checkpoints.go`).
4. **Trust Anchors & Authorization Scope:** Ed25519 public keys, allowlisted providers (`""`, `"local"`, `"breachatlas"`), and single-case ownership mappings (`internal/cases/model.go`).
5. **Epistemic Integrity:** Observed source-bound facts (`observed_fact`) strictly separated from non-evidence analyst hypotheses (`analyst_hypothesis`, `is_source_evidence: false`).

## 3. STRIDE Threat Analysis and Implemented Controls

### Spoofing
- **Threat:** Forged proxy/identity headers (`X-Identity-Override`, `X-Forwarded-User`, `X-Forwarded-Host`, `X-Role`, `X-Case-Scope`, `X-Provider`, including mixed/lowercase variants) or external/untrusted Ed25519 keys claiming authority.
- **Controls:**
  - `internal/storage/adapter.go` (`authorizeIdentity`) normalizes all `req.Headers` keys via `strings.ToLower` and rejects override/forwarded headers and mismatched role/scope with `ErrForgedHeader` (`ErrUnavailableProvider` for non-allowlisted `x-provider`) prior to idempotency lookup or state access.
  - `scripts/serve-web.mjs` and `cmd/breachatlas/main.go` reject forged identity/proxy headers on `/api/` with HTTP `403` (`forged_header`) while permitting documented reverse-proxy transport headers (`X-Forwarded-Proto`, `X-Forwarded-For`).
  - Ed25519 signatures bind `opID`, `caseID`, `evidenceID`, `sha256Hex`, and `expiresAt`; missing, expired, or replayed signatures fail with `ErrMissingIdentity`, `ErrExpiredIdentity`, or `ErrReplayedIdentity`.

### Tampering
- **Threat:** Modifying sealed source bytes, rewriting custody history, rolling back checkpoints, tampering with export bundles, or promoting analyst notes into source evidence.
- **Controls:**
  - Sealed blobs are written with owner-only `0600` permissions via staging `fsync` + atomic rename; `internal/evidence/verify.go` classifies single-byte `digest_mismatch`, `size_mismatch`, and `missing_file` without mutating bytes.
  - `internal/custody/events.go` and `checkpoints.go` enforce monotonic sequences, hash chaining, and `CheckpointTracker` anti-rollback checks.
  - `internal/findings/notes.go` and `cmd/breachatlas/timeline.go` reject promotion flags (`claim_source_evidence: true` or non-hypothesis `claim_record_kind`) with `ErrPromotionForbidden` / `422 promotion_forbidden`.

### Repudiation
- **Threat:** Unattributed custody changes, legal hold placements/releases, or evidence destruction without audit trail.
- **Controls:**
  - `internal/custody`, `internal/holds`, and `internal/retention` require non-empty `actor`, `reason`, and RFC3339 `timestamp`, recording append-only audit logs and immutable `DELETED_TOMBSTONE` records.

### Information Disclosure & XSS
- **Threat:** Stored/reflected XSS from malicious evidence filenames, custody actors/reasons, legal hold reasons, timeline summaries, or analyst notes; local file read via path traversal, symlinks, or dotfile requests; cross-origin browser reads (DNS rebinding / CSRF).
- **Controls:**
  - `apps/web/src/pages/Evidence.tsx`, `Timeline.tsx`, `ManifestValidation.tsx`, and `main.tsx` render all untrusted strings through React JSX text nodes (zero `dangerouslySetInnerHTML`, zero `eval`).
  - `scripts/serve-web.mjs` and `cmd/breachatlas/main.go` emit `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`.
  - Both the web relay and Go engine reject non-loopback `Host` (`403 invalid_host`), `Sec-Fetch-Site: cross-site`, and foreign `Origin` (`403 origin_not_allowed`).
  - `serve-web.mjs` rejects dotfiles (`/.env`), `..` segments, null bytes, backslashes, and `realpath` symlink escapes outside `dist/web`.
  - `apps/web/src/lib/preview.mjs` rejects `__proto__`, `constructor`, `prototype`, depth > 32, > 20,000 nodes, and > 1 MiB payloads.

### Denial of Service
- **Threat:** Unbounded JSON/stream uploads, deeply nested documents, hanging connections, analyzer network/disk abuse, or concurrent lock corruption.
- **Controls:**
  - Request caps (`16 KiB` manifest validation, `256 KiB` inspect endpoints, `1 MiB` local preview, `100 MiB` evidence stream ceiling), `http.MaxBytesReader`, `SetReadDeadline(2s)`, and `AbortSignal.timeout`.
  - `internal/analyzers/sandbox.go` isolates runs in private `0700` scratch directories with byte quotas, execution deadlines, and `NetworkGuard` blocking outbound sockets (`ErrNetworkForbidden`).
  - Authoritative stores hold exclusive `syscall.Flock` locks (`ErrLockBusy`).

### Elevation of Privilege
- **Threat:** Cross-case evidence access, widened path identifiers, non-allowlisted providers, or automatic raw-evidence TTL deletion bypassing legal holds.
- **Controls:**
  - `internal/cases/model.go` enforces single-case evidence ownership (`ErrCrossCaseAccess`).
  - Identifier validation rejects `/`, `\`, `..`, and non-allowlisted characters (`ErrWidenedPath` / `ErrPathTraversal`).
  - `internal/retention/destroy.go` prohibits automatic raw-evidence TTL (`ErrAutoRawTTLForbidden`) and blocks destruction whenever `holds.Service` reports an active legal hold (`ErrHoldActive`).

## 4. Local-Host Scope & Residual Risks

- **Same-UID OS Compromise:** Any local process running under the same OS user account can inspect process memory or attempt filesystem tampering on unlocked directories; `0600` permissions and cryptographic verification detect tampering after the fact rather than preventing root/same-UID OS writes.
- **TLS Termination:** Built-in listeners bind exclusively to loopback (`127.0.0.1` / `::1`). Remote operator access requires an explicit TLS reverse proxy configured per `ops/web/nginx.conf.template` with allowlisted CIDRs.
- **Hardware Performance Targets:** Memory/latency ceilings (`2 vCPU / 4096 MiB RAM`) remain unmeasured until `C28`.
