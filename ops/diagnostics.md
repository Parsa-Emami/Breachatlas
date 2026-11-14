# BreachAtlas Operational Readiness & Redacted Diagnostics (C29 / N29)

This document defines the runtime separation between web liveness, Go engine readiness, authoritative local storage availability, required provider checks, and secret-redacted diagnostic logging.

---

## 1. Separated Liveness vs. Readiness Endpoints

| Surface | Endpoint | Purpose | Failure Behavior |
|---|---|---|---|
| **Web Relay** | `GET /healthz` | Process liveness of `scripts/serve-web.mjs` | Always returns `200 OK` (`scope: "web-shell", webHealthy: true`) while the Node HTTP listener is alive, even when downstream engine/storage/providers are unavailable. |
| **Web Relay / Unified** | `GET /readyz` | Full stack readiness | In standalone web-only mode, verifies static web assets (`200`, `engineReady: false`). In unified runtime mode, probes `dist/web/index.html` AND upstream Go engine `/readyz`. Returns `503 Service Unavailable` with explicit component flags (`webReady`, `engineReady`, `storageReady`, `providersReady`) and `failures[]` if any component is unready. |
| **Go Engine** | `GET /healthz` | Loopback process liveness of `breachatlas-engine` | `200 OK` (`status: "ok"`) while engine listener is running. |
| **Go Engine** | `GET /readyz` | Authoritative storage & provider readiness | Verifies non-symlink storage directory integrity via `storage.Open` (without mutating sealed `0440` blobs) and verifies required providers (`local`, `csv`, `json`) against the allowlisted registry. Returns `503 Service Unavailable` with `storage_prerequisite_missing`, `storage_invalid_root`, `storage_unavailable`, or `provider_unavailable` on failure. |
| **Web Relay & Engine** | `GET /api/v1/diagnostics` | Combined health, readiness, and bounded logs | Enforces same-origin (`Origin`/`Sec-Fetch-Site`), loopback `Host`, and forged-header checks (`403`). Returns separated `web_health`/`engine_health`, `readiness`, and bounded secret-redacted diagnostic snapshots (`web_relay` and `engine`). |

---

## 2. Diagnostic Log Bounds & Secret Redaction

Both `cmd/breachatlas/diagnostics.go` and `scripts/serve-web.mjs` enforce strict memory bounds and deterministic redaction prior to storage or emission:

- **Ring Buffer Limits:** Defaults from `ops/web/runtime-config.json` (`maxDiagnosticEntries: 64`, `maxDiagnosticLogBytes: 16384`, max `256` UTF-8 bytes per entry message). Oldest entries are evicted FIFO under flood and tracked via `evicted_count`.
- **Mandatory Redaction Rules (`[REDACTED]` / `[REDACTED_PEM]`):**
  - Synthetic sentinels: `SECRET_SENTINEL_*`, `CREDENTIAL_SENTINEL_*`, `TOKEN_SENTINEL_*`, `PRIVATE_KEY_SENTINEL_*`, `API_KEY_SENTINEL_*`, `AUTH_SENTINEL_*`
  - PEM private key blocks and headers (`-----BEGIN ... PRIVATE KEY-----`)
  - HTTP `Bearer` and `Basic` authorization credentials
  - URL credentials (`https://user:pass@host`)
  - Credential key-value parameters (`password=`, `secret=`, `token=`, `api_key=`, `access_key=`, `private_key=`, `client_secret=`, `authorization:`, `cookie:`)

---

## 3. Restart Recovery & Immutability Guarantees

- Fixing a missing storage prerequisite or unavailable provider requirement and restarting the engine transitions `/readyz` and `/api/v1/diagnostics` cleanly from `503 not_ready` to `200 ready`.
- Readiness probes and diagnostics never alter sealed evidence bytes (`0440` blobs) or append synthetic mutations to custody ledgers.
