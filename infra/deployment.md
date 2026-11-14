# BreachAtlas Local Launch and Optional Private Hosting

## 1. Zero-Domain Local-First Operation (Default)

BreachAtlas requires **no owned public domain**, external DNS, TLS certificate, or cloud account for local single-analyst operation:

```sh
npm run setup
npm start
```

- `scripts/start-local.mjs` binds both processes exclusively to loopback:
  - Web relay: `http://127.0.0.1:4173` (or custom `--port`)
  - Go engine: `http://127.0.0.1:8080` (or custom `--enginePort`)
- Both `scripts/serve-web.mjs` (`validateLoopbackEngineTarget`) and `cmd/breachatlas` (`isLoopbackHost`) fail closed if configured with any non-loopback bind or upstream host (`0.0.0.0`, `192.0.2.x`, external hostname).

---

## 2. Enforced Network, Origin, Header & Cache Boundaries

1. **Host Authority (DNS-Rebinding Protection):**
   - Both the web relay and Go engine reject any request whose `Host` header is not a loopback authority (`127.0.0.1`, `localhost`, `[::1]`, or `127.x.x.x` with valid port `1..65535`) with `403 {"error":"invalid_host"}`.
2. **Same-Origin & Fetch-Metadata Enforcement:**
   - Cross-site browser requests (`Sec-Fetch-Site: cross-site`) and foreign or `null` `Origin` headers are rejected across all routes (`/`, `/index.html`, `/healthz`, `/readyz`, `/runtime-config.json`, `/assets/*`, and `/api/*`) with `403` (`origin_not_allowed`).
3. **Forged Proxy/Identity Header Rejection:**
   - On `/api/*`, requests containing `X-Identity-Override`, `X-Forwarded-User`, `X-Forwarded-Host`, `X-Forwarded-Role`, `X-Role`, `X-Case-Scope`, `X-Provider`, `X-Auth-User`, or `X-User-Override` (case-insensitive) are rejected with `403` (`forged_header`).
   - Standard Nginx reverse-proxy transport headers (`X-Forwarded-Proto`, `X-Forwarded-For`) remain permitted when forwarding to the loopback authority (`Host $proxy_host`).
4. **Strict Cache-Control Boundaries:**
   - Fingerprinted build assets (`/assets/*`): `Cache-Control: public, max-age=31536000, immutable`.
   - HTML shell (`/`, `/index.html`), `/runtime-config.json`, `/healthz`, `/readyz`, and all `/api/*` responses: `Cache-Control: no-store`.
   - Security headers set on every response: `Content-Security-Policy` (`frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
5. **Default Unexposed Engine Work:**
   - Standalone `scripts/serve-web.mjs` and `ops/web/runtime-config.json` keep `engineEnabled: false` and reject `/api/v1/*` with `503 engine_not_integrated`.
   - In unified supervised mode (`scripts/start-local.mjs`), `/readyz` and `/api/v1/diagnostics` fail closed (`503`) if storage prerequisites or required providers are missing.

---

## 3. Optional Private TLS Reverse Proxy (`ops/web/nginx.conf.template` & `ops/web/service.systemd`)

When an operator chooses to host BreachAtlas on a private host behind an owned domain and TLS certificate:

1. **No Direct Engine Exposure:** `ops/web/nginx.conf.template` terminates TLS 1.2/1.3 and proxies **only** to the web relay on `http://127.0.0.1:4310` with `proxy_set_header Host $proxy_host;` (never `$host`). Port `8080` (the Go engine) MUST remain unbound to external interfaces and unproxied.
2. **Deny-All Default:** `ops/web/nginx.conf.template` enforces `allow 127.0.0.1; allow ::1; deny all;` until reviewed operator CIDRs are explicitly added and validated with `nginx -t`.
3. **Systemd Isolation:** `ops/web/service.systemd` supervises the complete release from `/srv/breachatlas/current` as unprivileged user `breachatlas-web` with `StateDirectory=breachatlas`, `NoNewPrivileges=true`, `ProtectSystem=strict`, `PrivateTmp=true`, `ProtectHome=true`, and `CapabilityBoundingSet=`.
4. **No Implicit System Modification:** Neither `npm run setup`, `npm start`, nor `bash scripts/package.sh` edits `/etc/nginx`, `/etc/systemd`, or system trust stores.
