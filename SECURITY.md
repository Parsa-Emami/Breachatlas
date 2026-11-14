# Security Policy

## Supported Versions

BreachAtlas is an open-source, local-first DFIR tool. Security fixes are applied to `main` and the current `0.1.x` local-first release line on `Linux x86_64`.

| Version / Branch | Supported |
|---|---|
| `main` (`0.1.x` local-first) | Yes |
| Historical `legacy/v7` | No (archived) |

## Reporting a Vulnerability

**Do not open public GitHub issues for security vulnerabilities, real incident data, or secrets.**

Report vulnerabilities privately through **GitHub Private Vulnerability Reporting** on `Parsa-Emami/Breachatlas` (`Security` -> `Advisories` -> `Report a vulnerability`).

Include in your report:
- Affected component or endpoint (e.g., `cmd/breachatlas`, `scripts/serve-web.mjs`, `internal/export`)
- Minimal synthetic reproduction steps
- Observed impact and expected fail-closed behavior

Maintainers acknowledge private reports within **3 business days** and coordinate a fix and advisory before public disclosure.

## Scope & Non-Claims

- BreachAtlas enforces local loopback boundaries (`127.0.0.1` / `localhost` / `[::1]`), `Host`/`Origin`/`Sec-Fetch-Site`/forged-header rejection, `0440` sealed-byte immutability, and offline Ed25519 verification.
- Optional private TLS ingress (`ops/web/nginx.conf.template`) is operator-configured and defaults to `deny all`.
- No third-party security certification is claimed.
