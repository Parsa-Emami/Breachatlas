# BreachAtlas evidence manifest contract

C04 defines version `"1"` of the local manifest validation input and result. Submit the JSON file through the workspace or POST to `/api/v1/evidence-manifests/validate` through the unified local supervisor. Use UTF-8 JSON with `Content-Type: application/json`.

The [input schema](input.schema.json) specifies the eight required fields. The engine rejects unknown, duplicate, null, and incorrectly cased fields. Send `size_bytes` as a decimal integer without fractions or exponents. Supply the media type without parameters and a valid calendar timestamp with an explicit offset. The manifest is limited to 16 KiB and may describe up to 100 MiB of evidence. The engine allows two seconds to read the request body. The browser can cancel the request and the local relay closes its upstream connection when the caller disconnects.

The [result schema](result.schema.json) distinguishes valid metadata from typed errors. The success digest is SHA-256 of the submitted manifest bytes. Evidence files, cryptographic seals, custody records, and durable state belong to later stages. Validation remains stateless across restarts.

| HTTP | Validation errors |
|---|---|
| 400 | `invalid_json` |
| 403 | `origin_not_allowed` |
| 405 | `method_not_allowed` |
| 408 | `request_timeout` |
| 413 | `payload_too_large` |
| 415 | `unsupported_media_type` |
| 422 | `invalid_manifest`, `unexpected_or_duplicate_field`, `invalid_field`, `missing_field`, `unsupported_version` |
| 503 | `engine_unavailable` |

C01 reference fixtures and `legacy/v7/contracts` remain historical formats. The local contract requires the explicit version field. Future incompatible shapes require a new version with independent fixtures.

Run the [synthetic fixtures](../tests/fixtures/breachatlas/C04/) through the actual loopback engine with `npm run test:contracts`.
