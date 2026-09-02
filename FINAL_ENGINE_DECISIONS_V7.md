# BreachAtlas — Final Engine Decisions v7

These are accepted v1 decisions, not open blockers. Alternatives require a future ADR and must preserve public/domain contracts.

1. Evidence bytes are content-addressed immutable objects. The application never mutates source evidence; analyzers create new derived artifacts.
2. EvidenceManifest v1 records SHA-256, size, media type, acquisition/source metadata, uploader, storage locator, timestamps and custody root.
3. PostgreSQL is authoritative for cases/evidence/custody/legal holds. OpenSearch is a fully rebuildable timeline/search projection.
4. Timeline events retain original timestamp string/value, timezone/offset if known, normalized UTC, precision, source clock and confidence/ambiguity metadata.
5. AnalyzerPlugin v1 is an OCI image pinned by digest, no-network by default, read-only evidence mount, bounded resources and structured output manifest.
6. Analyzer results include tool/image digest, config hash, input evidence hashes, output hashes and timestamps; in-toto-style attestation format is supported for provenance.
7. Legal hold overrides normal retention/deletion. Deletion creates durable audit/tombstone evidence and never rewrites historical custody events.
8. Portable export contains case manifest, evidence/derived manifests, custody log and SHA256SUMS; optional manifest signature is produced via SignerProvider/OpenBao Transit.
9. Real incident evidence is never committed to repository demo fixtures.
