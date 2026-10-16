# BreachAtlas — Dependency Policy v7

## Reference dependencies
- opensearch
- podman
- s3-compatible object store
- postgresql
- valkey
- in-toto optional provenance
- openbao optional signer

All dependencies require exact source/license/security tracking. Vendor-specific libraries stay in Infrastructure adapters. Scanner/rule/model outputs are normalized before entering Domain. Third-party Actions/images are SHA/digest pinned in release paths.
