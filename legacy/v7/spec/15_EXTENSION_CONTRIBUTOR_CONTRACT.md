# BreachAtlas — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Extension principle
Only explicitly versioned ports are extension surfaces. Internal Laravel models/tables, worker internals and private event types are not plugin APIs.

## Plugin/adapter package requirements
Manifest: ID, semantic version, contract version range, capabilities, permissions/network/filesystem needs, license, source, maintainer, digest/signature where distributed. Conformance fixtures test valid input/output, malformed input, timeout/cancellation, resource bounds and backward compatibility.

## Community process
Small fixes use PR. New public contracts, security boundaries, datastore authority, network privilege or runtime process require RFC/ADR. DCO sign-off is required. Security vulnerabilities use private disclosure path, not public issue details before coordinated fix.
