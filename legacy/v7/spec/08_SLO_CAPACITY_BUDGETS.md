# BreachAtlas — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Service objectives / correctness objectives
- Original evidence bytes never modified after seal
- Every derived artifact references source evidence digest + analyzer identity/version/config
- OpenSearch/search timeline can be deleted and rebuilt without losing authoritative custody/evidence metadata

## Capacity envelope
`implementation-start/workload.json` is the initial declared workload, not a marketing benchmark. Before public v1 replace provisional thresholds with measured p50/p95/p99, throughput, CPU, memory, queue lag and storage growth on documented hardware.

## Backpressure
Every ingress/engine queue has a finite capacity or admission control. When saturated, the system rejects/degrades predictably with retry hints; it never solves overload by unbounded memory, goroutines, processes, graph expansions or queued jobs.
