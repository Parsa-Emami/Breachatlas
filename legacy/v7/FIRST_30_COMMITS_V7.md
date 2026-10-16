# BreachAtlas — First 30 Commit Plan v7

These are atomic intent boundaries, not mandatory commit-message text. Do not combine unrelated items merely to hit a number.

1. chore: initialize toolchain manifests and lockfiles
2. ci: make repository validation executable
3. chore: add local development environment/health checks
4. test: add clean-bootstrap smoke test
5. docs: freeze Phase 0 invariants and ADR index
6. phase0: case/actor/evidence domain
7. phase0: content-addressed evidence identity
8. phase0: classification/retention/legal-hold states
9. phase0: immutable custody event model
10. test(phase0): add domain invariant tests
11. docs(phase0): record exit evidence and ADR updates
12. phase1: stream to quarantine/object store
13. phase1: hash during upload with length checks
14. phase1: finalize immutable seal metadata
15. phase1: abort/cleanup partial uploads
16. test(phase1): add partial upload tests
17. docs(phase1): record exit evidence and ADR updates
18. phase2: signed/attributable custody events
19. phase2: legal hold prevents deletion/retention expiry
20. phase2: transfer/checkout state rules
21. phase2: clock/source metadata
22. test(phase2): add hold enforcement
23. docs(phase2): record exit evidence and ADR updates
24. phase3: analyzer plugin contract
25. phase3: rootless/no-network default
26. phase3: read-only evidence mount
27. phase3: resource/time limits and cleanup
28. test(phase3): add malicious analyzer tests
29. docs(phase3): record exit evidence and ADR updates
30. test: close Phase 0/1 regression or failure-proof gap before scope expansion
