# BreachAtlas — Observed Installation and Workflow Fixes (`C37` / `N37`)

This document records actual installation, packaging, CI, and workflow issues observed across `C30`, `C33`, `C35`, and `C36`, their targeted fixes, and regression checks. No customer feedback or external pilot claims are invented.

## Resolved Blockers and Fixes

| ID | Observed In | Root Cause | Resolution | Verification |
|---|---|---|---|---|
| `keyboard_enable_wait_in_c33` | `C33` CI (`web-foundation / verify`) | `tests/browser/full-workflow-accessibility.spec.ts` called `focus()` on a disabled workflow step button before React state enabled it after the prior step completed. | Wait for `expect(locator).toBeEnabled()` before focusing/activating the step button (`f78a10b`). | `npm run test:browser` |
| `content_addressed_blob_rel_path_check` | `C31` / `C35` test review | `tests/release_packaging_test.go` checked a hypothetical `cases/.../sealed.bin` path guarded by `if err == nil`, which silently skipped verifying the actual `blobs/sha256/...` sealed file (`SealStore` content-addressed path). | Capture `sealedManifest.BlobRelPath` from `ss.SealQuarantined` and require `os.ReadFile` + byte equality without silent skip (`tests/release_packaging_test.go`, `tests/distribution_upgrade_test.go`). | `go test -race -count=1 ./tests -run "TestC31\|TestC35"` |
| `clone_to_value_scenario_pin` | `C36` clean-clone verification | Updating `verified_at_commit` inside `tests/scenarios/clone-to-value.json` triggered `tests/web/reference-workflow.test.mjs` contract failure (`verified_at_commit` is pinned to `C30`). | Preserve `verified_at_commit: "C30"` in `tests/scenarios/clone-to-value.json` while recording C36 clean-clone timings and repeatability in `scripts/clone-smoke.mjs` and `docs/product/ONBOARDING_RESULTS.md`. | `npm run check` and `npm run test:clone` |

## Explicit Remaining Limits (Open Scope)

- Supported and observed runtime/distribution host architecture remains `Linux x86_64`.
- Non-Linux desktop/server targets (macOS, Windows) remain unverified in this release track and are not claimed as supported.
