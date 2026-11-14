# BreachAtlas — Independent Clone-to-Value Onboarding Results (`C36` / `N36`)

This document records the observed repeatability of BreachAtlas onboarding in a clean isolated `git clone` environment following only the public documentation (`README.md`, `docs/release/USER_GUIDE.md`, and `docs/engineering/CLONE_TO_RUN.md`).

## Environment & Prerequisites

- **Host OS:** `Linux x86_64`
- **Node.js:** `24.19.0` (`npm 11.17.0`)
- **Go:** `1.26.2`
- **Paid / Cloud Accounts Required:** None (`0` external accounts, `0` domains, `0` cloud APIs)
- **Customer Pilot / Demand Prerequisites:** Not required for open-source usability (`N36`)

## Observed Clone-to-Value Execution (`npm run test:clone`)

Executed via `scripts/clone-smoke.mjs` against a fresh isolated `git clone` checkout:

1. **Clean-Checkout Setup (`npm run setup`):**
   - Installed locked Node dependencies, built `dist/web/index.html`, and compiled `dist/bin/breachatlas` and `dist/bin/verify`.
   - Observed duration: **3144 ms** (~3.1 s).
2. **Web-Only Boundary Check:**
   - Verified `engineReady: false` and `/api/v1/*` `503` when started without the Go engine.
3. **Missing-Prerequisite Failure Check:**
   - Verified `/readyz` returns HTTP `503` (`storageReady: false`) when `--storageDir` is missing.
4. **Full 8-Step Core Workflow & Restart (`tests/browser/clone-to-value.spec.ts` + `tests/scenarios/clone-to-value.json`):**
   - Completed all 8 steps (upload, seal `0440`, custody event, timezone-aware timeline parse, legal hold delete block, export bundle, offline `dist/bin/verify`, restart persistence, and bundle restore) in Chromium against live `npm start`.
   - Observed duration: **2831 ms** (~2.8 s).
5. **Doctor & Scenario Contract Verification (`npm run doctor`):**
   - Confirmed `nodeSupported: true`, `webAssetsBuilt: true`, `engineBuilt: true`, and `scenarioSteps: 8`.
   - Total end-to-end clean-clone duration: **6463 ms** (~6.5 s).

## Observed Failures & Negative Cases

- Missing storage prerequisite: rejected with HTTP `503` on `/readyz`.
- Malformed JSON / invalid manifest / unavailable provider: rejected explicitly without placeholder success.
- Sealed `0440` source bytes: verified unmodified across workflow execution, restart, and restore.
