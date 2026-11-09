# BreachAtlas: Bootstrap & Engine Build Evidence

Updated for task **C03**: unified local engine setup and launch.

## Overview

BreachAtlas requires zero external cloud or paid services. `npm run setup` prepares the local development and operational profile with a single command:
1. Validates Node.js runtime (requires Node >= 24.19).
2. Verifies Go compiler availability (`go version`).
3. Compiles the Go engine binary into `dist/bin/breachatlas` from `./cmd/breachatlas`.
4. Prepares web workspace data and builds the client static bundle into `dist/web/`.

## Executed Setup Command

```bash
npm run setup
```

Output:
```json
{
  "executed": true,
  "steps": [
    ["ci", "--ignore-scripts", "--no-fund"],
    ["run", "build"]
  ],
  "capability": "unified-local-runtime",
  "engineReady": true,
  "binary": "dist/bin/breachatlas",
  "start": "npm start",
  "note": "Full product usability requires the C30 workflow; complete OSS v1 requires C40."
}
```

## Doctor Probe

```bash
npm run doctor
```

Output:
```json
{
  "nodeSupported": true,
  "webAssetsBuilt": true,
  "engineBuilt": true,
  "readiness": "WEB_FOUNDATION",
  "engineReady": false,
  "start": "npm start",
  "next": "npm run plan -- next"
}
```

## Build Artifacts

| Artifact | Path | Format | Verification |
|---|---|---|---|
| Go Engine Binary | `dist/bin/breachatlas` | ELF 64-bit LSB executable (x86_64) | `dist/bin/breachatlas --version` |
| Web Bundle | `dist/web/index.html` | Static HTML5 + CSS + JS bundle | `dist/web/index.html` presence |

No second terminal or external container daemon is required.
