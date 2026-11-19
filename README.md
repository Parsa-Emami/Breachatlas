# BreachAtlas

**Preserve incident evidence and give someone else a bundle they can verify offline.**

BreachAtlas is an open-source digital forensics and incident response (DFIR) workspace. It seals original evidence with SHA-256, records custody events, builds a timeline that preserves raw timestamps and confidence, and exports a portable bundle for independent verification. The browser workspace talks to a local Go engine. The offline verifier runs as a separate CLI.

[Start here](START_HERE.md) · [Release downloads](https://github.com/Parsa-Emami/Breachatlas/releases) · [Verify and install](docs/release/PUBLICATION.md) · [User guide](docs/release/USER_GUIDE.md)

[![Runtime](https://github.com/Parsa-Emami/Breachatlas/actions/workflows/runtime.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Breachatlas/actions/workflows/runtime.yml?query=branch%3Amain) [![Web](https://github.com/Parsa-Emami/Breachatlas/actions/workflows/web.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Breachatlas/actions/workflows/web.yml?query=branch%3Amain) [![Release gate](https://github.com/Parsa-Emami/Breachatlas/actions/workflows/release-gate.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Breachatlas/actions/workflows/release-gate.yml?query=branch%3Amain)

## Run locally

On Linux x86-64 with Git, Node.js 24.19 or later in the 24.x line, and Go 1.24 or later:

```sh
git clone https://github.com/Parsa-Emami/Breachatlas.git
cd Breachatlas
npm run setup
npm start
```

Open [the workflow at 127.0.0.1:4173](http://127.0.0.1:4173/#workflow). Press Ctrl+C to stop the app. For a named data directory, start with `npm start -- --storageDir /path/to/private-data`. Create the directory with mode 0700 before starting. The release archive also includes the built web workspace, Go engine and offline verifier. Its runtime needs Node.js and Linux x86-64. [Install a release archive](docs/release/PUBLICATION.md).

## Walk through a synthetic case

1. Open **Workflow** and use the prefilled synthetic evidence to run **Upload & Seal**. The result reports the SHA-256 digest of the sealed bytes.
2. Choose **Add Custody** and **Parse Bounded Timeline**. Inspect the custody chain, raw source timestamps, offsets and confidence.
3. Place a legal hold and try the delete and expiry checks. The app rejects both operations while the hold is active.
4. Export the signed bundle and verify it. The tamper check demonstrates what happens when bytes in a copy change.
5. Run consistency recovery and restore the bundle to check that derived indexes can be rebuilt without changing the sealed source.

For an independent check, transfer the whole export directory and obtain the signing public key through a separate trusted channel. The verifier can run on a machine without the engine:

```sh
./bin/verify -bundle /path/to/bundle -trusted-key "$TRUSTED_PUBLIC_KEY_HEX" -require-signature -json
```

Use `dist/bin/verify` when running from source. [Reference workflow](docs/product/REFERENCE_WORKFLOW.md) · [Storage, privacy and recovery](docs/release/SERVICE_POLICY.md).

## Supported use

BreachAtlas is designed for a local operator on Linux x86-64. The engine and web relay bind to loopback. The core workflow needs no cloud account, database service or external provider daemon. Keep case data on an operator-controlled filesystem and keep an independently verified export before upgrading. The [maintenance policy](docs/release/MAINTENANCE.md) and [operations runbook](docs/engineering/WEB_RUNBOOK.md) describe the support and recovery boundaries.

## Contribute

Run `npm run check` for the web and contract suite and `go test ./...` for the engine. The [contributing guide](CONTRIBUTING.md) explains the repository structure. Use synthetic, redacted examples when [reporting an issue](https://github.com/Parsa-Emami/Breachatlas/issues). Report vulnerabilities through the private route in the [security policy](SECURITY.md).

[Apache-2.0 license](LICENSE) · [Third-party notices](THIRD_PARTY_NOTICES.md) · [Roadmap](ROADMAP.md) · [نقشهٔ راه فارسی](docs/ROADMAP_FA.md)

Built and maintained by Parsa Emami. [Portfolio](https://parsaaemm.dev/) · [GitHub](https://github.com/Parsa-Emami)
