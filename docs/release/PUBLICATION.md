# Verify and install BreachAtlas

Use Linux x86-64 and Node.js 24.19 or later in the 24.x line. Install GitHub CLI with artifact attestation support and authenticate it before verification. Running the installed app requires neither npm dependencies nor a Go compiler.

1. Download all five assets of [v1.0.0](https://github.com/Parsa-Emami/Breachatlas/releases/tag/v1.0.0) into a single directory. Record the full source commit from the public release notes.
2. Verify the outer checksum manifest against the GitHub-hosted release workflow and the recorded commit. Verify all four listed assets before extraction.

```sh
release_commit=REPLACE_WITH_FULL_SOURCE_COMMIT_FROM_RELEASE_NOTES
gh attestation verify SHA256SUMS.txt \
  --repo Parsa-Emami/Breachatlas \
  --signer-workflow Parsa-Emami/Breachatlas/.github/workflows/release.yml \
  --source-ref refs/heads/main --source-digest "$release_commit" \
  --deny-self-hosted-runners
sha256sum --strict -c SHA256SUMS.txt
```

3. Extract the verified runtime into a new directory and check its internal inventory.

```sh
mkdir breachatlas-v1.0.0
tar --no-same-owner --no-same-permissions \
  -xzf breachatlas-v1.0.0-linux-x64.tar.gz -C breachatlas-v1.0.0
cd breachatlas-v1.0.0
sha256sum --strict -c SHA256SUMS.txt
./bin/breachatlas --version
./bin/verify --version
```

4. Start the browser workspace with a private data directory outside the install.

```sh
data_dir="$HOME/.local/share/breachatlas"
install -d -m 0700 "$data_dir"
node scripts/start-local.mjs --root web --engineBin bin/breachatlas --storageDir "$data_dir"
```

Open [the workflow](http://127.0.0.1:4173/#workflow). Keep the storage path when restarting. To avoid a port collision, add `--port 4310` or `--enginePort 8081` as needed. Run the [synthetic case walkthrough](../../README.md#walk-through-a-synthetic-case) before using the workspace with your own data.

The release includes a standalone source archive and SPDX SBOM. The [artifact specification](ARTIFACTS.md) explains the source build. For upgrades, retain the previous verified install and a verified portable export. Use the [rollback procedure](../engineering/WEB_RUNBOOK.md#update-and-rollback) to switch application binaries while preserving authoritative case data. A first installation has no previous version to roll back to.
