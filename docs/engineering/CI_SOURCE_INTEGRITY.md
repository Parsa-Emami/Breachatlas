# BreachAtlas: CI source integrity and dependency updates

The failed Dependabot PRs changed a GitHub Action pin, while CI compared the new checkout to the previous committed SHA256SUMS.txt and oss-roadmap evidence as if those were fresh results. The latest main build was green, but those PRs were blocked. RiskWeft's old bot branches additionally lacked the subsequent API/cache repairs.

## What is verified

`python3 scripts/verify_ci_source.py` requires full Git history and verifies every tracked file's actual bytes and executable/symlink mode against the exact checked-out HEAD. Unexpected untracked source fails. Workflows, lockfiles, tests and evidence are covered; dependencies and build outputs remain ignored runtime state.

The committed checksum manifest is verified in the Git commit where its contents last changed, with exact file-set and byte hashes. The recorded oss-roadmap source identity is independently verified against the Git tree where that evidence last changed. A forged identity, corrupted historical manifest, dirty checkout or missing history fails. Updating a dependency cannot relabel old tests as newly executed proof.

A new `source-integrity-<sha>-<run>` artifact contains this run's commit/tree, complete current file hashes and the original commits of the verified historical records. It certifies source integrity only. Real build, browser, clone and domain/API results remain the jobs executed for the new commit. No check is disabled, no success status is fabricated and no C task becomes verified from source checks.

## Local reproduction

Use a clean committed checkout with full history (`git fetch --unshallow` if shallow):

```sh
python3 -m unittest discover -s tests/engineering -p 'test_*.py' -v
python3 scripts/verify_ci_source.py
npm run check
npm run test:clone
```

The output defaults to ignored dist/ci/source.json. Source validation deliberately rejects uncommitted edits; contributors can test a staged candidate in an isolated temporary worktree before pushing.

`python3 scripts/hashes.py` and `python3 scripts/source_identity.py --check` retain their strict current-checkout behavior. They reproduce the recorded snapshot only when checked out at its original source. For a new release, regenerate the manifest, run the actual tests and record new source-bound results before certification. The CI artifact never substitutes for a published release's trusted checksums/signature or the C30/C40 acceptance gates.

Updating an existing Dependabot branch with the repaired main retains its proposed pinned dependency change and reruns the normal pull_request workflows. It does not merge the dependency upgrade into main. Historical failed runs remain an accurate record; the new head's checks show the repaired result.
