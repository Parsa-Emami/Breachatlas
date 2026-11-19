#!/usr/bin/env bash
set -euo pipefail

mode=${1:?expected pack, verify or download}
assets=${2:?expected asset directory}
commit=${3:?expected full source commit}
[[ "$commit" =~ ^[0-9a-f]{40}$ ]]
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
manifest="$root/docs/release/RELEASE_MANIFEST.json"
repo=$(jq -er .repository "$manifest")
tag=$(jq -er .tag "$manifest")
version=$(jq -er .version "$manifest")
mapfile -t names < <(jq -er '.assets[]' "$manifest")
[[ ${#names[@]} == 5 && "${names[3]}" == release.json && "${names[4]}" == SHA256SUMS.txt ]]

check_identity() {
  jq -e --arg commit "$commit" '
    .project == "BreachAtlas" and .scope == "complete-open-source" and
    .sourceCommit == $commit and .dirty == false and
    .engineReady == true and .offlineVerifierReady == true
  ' "$1" >/dev/null
}

case "$mode" in
  pack)
    release=${4:?expected packaged release directory}
    [[ "$(git -C "$root" rev-parse HEAD)" == "$commit" ]]
    [[ -z "$(git -C "$root" status --porcelain)" ]]
    check_identity "$release/release.json"
    mkdir -- "$assets"
    tar --sort=name --format=gnu --mtime="@$(git -C "$root" show -s --format=%ct "$commit")" \
      --owner=0 --group=0 --numeric-owner -C "$release" -cf - . | gzip -n > "$assets/${names[0]}"
    cp -- "$release/source/breachatlas-source.tar.gz" "$assets/${names[1]}"
    cp -- "$release/sbom.spdx.json" "$assets/${names[2]}"
    cp -- "$release/release.json" "$assets/${names[3]}"
    (cd -- "$assets" && sha256sum -- "${names[@]:0:4}" > SHA256SUMS.txt)
    ;;
  download)
    curl -fsSL --retry 3 --max-time 45 "https://api.github.com/repos/$repo/releases/tags/$tag" | jq -e \
      --arg commit "$commit" --arg tag "$tag" --argjson names "$(jq -c .assets "$manifest")" '
        .draft == false and .prerelease == false and .target_commitish == $commit and
        .tag_name == $tag and ([.assets[].name] | sort) == ($names | sort)
      ' >/dev/null
    [[ "$(git ls-remote --exit-code "https://github.com/$repo.git" "refs/tags/$tag" | cut -f1)" == "$commit" ]]
    mkdir -- "$assets"
    for name in "${names[@]}"; do
      curl -fsSL --retry 3 --max-time 90 --max-filesize 104857600 \
        "https://github.com/$repo/releases/download/$tag/$name" -o "$assets/$name"
    done
    ;;
  verify)
    gh attestation verify "$assets/SHA256SUMS.txt" --repo "$repo" \
      --signer-workflow "$(jq -er .signer_workflow "$manifest")" \
      --source-ref "$(jq -er .source_ref "$manifest")" --source-digest "$commit" \
      --deny-self-hosted-runners
    diff -u <(printf '%s\n' "${names[@]:0:4}") <(cut -c67- "$assets/SHA256SUMS.txt")
    (cd -- "$assets" && sha256sum --strict -c SHA256SUMS.txt)
    check_identity "$assets/release.json"
    if [[ ${4:-} ]]; then
      mkdir -- "$4"
      tar --no-same-owner --no-same-permissions -xzf "$assets/${names[0]}" -C "$4"
      cmp -- "$assets/release.json" "$4/release.json"
      cmp -- "$assets/${names[1]}" "$4/source/breachatlas-source.tar.gz"
      cmp -- "$assets/${names[2]}" "$4/sbom.spdx.json"
      (cd -- "$4" && sha256sum --strict -c SHA256SUMS.txt >/dev/null)
      "$4/bin/breachatlas" --version | jq -e --arg version "$version" '.version == $version'
      "$4/bin/verify" --version --json | jq -e --arg version "$version" '.version == $version'
    fi
    ;;
  *)
    exit 2
    ;;
esac
