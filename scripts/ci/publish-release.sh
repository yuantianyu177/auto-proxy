#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <release-tag> <expected-commit> <bundle-directory> <prerelease:true|false>" >&2
  exit 2
fi

release_tag="$1"
expected_commit="$(printf '%s' "$2" | tr 'A-F' 'a-f')"
bundle_directory="$3"
prerelease="$4"
: "${GH_TOKEN:?missing GH_TOKEN}"
: "${GH_REPO:?missing GH_REPO}"

if [[ ! "${release_tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid release tag: ${release_tag}" >&2
  exit 2
fi
if [[ ! "${expected_commit}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "expected commit must be a full Git SHA-1" >&2
  exit 2
fi
if [[ "${prerelease}" != true && "${prerelease}" != false ]]; then
  echo "prerelease must be true or false" >&2
  exit 2
fi
if [[ ! -d "${bundle_directory}" || -L "${bundle_directory}" ]]; then
  echo "bundle directory must be a real directory: ${bundle_directory}" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  checksum_command=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  checksum_command=(shasum -a 256)
else
  echo "sha256sum or shasum is required to publish release assets" >&2
  exit 1
fi

expected_assets="$({
  for asset in "${bundle_directory}"/*; do
    if [[ ! -f "${asset}" || -L "${asset}" ]]; then
      echo "release asset must be a regular, non-symlink file: ${asset}" >&2
      exit 1
    fi
    digest="$("${checksum_command[@]}" "${asset}" | awk '{ print $1 }')"
    printf '%s\tsha256:%s\n' "$(basename "${asset}")" "${digest}"
  done
} | LC_ALL=C sort)"
if [[ -z "${expected_assets}" ]]; then
  echo "release bundle contains no assets" >&2
  exit 1
fi

resolve_tag_commit() {
  local object_type
  local object_sha
  local response
  if ! response="$(
    gh api "repos/${GH_REPO}/git/ref/tags/${release_tag}" \
      --jq '[.object.type, .object.sha] | @tsv'
  )"; then
    return 1
  fi
  IFS=$'\t' read -r object_type object_sha <<< "${response}"

  for _ in {1..8}; do
    case "${object_type}" in
      commit)
        printf '%s\n' "${object_sha}"
        return 0
        ;;
      tag)
        if ! response="$(
          gh api "repos/${GH_REPO}/git/tags/${object_sha}" \
            --jq '[.object.type, .object.sha] | @tsv'
        )"; then
          return 1
        fi
        IFS=$'\t' read -r object_type object_sha <<< "${response}"
        ;;
      *)
        return 1
        ;;
    esac
  done
  return 1
}

assert_tag_commit() {
  local stage="$1"
  local current_commit
  if ! current_commit="$(resolve_tag_commit)"; then
    echo "could not resolve ${release_tag} ${stage}" >&2
    return 1
  fi
  if [[ "${current_commit}" != "${expected_commit}" ]]; then
    echo "${release_tag} moved during the release; expected ${expected_commit}, got ${current_commit}" >&2
    return 1
  fi
}

assert_tag_commit "before creating the draft"
if gh release view "${release_tag}" >/dev/null 2>&1; then
  echo "a GitHub release already exists for ${release_tag}; refusing to replace it" >&2
  exit 1
fi

create_arguments=(
  "${release_tag}"
  --draft
  --verify-tag
  --generate-notes
  --title "ap ${release_tag}"
)
if [[ "${prerelease}" == true ]]; then
  create_arguments+=(--prerelease)
fi

release_created=false
cleanup_failed_draft() {
  local status=$?
  local draft_state
  if [[ "${status}" -ne 0 && "${release_created}" == true ]]; then
    draft_state="$(gh release view "${release_tag}" --json isDraft --jq '.isDraft' 2>/dev/null || true)"
    if [[ "${draft_state}" == true ]]; then
      echo "release publication failed; removing the unpublished draft" >&2
      gh release delete "${release_tag}" --yes >/dev/null 2>&1 || true
    else
      echo "release publication failed; preserving release because draft state could not be confirmed" >&2
    fi
  fi
  exit "${status}"
}
trap cleanup_failed_draft EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

gh release create "${create_arguments[@]}"
release_created=true
gh release upload "${release_tag}" "${bundle_directory}"/*

assets_verified=false
actual_assets=""
for _ in {1..10}; do
  if actual_assets="$(
    gh release view "${release_tag}" --json assets \
      --jq '.assets[] | [.name, .digest] | @tsv' \
      | LC_ALL=C sort
  )" && [[ "${actual_assets}" == "${expected_assets}" ]]; then
    assets_verified=true
    break
  fi
  sleep 1
done
if [[ "${assets_verified}" != true ]]; then
  echo "uploaded GitHub release asset digests do not match the verified bundle" >&2
  exit 1
fi

draft_state="$(gh release view "${release_tag}" --json isDraft --jq '.isDraft')"
if [[ "${draft_state}" != true ]]; then
  echo "release unexpectedly became public before final verification" >&2
  exit 1
fi
assert_tag_commit "before publication"
gh release edit "${release_tag}" --draft=false
release_created=false
trap - EXIT HUP INT TERM
