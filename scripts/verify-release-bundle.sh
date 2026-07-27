#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <version> <bundle-directory>" >&2
  exit 2
fi

version="$1"
bundle_directory="$2"
if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid release version: ${version}" >&2
  exit 2
fi
if [[ ! -d "${bundle_directory}" || -L "${bundle_directory}" ]]; then
  echo "bundle directory must be a real directory: ${bundle_directory}" >&2
  exit 1
fi
command -v file >/dev/null || {
  echo "file is required to verify release binary formats" >&2
  exit 1
}
temporary_root="$(mktemp -d)"
cleanup() {
  if [[ -n "${temporary_root}" && -d "${temporary_root}" && ! -L "${temporary_root}" ]]; then
    rm -rf -- "${temporary_root}"
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
checksum_file="${bundle_directory}/SHA256SUMS"

if [[ ! -f "${checksum_file}" || -L "${checksum_file}" ]]; then
  echo "release bundle is missing SHA256SUMS" >&2
  exit 1
fi

expected_files=(
  "ap-v${version}-aarch64-apple-darwin.tar.gz"
  "ap-v${version}-aarch64-unknown-linux-musl.tar.gz"
  "ap-v${version}-x86_64-apple-darwin.tar.gz"
  "ap-v${version}-x86_64-unknown-linux-musl.tar.gz"
)
for file in "${expected_files[@]}"; do
  if [[ ! -f "${bundle_directory}/${file}" || -L "${bundle_directory}/${file}" ]]; then
    echo "release bundle asset must be a regular, non-symlink file: ${file}" >&2
    exit 1
  fi
done
expected_bundle_entries="$({
  printf '%s\n' "${expected_files[@]}"
  printf '%s\n' "SHA256SUMS"
} | LC_ALL=C sort)"
actual_bundle_entries="$(find "${bundle_directory}" -mindepth 1 -maxdepth 1 -exec basename {} \; | LC_ALL=C sort)"
if [[ "${actual_bundle_entries}" != "${expected_bundle_entries}" ]]; then
  echo "release bundle does not contain the exact asset set" >&2
  exit 1
fi
checksum_entries="$(wc -l < "${checksum_file}" | tr -d ' ')"
if [[ "${checksum_entries}" != "${#expected_files[@]}" ]]; then
  echo "SHA256SUMS should contain ${#expected_files[@]} entries, found ${checksum_entries}" >&2
  exit 1
fi
if ! LC_ALL=C awk '
  NF != 2 || length($1) != 64 || $1 !~ /^[0-9A-Fa-f]+$/ { exit 1 }
' "${checksum_file}"; then
  echo "SHA256SUMS contains a malformed entry" >&2
  exit 1
fi
for file in "${expected_files[@]}"; do
  matches="$(LC_ALL=C awk -v expected="${file}" '$2 == expected { count++ } END { print count + 0 }' "${checksum_file}")"
  if [[ "${matches}" != "1" ]]; then
    echo "SHA256SUMS must contain exactly one entry for ${file}" >&2
    exit 1
  fi
done

if command -v sha256sum >/dev/null 2>&1; then
  (cd "${bundle_directory}" && sha256sum --check SHA256SUMS)
else
  (cd "${bundle_directory}" && shasum -a 256 --check SHA256SUMS)
fi

for target in \
  x86_64-unknown-linux-musl \
  aarch64-unknown-linux-musl \
  x86_64-apple-darwin \
  aarch64-apple-darwin
do
  archive_base="ap-v${version}-${target}"
  archive="${bundle_directory}/${archive_base}.tar.gz"
  actual_members="$(tar -tzf "${archive}" | LC_ALL=C sort)"
  expected_members="$(
    printf '%s\n' \
      "${archive_base}/" \
      "${archive_base}/ap" \
      "${archive_base}/README.md" \
      "${archive_base}/RELEASING.md" \
      "${archive_base}/LICENSE" \
      "${archive_base}/LICENSE-MIT" \
      "${archive_base}/LICENSE-APACHE" \
      "${archive_base}/CHANGELOG.md" \
      "${archive_base}/config.example.toml" \
      | LC_ALL=C sort
  )"
  if [[ "${actual_members}" != "${expected_members}" ]]; then
    echo "archive ${archive_base}.tar.gz does not contain the exact release file set" >&2
    exit 1
  fi

  actual_metadata="$(
    LC_ALL=C tar -tvzf "${archive}" \
      | awk '{ print substr($1, 1, 10), $NF }' \
      | LC_ALL=C sort
  )"
  expected_metadata="$({
    printf '%s\n' "drwxr-xr-x ${archive_base}/"
    printf '%s\n' "-rwxr-xr-x ${archive_base}/ap"
    for document in README.md RELEASING.md LICENSE LICENSE-MIT LICENSE-APACHE CHANGELOG.md config.example.toml; do
      printf '%s\n' "-rw-r--r-- ${archive_base}/${document}"
    done
  } | LC_ALL=C sort)"
  if [[ "${actual_metadata}" != "${expected_metadata}" ]]; then
    echo "archive ${archive_base}.tar.gz contains an unexpected file type or mode" >&2
    exit 1
  fi

  binary_temporary="${temporary_root}/${target}-ap"
  tar -xOzf "${archive}" "${archive_base}/ap" > "${binary_temporary}"
  binary_description="$(file -b "${binary_temporary}")"
  case "${target}" in
    x86_64-unknown-linux-musl)
      expected_description='ELF.*x86-64.*(statically linked|static-pie linked)'
      ;;
    aarch64-unknown-linux-musl)
      expected_description='ELF.*(aarch64|ARM64).*(statically linked|static-pie linked)'
      ;;
    x86_64-apple-darwin)
      expected_description='Mach-O.*x86_64'
      ;;
    aarch64-apple-darwin)
      expected_description='Mach-O.*arm64'
      ;;
  esac
  if [[ ! "${binary_description}" =~ ${expected_description} ]]; then
    echo "archive binary does not match ${target}: ${binary_description}" >&2
    exit 1
  fi
done
