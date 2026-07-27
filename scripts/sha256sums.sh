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
files=(
  "ap-v${version}-aarch64-apple-darwin.tar.gz"
  "ap-v${version}-aarch64-unknown-linux-musl.tar.gz"
  "ap-v${version}-x86_64-apple-darwin.tar.gz"
  "ap-v${version}-x86_64-unknown-linux-musl.tar.gz"
)

for file in "${files[@]}"; do
  if [[ ! -f "${bundle_directory}/${file}" || -L "${bundle_directory}/${file}" ]]; then
    echo "release asset must be a regular, non-symlink file: ${file}" >&2
    exit 1
  fi
done

checksum_file="${bundle_directory}/SHA256SUMS"
checksum_temporary="$(mktemp "${bundle_directory}/.SHA256SUMS.XXXXXX")"
cleanup() {
  rm -f "${checksum_temporary}"
}
trap cleanup EXIT HUP INT TERM
for file in "${files[@]}"; do
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "${bundle_directory}" && sha256sum -- "${file}") >> "${checksum_temporary}"
  else
    (cd "${bundle_directory}" && shasum -a 256 -- "${file}") >> "${checksum_temporary}"
  fi
done
chmod 0644 "${checksum_temporary}"
mv -f -- "${checksum_temporary}" "${checksum_file}"
