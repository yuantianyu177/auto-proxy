#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <target> <version> <binary> <output-directory>" >&2
  exit 2
fi

target="$1"
version="$2"
binary="$3"
output_directory="$4"

case "${target}" in
  x86_64-unknown-linux-musl|aarch64-unknown-linux-musl|x86_64-apple-darwin|aarch64-apple-darwin) ;;
  *)
    echo "unsupported release target: ${target}" >&2
    exit 2
    ;;
esac

if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid release version: ${version}" >&2
  exit 2
fi
if [[ ! -f "${binary}" || -L "${binary}" || ! -x "${binary}" ]]; then
  echo "release binary must be an executable, non-symlink regular file: ${binary}" >&2
  exit 1
fi

for document in README.md RELEASING.md LICENSE LICENSE-MIT LICENSE-APACHE CHANGELOG.md config.example.toml; do
  if [[ ! -f "${document}" || -L "${document}" ]]; then
    echo "required release document must be a regular, non-symlink file: ${document}" >&2
    exit 1
  fi
done

archive_base="ap-v${version}-${target}"
mkdir -p "${output_directory}"
if [[ ! -d "${output_directory}" || -L "${output_directory}" ]]; then
  echo "release output directory must be a real directory: ${output_directory}" >&2
  exit 1
fi
staging_root="$(mktemp -d)"
archive_temporary=""
cleanup() {
  rm -rf "${staging_root}"
  if [[ -n "${archive_temporary}" ]]; then
    rm -f "${archive_temporary}"
  fi
}
trap cleanup EXIT HUP INT TERM

archive_temporary="$(mktemp "${output_directory}/.${archive_base}.XXXXXX")"

binary_description="$(file -b "${binary}")"
case "${target}" in
  x86_64-unknown-linux-musl)
    expected_description='ELF.*x86-64'
    ;;
  aarch64-unknown-linux-musl)
    expected_description='ELF.*(aarch64|ARM64)'
    ;;
  x86_64-apple-darwin)
    expected_description='Mach-O.*x86_64'
    ;;
  aarch64-apple-darwin)
    expected_description='Mach-O.*arm64'
    ;;
esac
if [[ ! "${binary_description}" =~ ${expected_description} ]]; then
  echo "binary architecture does not match ${target}: ${binary_description}" >&2
  exit 1
fi

mkdir -p "${staging_root}/${archive_base}"
chmod 0755 "${staging_root}/${archive_base}"
install -m 0755 "${binary}" "${staging_root}/${archive_base}/ap"
for document in README.md RELEASING.md LICENSE LICENSE-MIT LICENSE-APACHE CHANGELOG.md config.example.toml; do
  install -m 0644 "${document}" "${staging_root}/${archive_base}/${document}"
done

COPYFILE_DISABLE=1 tar -czf "${archive_temporary}" \
  -C "${staging_root}" "${archive_base}"
chmod 0644 "${archive_temporary}"
mv -f -- "${archive_temporary}" "${output_directory}/${archive_base}.tar.gz"
