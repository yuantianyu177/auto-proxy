#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <Mach-O binary>" >&2
  exit 2
fi
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Developer ID signing must run on macOS" >&2
  exit 2
fi

binary="$1"
: "${AP_MACOS_CERTIFICATE_P12_BASE64:?missing AP_MACOS_CERTIFICATE_P12_BASE64}"
: "${AP_MACOS_CERTIFICATE_PASSWORD:?missing AP_MACOS_CERTIFICATE_PASSWORD}"
: "${AP_MACOS_SIGNING_IDENTITY:?missing AP_MACOS_SIGNING_IDENTITY}"

if [[ ! -f "${binary}" || -L "${binary}" || ! -x "${binary}" ]]; then
  echo "binary must be an executable, non-symlink regular file: ${binary}" >&2
  exit 1
fi

temporary_root="$(mktemp -d)"
certificate_path="${temporary_root}/developer-id.p12"
keychain_path="${temporary_root}/ap-release.keychain-db"
keychain_password="$(uuidgen)$(uuidgen)"

cleanup() {
  security delete-keychain "${keychain_path}" >/dev/null 2>&1 || true
  rm -rf "${temporary_root}"
}
trap cleanup EXIT HUP INT TERM

printf '%s' "${AP_MACOS_CERTIFICATE_P12_BASE64}" | base64 -D > "${certificate_path}"
chmod 0600 "${certificate_path}"

security create-keychain -p "${keychain_password}" "${keychain_path}"
security set-keychain-settings -lut 21600 "${keychain_path}"
security unlock-keychain -p "${keychain_password}" "${keychain_path}"
security import "${certificate_path}" \
  -k "${keychain_path}" \
  -P "${AP_MACOS_CERTIFICATE_PASSWORD}" \
  -T /usr/bin/codesign
security set-key-partition-list \
  -S apple-tool:,apple:,codesign: \
  -s \
  -k "${keychain_password}" \
  "${keychain_path}" >/dev/null

if ! security find-identity -v -p codesigning "${keychain_path}" \
  | grep -F -- "${AP_MACOS_SIGNING_IDENTITY}" >/dev/null; then
  echo "configured Developer ID identity was not imported" >&2
  exit 1
fi

codesign --force \
  --identifier dev.approxy.ap \
  --options runtime \
  --timestamp \
  --keychain "${keychain_path}" \
  --sign "${AP_MACOS_SIGNING_IDENTITY}" \
  "${binary}"
codesign --verify --strict --verbose=2 "${binary}"
if ! codesign --display --verbose=4 "${binary}" 2>&1 \
  | grep -F -- 'Authority=Developer ID Application:' >/dev/null; then
  echo "binary was not signed with a Developer ID Application certificate" >&2
  exit 1
fi
if ! codesign --display --verbose=4 "${binary}" 2>&1 \
  | grep -Fqx -- 'Identifier=dev.approxy.ap'; then
  echo "binary does not use the stable ap signing identifier" >&2
  exit 1
fi
