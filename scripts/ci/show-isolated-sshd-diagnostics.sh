#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${AP_CI_DIR:-}" ]]; then
  echo "isolated sshd was not initialized"
  exit 0
fi
case "${AP_CI_DIR}" in
  "${RUNNER_TEMP}"/ap-sshd.*) ;;
  *)
    echo "refusing to inspect an unexpected test directory: ${AP_CI_DIR}" >&2
    exit 1
    ;;
esac
if [[ -L "${AP_CI_DIR}" ]]; then
  echo "refusing to inspect a symlinked test directory: ${AP_CI_DIR}" >&2
  exit 1
fi

echo "Network namespace"
if sudo ip netns list | awk '{print $1}' | grep -Fqx -- "${AP_CI_NETNS}"; then
  sudo ip netns exec "${AP_CI_NETNS}" ip address show || true
  sudo ip netns exec "${AP_CI_NETNS}" ip route show || true
  sudo ip netns exec "${AP_CI_NETNS}" ss -ltnp || true
else
  echo "not present"
fi

echo "sshd logs"
for log in "${AP_CI_DIR}"/sshd-*.log; do
  if [[ -f "${log}" && ! -L "${log}" ]]; then
    echo "== $(basename "${log}") =="
    sed -n '1,200p' "${log}"
  fi
done
