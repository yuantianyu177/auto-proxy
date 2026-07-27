#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${AP_CI_DIR:-}" ]]; then
  exit 0
fi
case "${AP_CI_DIR}" in
  "${RUNNER_TEMP}"/ap-sshd.*) ;;
  *)
    echo "refusing to use an unexpected test directory for cleanup: ${AP_CI_DIR}" >&2
    exit 1
    ;;
esac

cleanup_failed=false
directory_valid=false
if [[ -d "${AP_CI_DIR}" && ! -L "${AP_CI_DIR}" ]]; then
  directory_valid=true
else
  echo "test directory is missing or invalid; continuing global fixture cleanup" >&2
  cleanup_failed=true
fi

cleanup_user=false
cleanup_network=false
if [[ "${directory_valid}" == true ]]; then
  [[ -f "${AP_CI_DIR}/user-create-attempted" ]] && cleanup_user=true
  [[ -f "${AP_CI_DIR}/netns-create-attempted" ]] && cleanup_network=true
else
  # AP_CI_DIR is exported only after all fixed resource names were confirmed
  # absent, so any matching resources after a lost directory belong to this
  # fixture on the single-use hosted runner.
  cleanup_user=true
  cleanup_network=true
fi

namespace_present() {
  local output
  if ! output="$(sudo ip netns list)"; then
    return 2
  fi
  awk -v expected="${AP_CI_NETNS}" '$1 == expected { found = 1 } END { exit !found }' \
    <<< "${output}"
}

interface_present() {
  local output
  if ! output="$(sudo ip -o link show)"; then
    return 2
  fi
  awk -F': ' -v expected="${AP_CI_HOST_VETH}" '
    {
      split($2, name, "@")
      if (name[1] == expected) {
        found = 1
      }
    }
    END { exit !found }
  ' <<< "${output}"
}

namespace_processes=()
read_namespace_processes() {
  local output
  local process
  namespace_processes=()
  if ! output="$(sudo ip netns pids "${AP_CI_NETNS}" 2>/dev/null)"; then
    return 2
  fi
  while IFS= read -r process; do
    [[ -z "${process}" ]] && continue
    if [[ ! "${process}" =~ ^[0-9]+$ ]]; then
      echo "invalid namespace process ID: ${process}" >&2
      return 2
    fi
    namespace_processes+=("${process}")
  done <<< "${output}"
}

wait_for_namespace_processes() {
  for _ in {1..50}; do
    if ! read_namespace_processes; then
      return 2
    fi
    if [[ "${#namespace_processes[@]}" -eq 0 ]]; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wrapper_processes=()
if [[ "${directory_valid}" == true ]]; then
  for process_file in "${AP_CI_DIR}"/sshd-*.process; do
    [[ -f "${process_file}" && ! -L "${process_file}" ]] || continue
    process="$(< "${process_file}")"
    if [[ "${process}" =~ ^[0-9]+$ ]]; then
      wrapper_processes+=("${process}")
    else
      echo "invalid saved sshd wrapper process ID: ${process}" >&2
      cleanup_failed=true
    fi
  done
fi

live_wrapper_processes=()
refresh_live_wrapper_processes() {
  local process
  live_wrapper_processes=()
  for process in "${wrapper_processes[@]}"; do
    if sudo kill -0 "${process}" 2>/dev/null; then
      live_wrapper_processes+=("${process}")
    fi
  done
}

network_namespace_present=false
if [[ "${cleanup_network}" == true ]]; then
  if namespace_present; then
    network_namespace_present=true
  else
    namespace_status=$?
    if [[ "${namespace_status}" -eq 2 ]]; then
      echo "failed to inspect network namespaces before cleanup" >&2
      cleanup_failed=true
    fi
  fi
fi

namespace_ready_for_delete=true
if [[ "${network_namespace_present}" == true ]]; then
  if read_namespace_processes; then
    if [[ "${#namespace_processes[@]}" -gt 0 ]]; then
      sudo kill -TERM "${namespace_processes[@]}" 2>/dev/null || true
    fi
  else
    echo "failed to inspect namespace processes before cleanup" >&2
    cleanup_failed=true
    namespace_ready_for_delete=false
  fi
fi
refresh_live_wrapper_processes
if [[ "${#live_wrapper_processes[@]}" -gt 0 ]]; then
  sudo kill -TERM "${live_wrapper_processes[@]}" 2>/dev/null || true
fi

if [[ "${network_namespace_present}" == true && "${namespace_ready_for_delete}" == true ]]; then
  if wait_for_namespace_processes; then
    :
  else
    wait_status=$?
    if [[ "${wait_status}" -eq 1 && "${#namespace_processes[@]}" -gt 0 ]]; then
      sudo kill -KILL "${namespace_processes[@]}" 2>/dev/null || true
      if wait_for_namespace_processes; then
        :
      else
        echo "namespace processes remain after SIGKILL" >&2
        cleanup_failed=true
        namespace_ready_for_delete=false
      fi
    else
      echo "failed while waiting for namespace processes" >&2
      cleanup_failed=true
      namespace_ready_for_delete=false
    fi
  fi
fi

for _ in {1..50}; do
  refresh_live_wrapper_processes
  [[ "${#live_wrapper_processes[@]}" -eq 0 ]] && break
  sleep 0.1
done
if [[ "${#live_wrapper_processes[@]}" -gt 0 ]]; then
  sudo kill -KILL "${live_wrapper_processes[@]}" 2>/dev/null || true
  for _ in {1..50}; do
    refresh_live_wrapper_processes
    [[ "${#live_wrapper_processes[@]}" -eq 0 ]] && break
    sleep 0.1
  done
fi
if [[ "${#live_wrapper_processes[@]}" -gt 0 ]]; then
  echo "sshd wrapper processes remain after SIGKILL" >&2
  cleanup_failed=true
fi

if [[ "${network_namespace_present}" == true && "${namespace_ready_for_delete}" == true ]]; then
  if ! sudo ip netns delete "${AP_CI_NETNS}"; then
    echo "failed to remove network namespace: ${AP_CI_NETNS}" >&2
    cleanup_failed=true
  fi
fi

if [[ "${cleanup_network}" == true ]]; then
  if interface_present; then
    if ! sudo ip link delete "${AP_CI_HOST_VETH}"; then
      echo "failed to remove network interface: ${AP_CI_HOST_VETH}" >&2
      cleanup_failed=true
    fi
  else
    interface_status=$?
    if [[ "${interface_status}" -eq 2 ]]; then
      echo "failed to inspect network interfaces during cleanup" >&2
      cleanup_failed=true
    fi
  fi
fi

if [[ "${cleanup_user}" == true ]] && id -u "${AP_CI_TEST_USER}" >/dev/null 2>&1; then
  if ! sudo userdel --remove "${AP_CI_TEST_USER}"; then
    echo "failed to remove isolated SSH account: ${AP_CI_TEST_USER}" >&2
    cleanup_failed=true
  fi
fi

if [[ "${cleanup_network}" == true ]]; then
  if namespace_present; then
    echo "network namespace remains after cleanup: ${AP_CI_NETNS}" >&2
    cleanup_failed=true
  else
    namespace_status=$?
    if [[ "${namespace_status}" -eq 2 ]]; then
      echo "failed to verify network namespace cleanup" >&2
      cleanup_failed=true
    fi
  fi
  if interface_present; then
    echo "network interface remains after cleanup: ${AP_CI_HOST_VETH}" >&2
    cleanup_failed=true
  else
    interface_status=$?
    if [[ "${interface_status}" -eq 2 ]]; then
      echo "failed to verify network interface cleanup" >&2
      cleanup_failed=true
    fi
  fi
fi
if [[ "${cleanup_user}" == true ]] && id -u "${AP_CI_TEST_USER}" >/dev/null 2>&1; then
  echo "isolated SSH account remains after cleanup: ${AP_CI_TEST_USER}" >&2
  cleanup_failed=true
fi

if [[ "${directory_valid}" == true ]]; then
  rm -rf -- "${AP_CI_DIR}"
  if [[ -e "${AP_CI_DIR}" ]]; then
    echo "test directory remains after cleanup: ${AP_CI_DIR}" >&2
    cleanup_failed=true
  fi
fi

if [[ "${cleanup_failed}" == true ]]; then
  exit 1
fi
