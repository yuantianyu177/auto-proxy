#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

required_environment=(
  RUNNER_TEMP
  GITHUB_ENV
  AP_CI_TEST_USER
  AP_CI_NETNS
  AP_CI_HOST_VETH
  AP_CI_NS_VETH
  AP_CI_HOST_ADDR
  AP_CI_SSH_ADDR
  AP_CI_SSH_PORT
  AP_CI_FORWARDING_DENIED_SSH_PORT
  AP_CI_LISTEN_DENIED_SSH_PORT
  AP_CI_PASSWORD_SSH_PORT
  AP_CI_UNUSED_PERMITTED_PORT
  AP_SSH_POLICY_LISTEN_DENIED_PORT
)
for variable in "${required_environment[@]}"; do
  if [[ -z "${!variable:-}" ]]; then
    echo "missing required environment variable: ${variable}" >&2
    exit 2
  fi
done

for command in chpasswd getent ip iptables openssl ssh-keygen ss sudo sysctl useradd; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "required command is unavailable: ${command}" >&2
    exit 1
  fi
done
if [[ ! -x /usr/sbin/sshd ]]; then
  echo "required command is unavailable: /usr/sbin/sshd" >&2
  exit 1
fi

ports=(
  "${AP_CI_SSH_PORT}"
  "${AP_CI_FORWARDING_DENIED_SSH_PORT}"
  "${AP_CI_LISTEN_DENIED_SSH_PORT}"
  "${AP_CI_PASSWORD_SSH_PORT}"
)
if [[ "$(printf '%s\n' "${ports[@]}" | LC_ALL=C sort -u | wc -l | tr -d ' ')" != "${#ports[@]}" ]]; then
  echo "isolated sshd ports must be distinct" >&2
  exit 2
fi
if [[ "${AP_CI_UNUSED_PERMITTED_PORT}" == "${AP_SSH_POLICY_LISTEN_DENIED_PORT}" ]]; then
  echo "the permitted control port must differ from the denied test port" >&2
  exit 2
fi
if id -u "${AP_CI_TEST_USER}" >/dev/null 2>&1; then
  echo "refusing to reuse an existing login user: ${AP_CI_TEST_USER}" >&2
  exit 1
fi
if ! namespace_output="$(sudo ip netns list)"; then
  echo "could not inspect existing network namespaces" >&2
  exit 1
fi
if awk '{print $1}' <<< "${namespace_output}" | grep -Fqx -- "${AP_CI_NETNS}"; then
  echo "refusing to reuse an existing network namespace: ${AP_CI_NETNS}" >&2
  exit 1
fi
if ! link_output="$(sudo ip -o link show)"; then
  echo "could not inspect existing network interfaces" >&2
  exit 1
fi
if awk -F': ' '{ split($2, name, "@"); print name[1] }' <<< "${link_output}" \
  | grep -Fqx -- "${AP_CI_HOST_VETH}"; then
  echo "refusing to reuse an existing network interface: ${AP_CI_HOST_VETH}" >&2
  exit 1
fi

AP_CI_DIR="$(mktemp -d "${RUNNER_TEMP}/ap-sshd.XXXXXX")"
chmod 0700 "${AP_CI_DIR}"
printf 'AP_CI_DIR=%s\n' "${AP_CI_DIR}" >> "${GITHUB_ENV}"

touch "${AP_CI_DIR}/user-create-attempted"
sudo useradd --create-home --user-group --shell /bin/sh "${AP_CI_TEST_USER}"
user_uid="$(id -u "${AP_CI_TEST_USER}")"
user_gid="$(id -g "${AP_CI_TEST_USER}")"
read -r -a user_groups <<< "$(id -G "${AP_CI_TEST_USER}")"
if [[ "${user_uid}" == "0" || "${user_gid}" == "0" || "${#user_groups[@]}" -ne 1 || "${user_groups[0]}" != "${user_gid}" ]]; then
  echo "the isolated SSH account is not an ordinary unprivileged user" >&2
  exit 1
fi
user_home="$(getent passwd "${AP_CI_TEST_USER}" | awk -F: 'NR == 1 { print $6 }')"
if [[ -z "${user_home}" || ! -d "${user_home}" || -L "${user_home}" ]]; then
  echo "the isolated SSH account has an invalid home directory" >&2
  exit 1
fi

# The random account password is used only by the password-only fixture. Its
# value never enters argv, the environment, or logs; tests receive only the
# path to a mode-0600 file.
account_password="$(openssl rand -hex 32)"
password_fixture="${AP_CI_DIR}/account-password"
printf '%s' "${account_password}" > "${password_fixture}"
chmod 0600 "${password_fixture}"
printf 'AP_TEST_SSH_PASSWORD_FIXTURE_PATH=%s\n' "${password_fixture}" >> "${GITHUB_ENV}"
account_password_hash="$(printf '%s' "${account_password}" | openssl passwd -6 -stdin)"
unset account_password
printf '%s:%s\n' "${AP_CI_TEST_USER}" "${account_password_hash}" | sudo chpasswd --encrypted
unset account_password_hash

ssh-keygen -q -t ed25519 -N "" -f "${AP_CI_DIR}/client-key"
ssh-keygen -q -t ed25519 -N "" -f "${AP_CI_DIR}/host-key"
cut -d ' ' -f 1,2 "${AP_CI_DIR}/client-key.pub" \
  | sed 's/^/restrict,port-forwarding /' > "${AP_CI_DIR}/authorized_keys"
sudo install -d -m 0700 -o "${AP_CI_TEST_USER}" -g "${AP_CI_TEST_USER}" "${user_home}/.ssh"
sudo install -m 0600 -o "${AP_CI_TEST_USER}" -g "${AP_CI_TEST_USER}" \
  "${AP_CI_DIR}/authorized_keys" "${user_home}/.ssh/authorized_keys"

host_public_key="$(cut -d ' ' -f 1,2 "${AP_CI_DIR}/host-key.pub")"
for port in "${ports[@]}"; do
  printf '[%s]:%s %s\n' "${AP_CI_SSH_ADDR}" "${port}" "${host_public_key}"
done > "${AP_CI_DIR}/known_hosts"
chmod 0600 "${AP_CI_DIR}/known_hosts"

for variable in \
  AP_DIRECT_SSH_DEV_IDENTITY_FILE \
  AP_SSH_POLICY_IDENTITY_FILE \
  AP_THROUGHPUT_SSH_IDENTITY_FILE
do
  printf '%s=%s\n' "${variable}" "${AP_CI_DIR}/client-key" >> "${GITHUB_ENV}"
done
for variable in \
  AP_DIRECT_SSH_DEV_KNOWN_HOSTS \
  AP_SSH_POLICY_KNOWN_HOSTS \
  AP_THROUGHPUT_SSH_KNOWN_HOSTS \
  AP_TEST_SSH_PASSWORD_KNOWN_HOSTS
do
  printf '%s=%s\n' "${variable}" "${AP_CI_DIR}/known_hosts" >> "${GITHUB_ENV}"
done

touch "${AP_CI_DIR}/netns-create-attempted"
sudo ip netns add "${AP_CI_NETNS}"
sudo ip link add "${AP_CI_HOST_VETH}" type veth peer name "${AP_CI_NS_VETH}"
sudo ip link set "${AP_CI_NS_VETH}" netns "${AP_CI_NETNS}"
sudo ip address add "${AP_CI_HOST_ADDR}/30" dev "${AP_CI_HOST_VETH}"
sudo ip link set "${AP_CI_HOST_VETH}" up

# Disable IPv6 and omit a default IPv4 route so the fixture cannot reach the
# public network through an untested path.
sudo ip netns exec "${AP_CI_NETNS}" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1
sudo ip netns exec "${AP_CI_NETNS}" sysctl -q -w net.ipv6.conf.default.disable_ipv6=1
sudo ip netns exec "${AP_CI_NETNS}" ip link set lo up
sudo ip netns exec "${AP_CI_NETNS}" ip address add \
  "${AP_CI_SSH_ADDR}/30" dev "${AP_CI_NS_VETH}"
sudo ip netns exec "${AP_CI_NETNS}" ip link set "${AP_CI_NS_VETH}" up

sudo ip netns exec "${AP_CI_NETNS}" iptables -P INPUT DROP
sudo ip netns exec "${AP_CI_NETNS}" iptables -P FORWARD DROP
sudo ip netns exec "${AP_CI_NETNS}" iptables -P OUTPUT DROP
sudo ip netns exec "${AP_CI_NETNS}" iptables -A INPUT -i lo -j ACCEPT
sudo ip netns exec "${AP_CI_NETNS}" iptables -A OUTPUT -o lo -j ACCEPT
for port in "${ports[@]}"; do
  sudo ip netns exec "${AP_CI_NETNS}" iptables -A INPUT \
    -i "${AP_CI_NS_VETH}" -s "${AP_CI_HOST_ADDR}" -p tcp --dport "${port}" \
    -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
  sudo ip netns exec "${AP_CI_NETNS}" iptables -A OUTPUT \
    -o "${AP_CI_NS_VETH}" -d "${AP_CI_HOST_ADDR}" -p tcp --sport "${port}" \
    -m conntrack --ctstate ESTABLISHED -j ACCEPT
done
if ! ipv4_default_routes="$(sudo ip netns exec "${AP_CI_NETNS}" ip route show default)"; then
  echo "could not inspect isolated IPv4 routes" >&2
  exit 1
fi
if [[ -n "${ipv4_default_routes}" ]]; then
  echo "the isolated sshd namespace unexpectedly has an IPv4 default route" >&2
  exit 1
fi
if ! ipv6_default_routes="$(sudo ip netns exec "${AP_CI_NETNS}" ip -6 route show default)"; then
  echo "could not inspect isolated IPv6 routes" >&2
  exit 1
fi
if [[ -n "${ipv6_default_routes}" ]]; then
  echo "the isolated sshd namespace unexpectedly has an IPv6 default route" >&2
  exit 1
fi

sudo install -d -m 0755 /run/sshd
sudo chown root:root "${AP_CI_DIR}/host-key"
sudo chmod 0600 "${AP_CI_DIR}/host-key"

write_sshd_config() {
  local config="$1"
  local port="$2"
  local pid_file="$3"
  local forwarding="$4"
  local permit_listen="$5"
  local authentication_methods="$6"
  local public_key_authentication="$7"
  local password_authentication="$8"
  {
    printf 'Port %s\n' "${port}"
    printf 'ListenAddress %s\n' "${AP_CI_SSH_ADDR}"
    printf 'HostKey %s\n' "${AP_CI_DIR}/host-key"
    printf 'PidFile %s\n' "${pid_file}"
    printf 'AllowUsers %s\n' "${AP_CI_TEST_USER}"
    printf 'AuthenticationMethods %s\n' "${authentication_methods}"
    printf 'PubkeyAuthentication %s\n' "${public_key_authentication}"
    printf 'PasswordAuthentication %s\n' "${password_authentication}"
    printf 'KbdInteractiveAuthentication no\n'
    printf 'PermitEmptyPasswords no\n'
    printf 'PermitRootLogin no\n'
    printf 'UsePAM no\n'
    printf 'UseDNS no\n'
    printf 'StrictModes yes\n'
    printf 'AllowTcpForwarding %s\n' "${forwarding}"
    printf 'GatewayPorts no\n'
    printf 'PermitListen %s\n' "${permit_listen}"
    printf 'PermitOpen 127.0.0.1:*\n'
    printf 'AllowAgentForwarding no\n'
    printf 'X11Forwarding no\n'
    printf 'PermitTTY no\n'
    printf 'PermitTunnel no\n'
    printf 'PermitUserEnvironment no\n'
    printf 'PermitUserRC no\n'
    printf 'MaxAuthTries 1\n'
    printf 'MaxSessions 0\n'
    printf 'LogLevel VERBOSE\n'
  } > "${config}"
  chmod 0600 "${config}"
  sudo /usr/sbin/sshd -t -f "${config}"
}

write_sshd_config \
  "${AP_CI_DIR}/sshd-probe.conf" \
  "${AP_CI_SSH_PORT}" \
  "${AP_CI_DIR}/sshd-probe.pid" \
  yes '127.0.0.1:*' publickey yes no
write_sshd_config \
  "${AP_CI_DIR}/sshd-no-forwarding.conf" \
  "${AP_CI_FORWARDING_DENIED_SSH_PORT}" \
  "${AP_CI_DIR}/sshd-no-forwarding.pid" \
  no '127.0.0.1:*' publickey yes no
write_sshd_config \
  "${AP_CI_DIR}/sshd-listen-denied.conf" \
  "${AP_CI_LISTEN_DENIED_SSH_PORT}" \
  "${AP_CI_DIR}/sshd-listen-denied.pid" \
  yes "127.0.0.1:${AP_CI_UNUSED_PERMITTED_PORT}" publickey yes no
write_sshd_config \
  "${AP_CI_DIR}/sshd-password-only.conf" \
  "${AP_CI_PASSWORD_SSH_PORT}" \
  "${AP_CI_DIR}/sshd-password-only.pid" \
  yes '127.0.0.1:*' password no yes

sudo /usr/sbin/sshd -T -f "${AP_CI_DIR}/sshd-password-only.conf" \
  | grep -Fqx 'authenticationmethods password'
sudo /usr/sbin/sshd -T -f "${AP_CI_DIR}/sshd-password-only.conf" \
  | grep -Fqx 'pubkeyauthentication no'
sudo /usr/sbin/sshd -T -f "${AP_CI_DIR}/sshd-password-only.conf" \
  | grep -Fqx 'passwordauthentication yes'

start_sshd() {
  local name="$1"
  local config="$2"
  # The runner shell intentionally owns the private log file; sudo is needed
  # only for the namespaced sshd process.
  # shellcheck disable=SC2024
  sudo ip netns exec "${AP_CI_NETNS}" \
    /usr/sbin/sshd -D -e -f "${config}" \
    </dev/null >"${AP_CI_DIR}/sshd-${name}.log" 2>&1 &
  printf '%s\n' "$!" > "${AP_CI_DIR}/sshd-${name}.process"
}

start_sshd probe "${AP_CI_DIR}/sshd-probe.conf"
start_sshd no-forwarding "${AP_CI_DIR}/sshd-no-forwarding.conf"
start_sshd listen-denied "${AP_CI_DIR}/sshd-listen-denied.conf"
start_sshd password-only "${AP_CI_DIR}/sshd-password-only.conf"

ready=false
for _ in {1..150}; do
  processes_alive=true
  for process_file in "${AP_CI_DIR}"/sshd-*.process; do
    if ! sudo kill -0 "$(< "${process_file}")" 2>/dev/null; then
      processes_alive=false
      break
    fi
  done
  if [[ "${processes_alive}" != true ]]; then
    break
  fi
  listeners="$(sudo ip netns exec "${AP_CI_NETNS}" ss -H -ltn 2>/dev/null || true)"
  listeners_ready=true
  for port in "${ports[@]}"; do
    if ! awk -v endpoint="${AP_CI_SSH_ADDR}:${port}" '$4 == endpoint { found = 1 } END { exit !found }' \
      <<< "${listeners}"; then
      listeners_ready=false
      break
    fi
  done
  if [[ "${processes_alive}" == true && "${listeners_ready}" == true ]]; then
    ready=true
    break
  fi
  sleep 0.1
done
if [[ "${ready}" != true ]]; then
  echo "isolated sshd listeners did not become ready" >&2
  for log in "${AP_CI_DIR}"/sshd-*.log; do
    [[ -f "${log}" ]] && sed -n '1,160p' "${log}" >&2
  done
  exit 1
fi
