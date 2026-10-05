#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-}"
CHANNEL="${2:-stable}"
AUTO_UPDATE="${3:-}"
EXPECTED_SIGNING_KEY_FINGERPRINT="2B2333E4F37359BADD4F72A6394AA75F2815A5C3"

[[ "${EUID}" -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
[[ -n "${BASE_URL}" ]] || { echo "Usage: $0 BASE_URL [stable|canary] [--enable-auto-update]" >&2; exit 1; }
[[ "${CHANNEL}" == "stable" || "${CHANNEL}" == "canary" ]] || { echo "Invalid channel" >&2; exit 1; }

for command_name in curl gpg apt-get; do
  command -v "${command_name}" >/dev/null 2>&1 || { echo "${command_name} is required" >&2; exit 1; }
done

install -d -m 0755 /usr/share/keyrings
key_file="$(mktemp)"
trap 'rm -f "${key_file}"' EXIT
curl -fsSL "${BASE_URL%/}/sadapp-archive-keyring.asc" -o "${key_file}"
actual_fingerprint="$(gpg --show-keys --with-colons "${key_file}" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')"
[[ "${actual_fingerprint}" == "${EXPECTED_SIGNING_KEY_FINGERPRINT}" ]] || { echo "Repository signing key fingerprint mismatch" >&2; exit 1; }
gpg --dearmor --yes -o /usr/share/keyrings/sadapp-archive-keyring.gpg "${key_file}"

if [[ -n "${REPOSITORY_USERNAME:-}" && -n "${REPOSITORY_PASSWORD:-}" ]]; then
  install -d -m 0700 /etc/apt/auth.conf.d
  host="$(printf '%s' "${BASE_URL}" | sed -E 's#^https?://([^/]+).*#\1#')"
  printf 'machine %s login %s password %s\n' "${host}" "${REPOSITORY_USERNAME}" "${REPOSITORY_PASSWORD}" \
    > /etc/apt/auth.conf.d/sadapp.conf
  chmod 0600 /etc/apt/auth.conf.d/sadapp.conf
fi

printf 'deb [signed-by=/usr/share/keyrings/sadapp-archive-keyring.gpg] %s %s main\n' \
  "${BASE_URL%/}" "${CHANNEL}" > /etc/apt/sources.list.d/sadapp.list
apt-get update
apt-get install -y sadapp-host-agent

if grep -q '^API_UPDATE_CHANNEL=' /etc/default/sadapp-host-agent; then
  sed -i "s/^API_UPDATE_CHANNEL=.*/API_UPDATE_CHANNEL=${CHANNEL}/" /etc/default/sadapp-host-agent
else
  printf 'API_UPDATE_CHANNEL=%s\n' "${CHANNEL}" >> /etc/default/sadapp-host-agent
fi

if [[ "${AUTO_UPDATE}" == "--enable-auto-update" ]]; then
  apt-get install -y unattended-upgrades
  cat > /etc/apt/apt.conf.d/52sadapp-host-agent <<EOF
Unattended-Upgrade::Origins-Pattern {
  "origin=SadApp,codename=${CHANNEL}";
};
Unattended-Upgrade::Package-Blacklist {};
EOF
  systemctl enable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
fi

echo "SadApp APT ${CHANNEL} channel configured"