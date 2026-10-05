#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-}"
CHANNEL="${2:-stable}"
AUTO_UPDATE="${3:-}"
EXPECTED_SIGNING_KEY_FINGERPRINT="2B2333E4F37359BADD4F72A6394AA75F2815A5C3"

[[ "${EUID}" -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
[[ -n "${BASE_URL}" ]] || { echo "Usage: $0 BASE_URL [stable|canary] [--enable-auto-update]" >&2; exit 1; }
[[ "${CHANNEL}" == "stable" || "${CHANNEL}" == "canary" ]] || { echo "Invalid channel" >&2; exit 1; }

DNF="$(command -v dnf || command -v yum || true)"
[[ -n "${DNF}" ]] || { echo "dnf or yum is required" >&2; exit 1; }
for command_name in curl gpg; do
  command -v "${command_name}" >/dev/null 2>&1 || { echo "${command_name} is required" >&2; exit 1; }
done

key_file="$(mktemp)"
trap 'rm -f "${key_file}"' EXIT
curl -fsSL "${BASE_URL%/}/sadapp-archive-keyring.asc" -o "${key_file}"
actual_fingerprint="$(gpg --show-keys --with-colons "${key_file}" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')"
[[ "${actual_fingerprint}" == "${EXPECTED_SIGNING_KEY_FINGERPRINT}" ]] || { echo "Repository signing key fingerprint mismatch" >&2; exit 1; }

credentials=""
if [[ -n "${REPOSITORY_USERNAME:-}" && -n "${REPOSITORY_PASSWORD:-}" ]]; then
  credentials="username=${REPOSITORY_USERNAME}
password=${REPOSITORY_PASSWORD}"
fi

cat > /etc/yum.repos.d/sadapp.repo <<EOF
[sadapp-${CHANNEL}]
name=SadApp Host Agent (${CHANNEL})
baseurl=${BASE_URL%/}/${CHANNEL}
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=${BASE_URL%/}/sadapp-archive-keyring.asc
${credentials}
EOF

"${DNF}" -y install sadapp-host-agent

if grep -q '^API_UPDATE_CHANNEL=' /etc/default/sadapp-host-agent; then
  sed -i "s/^API_UPDATE_CHANNEL=.*/API_UPDATE_CHANNEL=${CHANNEL}/" /etc/default/sadapp-host-agent
else
  printf 'API_UPDATE_CHANNEL=%s\n' "${CHANNEL}" >> /etc/default/sadapp-host-agent
fi

if [[ "${AUTO_UPDATE}" == "--enable-auto-update" ]]; then
  "${DNF}" -y install dnf-automatic
  sed -i 's/^upgrade_type.*/upgrade_type = default/' /etc/dnf/automatic.conf
  sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
  systemctl enable --now dnf-automatic.timer
fi

echo "SadApp RPM ${CHANNEL} channel configured"