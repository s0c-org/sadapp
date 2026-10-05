#!/bin/sh
set -eu

DEB_REPOSITORY_URL="https://deb.sadapp.org"
RPM_REPOSITORY_URL="https://rpm.sadapp.org"
EXPECTED_SIGNING_KEY_FINGERPRINT="2B2333E4F37359BADD4F72A6394AA75F2815A5C3"
CHANNEL="stable"
INVITE_TOKEN=""
ACTION="install"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  ESC="$(printf '\033')"
  BOLD="${ESC}[1m"
  CYAN="${ESC}[36m"
  GREEN="${ESC}[32m"
  YELLOW="${ESC}[33m"
  RED="${ESC}[31m"
  RESET="${ESC}[0m"
else
  BOLD=''
  CYAN=''
  GREEN=''
  YELLOW=''
  RED=''
  RESET=''
fi

success() {
  printf '%sOK%s %s\n' "${GREEN}" "${RESET}" "$1"
}

fail() {
  printf '%sERROR%s %s\n' "${RED}" "${RESET}" "$1" >&2
  exit 1
}

show_header() {
  printf '\n%s+----------------------------------------------------------+%s\n' "${CYAN}" "${RESET}"
  printf '%s|%s  %sSadApp Host Agent Installer%s                         %s|%s\n' "${CYAN}" "${RESET}" "${BOLD}" "${RESET}" "${CYAN}" "${RESET}"
  printf '%s+----------------------------------------------------------+%s\n\n' "${CYAN}" "${RESET}"
}

show_step() {
  printf '\n%s[%s/%s]%s %s%s%s\n' "${CYAN}" "$1" "$2" "${RESET}" "${BOLD}" "$3" "${RESET}"
}

confirm_changes() {
  prompt="$1"
  if ! exec 3<> /dev/tty; then
    fail "Interactive consent is required. Run this command from a terminal."
  fi
  printf '\n%s%s [y/N] %s' "${BOLD}" "${prompt}" "${RESET}" >&3
  IFS= read -r consent <&3 || consent=""
  exec 3>&-
  case "${consent}" in
    y|Y|yes|YES|Yes) ;;
    *)
      printf '\n%sCancelled. No changes were made.%s\n' "${YELLOW}" "${RESET}"
      exit 0
      ;;
  esac
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --token)
      [ "$#" -ge 2 ] || fail "--token requires a value"
      INVITE_TOKEN="$2"
      shift 2
      ;;
    --channel)
      [ "$#" -ge 2 ] || fail "--channel requires a value"
      CHANNEL="$2"
      shift 2
      ;;
    --uninstall)
      ACTION="uninstall"
      shift
      ;;
    *)
      fail "Unknown argument: $1"
      ;;
  esac
done

show_header

[ "$(id -u)" -eq 0 ] || fail "Run this installer as root (use sudo)."
case "${CHANNEL}" in
  stable|canary) ;;
  *) fail "Channel must be stable or canary." ;;
esac
command -v systemctl >/dev/null 2>&1 || fail "systemd is required."

if [ "${ACTION}" = "install" ]; then
  case "${INVITE_TOKEN}" in
    ""|*[!A-Za-z0-9._~-]*) fail "Invalid invitation token." ;;
  esac
fi

MISSING_PACKAGES=""
INSTALLED_VERSION="not installed"

if command -v apt-get >/dev/null 2>&1; then
  PLATFORM="Debian / Ubuntu"
  PACKAGE_MANAGER="apt"
  REPOSITORY_URL="${DEB_REPOSITORY_URL}"
  for package_check in "ca-certificates:update-ca-certificates" "curl:curl" "gnupg:gpg"; do
    package_name=${package_check%%:*}
    command_name=${package_check#*:}
    if ! command -v "${command_name}" >/dev/null 2>&1; then
      MISSING_PACKAGES="${MISSING_PACKAGES}${MISSING_PACKAGES:+ }${package_name}"
    fi
  done
  if command -v dpkg-query >/dev/null 2>&1; then
    current_version="$(dpkg-query -W -f='${Version}' sadapp-host-agent 2>/dev/null || true)"
    [ -z "${current_version}" ] || INSTALLED_VERSION="${current_version}"
  fi
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  PLATFORM="Fedora / RHEL"
  PACKAGE_MANAGER="$(command -v dnf || command -v yum)"
  REPOSITORY_URL="${RPM_REPOSITORY_URL}/${CHANNEL}"
  for package_check in "ca-certificates:update-ca-trust" "curl:curl" "gnupg2:gpg"; do
    package_name=${package_check%%:*}
    command_name=${package_check#*:}
    if ! command -v "${command_name}" >/dev/null 2>&1; then
      MISSING_PACKAGES="${MISSING_PACKAGES}${MISSING_PACKAGES:+ }${package_name}"
    fi
  done
  if command -v rpm >/dev/null 2>&1; then
    current_version="$(rpm -q --qf '%{VERSION}-%{RELEASE}' sadapp-host-agent 2>/dev/null || true)"
    [ -z "${current_version}" ] || INSTALLED_VERSION="${current_version}"
  fi
else
  fail "Unsupported Linux distribution: apt-get, dnf, or yum is required."
fi

if [ "${ACTION}" = "uninstall" ]; then
  printf '%sUninstallation plan%s\n' "${BOLD}" "${RESET}"
  printf '  %-18s %s\n' 'Platform' "${PLATFORM}"
  printf '  %-18s %s\n' 'Agent status' "${INSTALLED_VERSION}"
  printf '\n%sChanges requiring approval%s\n' "${BOLD}" "${RESET}"
  printf '  1. Stop and disable sadapp-host-agent.service.\n'
  printf '  2. Remove the sadapp-host-agent package.\n'
  printf '  3. Remove /etc/default/sadapp-host-agent.\n'
  if [ "${PACKAGE_MANAGER}" = "apt" ]; then
    printf '  4. Remove the SadApp APT source and signing key.\n'
  else
    printf '  4. Remove the SadApp RPM repository configuration.\n'
  fi
  printf '  5. Reload systemd configuration.\n'
  printf '\n%sThe downloaded installer file will remain available.%s\n' "${YELLOW}" "${RESET}"
  printf '%sNo system changes have been made yet.%s\n' "${YELLOW}" "${RESET}"
  confirm_changes "Proceed with uninstall?"

  show_step 1 5 "Stop and disable the service"
  systemctl disable --now sadapp-host-agent.service 2>/dev/null || true

  show_step 2 5 "Remove SadApp Host Agent"
  if [ "${PACKAGE_MANAGER}" = "apt" ]; then
    apt-get remove -y sadapp-host-agent
  else
    "${PACKAGE_MANAGER}" -y remove sadapp-host-agent
  fi

  show_step 3 5 "Remove agent configuration"
  rm -f /etc/default/sadapp-host-agent

  show_step 4 5 "Remove package repository configuration"
  if [ "${PACKAGE_MANAGER}" = "apt" ]; then
    rm -f /etc/apt/sources.list.d/sadapp.list
    rm -f /usr/share/keyrings/sadapp-archive-keyring.gpg
  else
    rm -f /etc/yum.repos.d/sadapp.repo
  fi

  show_step 5 5 "Reload systemd configuration"
  systemctl daemon-reload

  printf '\n%s+----------------------------------------------------------+%s\n' "${GREEN}" "${RESET}"
  printf '%s|%s  %sUninstall complete%s                                  %s|%s\n' "${GREEN}" "${RESET}" "${BOLD}" "${RESET}" "${GREEN}" "${RESET}"
  printf '%s+----------------------------------------------------------+%s\n' "${GREEN}" "${RESET}"
  printf '  Installer: retained in the directory where you downloaded it.\n\n'
  exit 0
fi

printf '%sInstallation plan%s\n' "${BOLD}" "${RESET}"
printf '  %-18s %s\n' 'Platform' "${PLATFORM}"
printf '  %-18s %s\n' 'Channel' "${CHANNEL}"
printf '  %-18s %s\n' 'Repository' "${REPOSITORY_URL}"
printf '  %-18s %s\n' 'Agent status' "${INSTALLED_VERSION}"
if [ -n "${MISSING_PACKAGES}" ]; then
  printf '  %-18s %s\n' 'Prerequisites' "${MISSING_PACKAGES}"
else
  printf '  %-18s %s\n' 'Prerequisites' 'already installed'
fi

printf '\n%sChanges requiring approval%s\n' "${BOLD}" "${RESET}"
printf '  1. Refresh package metadata.\n'
if [ -n "${MISSING_PACKAGES}" ]; then
  printf '  2. Install prerequisites: %s.\n' "${MISSING_PACKAGES}"
else
  printf '  2. Keep existing prerequisites unchanged.\n'
fi
printf '  3. Trust the SadApp signing key and configure the repository.\n'
printf '  4. Install or update sadapp-host-agent to the latest %s release.\n' "${CHANNEL}"
printf '  5. Store the invitation token in /etc/default/sadapp-host-agent.\n'
printf '  6. Enable and start sadapp-host-agent.service.\n'
printf '\n%sNo system changes have been made yet.%s\n' "${YELLOW}" "${RESET}"
confirm_changes "Proceed with these changes?"

if [ "${PACKAGE_MANAGER}" = "apt" ]; then
  show_step 1 6 "Refresh system package metadata"
  apt-get update

  show_step 2 6 "Install required package tools"
  if [ -n "${MISSING_PACKAGES}" ]; then
    # shellcheck disable=SC2086
    apt-get install -y ${MISSING_PACKAGES}
  else
    success "Required package tools are already installed."
  fi

  show_step 3 6 "Configure the signed SadApp APT repository"
  install -d -m 0755 /usr/share/keyrings
  key_file="$(mktemp)"
  trap 'rm -f "${key_file}"' EXIT
  curl -fsSL "${DEB_REPOSITORY_URL}/sadapp-archive-keyring.asc" -o "${key_file}"
  actual_fingerprint="$(gpg --show-keys --with-colons "${key_file}" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')"
  [ "${actual_fingerprint}" = "${EXPECTED_SIGNING_KEY_FINGERPRINT}" ] || fail "Repository signing key fingerprint mismatch."
  gpg --dearmor --yes -o /usr/share/keyrings/sadapp-archive-keyring.gpg "${key_file}"
  printf 'deb [signed-by=/usr/share/keyrings/sadapp-archive-keyring.gpg] %s %s main\n' \
    "${DEB_REPOSITORY_URL}" "${CHANNEL}" > /etc/apt/sources.list.d/sadapp.list

  show_step 4 6 "Install or update SadApp Host Agent"
  apt-get update
  candidate_version="$(apt-cache policy sadapp-host-agent 2>/dev/null | sed -n 's/^[[:space:]]*Candidate:[[:space:]]*//p' | head -n 1)"
  printf '  Current:   %s\n' "${INSTALLED_VERSION}"
  printf '  Candidate: %s\n' "${candidate_version:-unavailable}"
  apt-get install -y sadapp-host-agent
else
  show_step 1 6 "Install required package tools"
  if [ -n "${MISSING_PACKAGES}" ]; then
    # shellcheck disable=SC2086
    "${PACKAGE_MANAGER}" -y install ${MISSING_PACKAGES}
  else
    success "Required package tools are already installed."
  fi

  show_step 2 6 "Verify signing key and configure the SadApp RPM repository"
  install -d -m 0755 /etc/yum.repos.d
  key_file="$(mktemp)"
  trap 'rm -f "${key_file}"' EXIT
  curl -fsSL "${RPM_REPOSITORY_URL}/sadapp-archive-keyring.asc" -o "${key_file}"
  actual_fingerprint="$(gpg --show-keys --with-colons "${key_file}" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')"
  [ "${actual_fingerprint}" = "${EXPECTED_SIGNING_KEY_FINGERPRINT}" ] || fail "Repository signing key fingerprint mismatch."
  cat > /etc/yum.repos.d/sadapp.repo <<EOF
[sadapp-${CHANNEL}]
name=SadApp Host Agent (${CHANNEL})
baseurl=${RPM_REPOSITORY_URL}/${CHANNEL}
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=${RPM_REPOSITORY_URL}/sadapp-archive-keyring.asc
EOF
  success "Repository configured with package and metadata signature checks."

  show_step 3 6 "Refresh signed repository metadata"
  "${PACKAGE_MANAGER}" -y makecache

  show_step 4 6 "Install or update SadApp Host Agent"
  printf '  Current: %s\n' "${INSTALLED_VERSION}"
  "${PACKAGE_MANAGER}" -q info sadapp-host-agent || true
  "${PACKAGE_MANAGER}" -y install sadapp-host-agent
fi

show_step 5 6 "Configure invitation credentials"
CONFIG_FILE="/etc/default/sadapp-host-agent"
touch "${CONFIG_FILE}"
sed -i '/^API_INVITE_TOKEN=/d' "${CONFIG_FILE}"
printf 'API_INVITE_TOKEN=%s\n' "${INVITE_TOKEN}" >> "${CONFIG_FILE}"
chmod 0600 "${CONFIG_FILE}"
success "Invitation token stored with root-only permissions."

show_step 6 6 "Enable and start the service"
systemctl daemon-reload
systemctl enable --now sadapp-host-agent.service

printf '\n%s+----------------------------------------------------------+%s\n' "${GREEN}" "${RESET}"
printf '%s|%s  %sInstallation complete%s                               %s|%s\n' "${GREEN}" "${RESET}" "${BOLD}" "${RESET}" "${GREEN}" "${RESET}"
printf '%s+----------------------------------------------------------+%s\n' "${GREEN}" "${RESET}"
printf '  Channel: %s\n' "${CHANNEL}"
printf '  Service: sadapp-host-agent.service (enabled and running)\n'
printf '  Uninstall: sudo sh install-agent.sh --uninstall\n'
printf '  Logs:      journalctl -u sadapp-host-agent -f\n\n'