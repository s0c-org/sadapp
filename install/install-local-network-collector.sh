#!/usr/bin/env bash
set -euo pipefail

readonly DEB_REPOSITORY_URL="https://deb.sadapp.org"
readonly RPM_REPOSITORY_URL="https://rpm.sadapp.org"
readonly EXPECTED_SIGNING_KEY_FINGERPRINT="2B2333E4F37359BADD4F72A6394AA75F2815A5C3"
readonly CONFIG_FILE="/etc/default/sadapp-local-network-collector"
channel="stable"
enrollment_token=""

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --channel)
      [[ $# -ge 2 ]] || fail '--channel requires a value'
      channel="$2"
      shift 2
      ;;
    --token)
      [[ $# -ge 2 ]] || fail '--token requires a value'
      [[ -z "$enrollment_token" ]] || fail '--token may only be provided once'
      enrollment_token="$2"
      shift 2
      ;;
    *) fail "Unknown option: $1" ;;
  esac
done

[[ "$channel" == stable || "$channel" == canary ]] || fail 'Channel must be stable or canary.'
[[ "$EUID" -eq 0 ]] || fail 'Run with sudo, for example: curl -fsSL https://sadapp.org/install-local-network-collector.sh | sudo bash -s -- --channel stable --token <enrollment-token>'

if [[ -z "$enrollment_token" ]]; then
  [[ -r /dev/tty ]] || fail 'A terminal is required to enter the enrollment token, or pass it with --token.'
  printf 'Enter the one-time enrollment token from SadApp: '
  IFS= read -r -s enrollment_token </dev/tty || fail 'Unable to read enrollment token.'
  printf '\n'
fi
[[ -n "$enrollment_token" ]] || fail 'Enrollment token cannot be empty.'
[[ "$enrollment_token" =~ ^[A-Za-z0-9._~-]+$ ]] || fail 'Enrollment token contains unsupported characters.'

for command_name in curl gpg awk systemctl; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required. Install it and rerun this command."
done

temporary_dir="$(mktemp -d)"
trap 'rm -rf "$temporary_dir"' EXIT
key_file="$temporary_dir/sadapp-archive-keyring.asc"
curl -fsSL "$DEB_REPOSITORY_URL/sadapp-archive-keyring.asc" -o "$key_file"
fingerprint="$(gpg --show-keys --with-colons "$key_file" | awk -F: '$1 == "fpr" { print $10; exit }')"
[[ "$fingerprint" == "$EXPECTED_SIGNING_KEY_FINGERPRINT" ]] || fail 'SadApp package signing key fingerprint did not match.'

if command -v apt-get >/dev/null 2>&1; then
  install -d -m 0755 /usr/share/keyrings
  gpg --dearmor --yes -o /usr/share/keyrings/sadapp-archive-keyring.gpg "$key_file"
  printf 'deb [signed-by=/usr/share/keyrings/sadapp-archive-keyring.gpg] %s %s main\n' "$DEB_REPOSITORY_URL" "$channel" > /etc/apt/sources.list.d/sadapp.list
  apt-get update
  architecture="$(dpkg --print-architecture)"
  candidate="$(apt-cache policy sadapp-local-network-collector | awk '/Candidate:/ { print $2; exit }')"
  [[ -n "$candidate" && "$candidate" != '(none)' ]] || fail "No Local Network Collector package is published for $architecture in the $channel repository."
  DEBIAN_FRONTEND=noninteractive apt-get install -y sadapp-local-network-collector
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  install -d -m 0755 /etc/pki/rpm-gpg
  install -m 0644 "$key_file" /etc/pki/rpm-gpg/sadapp-archive-keyring.asc
  cat > /etc/yum.repos.d/sadapp-local-network-collector.repo <<EOF
[sadapp-local-network-collector]
name=SadApp Local Network Collector
baseurl=$RPM_REPOSITORY_URL/$channel
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/sadapp-archive-keyring.asc
EOF
  if command -v dnf >/dev/null 2>&1; then
    dnf install -y sadapp-local-network-collector
  else
    yum install -y sadapp-local-network-collector
  fi
else
  fail 'Supported systems are Debian/Ubuntu (APT) and Fedora/RHEL (DNF or YUM).'
fi

[[ -f "$CONFIG_FILE" ]] || install -m 0600 /dev/null "$CONFIG_FILE"
chmod 0600 "$CONFIG_FILE"
if grep -q '^ENROLLMENT_TOKEN=' "$CONFIG_FILE"; then
  sed -i "s|^ENROLLMENT_TOKEN=.*|ENROLLMENT_TOKEN=$enrollment_token|" "$CONFIG_FILE"
else
  printf '\nENROLLMENT_TOKEN=%s\n' "$enrollment_token" >> "$CONFIG_FILE"
fi
unset enrollment_token

systemctl daemon-reload
systemctl enable --now sadapp-local-network-collector.service
printf 'Local Network Collector installed and started on the %s channel.\n' "$channel"