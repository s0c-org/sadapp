#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT_DIR}"

CHANNEL="${CHANNEL:-stable}"
TARGET="${TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
ITERATION="${ITERATION:-1}"

for command_name in cargo nfpm rustc; do
  command -v "${command_name}" >/dev/null 2>&1 || { echo "${command_name} is required" >&2; exit 1; }
done
[[ "${CHANNEL}" == "stable" || "${CHANNEL}" == "canary" ]] || { echo "CHANNEL must be stable or canary" >&2; exit 1; }

VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)"
RELEASE="${ITERATION}"
[[ "${CHANNEL}" == "canary" ]] && RELEASE="${ITERATION}.canary"

if [[ -n "${PREBUILT_BINARY:-}" ]]; then
  BINARY="${PREBUILT_BINARY}"
else
  cargo build --locked --release --target "${TARGET}"
  BINARY="target/${TARGET}/release/sadapp-local-network-collector"
fi
[[ -x "${BINARY}" ]] || { echo "Built binary is missing: ${BINARY}" >&2; exit 1; }

case "${TARGET%%-*}" in
  x86_64) NFPM_ARCH=amd64; DEB_ARCH=amd64; RPM_ARCH=x86_64 ;;
  aarch64) NFPM_ARCH=arm64; DEB_ARCH=arm64; RPM_ARCH=aarch64 ;;
  armv7*) NFPM_ARCH=armhf; DEB_ARCH=armhf; RPM_ARCH=armv7hl ;;
  *) echo "Unsupported package target: ${TARGET}" >&2; exit 1 ;;
esac

if [[ "${TARGET}" == *-linux-musl* ]]; then
  command -v readelf >/dev/null 2>&1 || { echo "readelf is required to verify static binaries" >&2; exit 1; }
  if readelf --program-headers "${BINARY}" | grep -q 'Requesting program interpreter'; then
    echo "Refusing to package a dynamically linked musl binary: ${BINARY}" >&2
    exit 1
  fi
fi

OUTPUT_DIR="dist/${CHANNEL}"
mkdir -p "${OUTPUT_DIR}" dist/.package-root
install -m 0755 "${BINARY}" dist/.package-root/sadapp-local-network-collector
NFPM_CONFIG="$(mktemp)"
trap 'rm -f "${NFPM_CONFIG}"' EXIT
sed -e "s/__NFPM_ARCH__/${NFPM_ARCH}/g" -e "s/__RPM_ARCH__/${RPM_ARCH}/g" -e "s/__NFPM_VERSION__/${VERSION}/g" -e "s/__NFPM_RELEASE__/${RELEASE}/g" packaging/nfpm.yaml > "${NFPM_CONFIG}"
nfpm package --config "${NFPM_CONFIG}" --packager deb --target "${OUTPUT_DIR}/sadapp-local-network-collector_${VERSION}-${RELEASE}_${DEB_ARCH}.deb"
nfpm package --config "${NFPM_CONFIG}" --packager rpm --target "${OUTPUT_DIR}/sadapp-local-network-collector-${VERSION}-${RELEASE}.${RPM_ARCH}.rpm"