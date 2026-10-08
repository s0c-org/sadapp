#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT_DIR}"

CHANNEL="${CHANNEL:-stable}"
TARGET="${TARGET:-}"
ITERATION="${ITERATION:-1}"

if [[ -z "${TARGET}" ]]; then
  case "$(uname -m)" in
    x86_64|amd64)
      TARGET="x86_64-unknown-linux-musl"
      ;;
    aarch64|arm64)
      TARGET="aarch64-unknown-linux-musl"
      ;;
    armv7*|armhf)
      TARGET="armv7-unknown-linux-musleabihf"
      ;;
    *)
      echo "Unsupported package architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
fi

if [[ "${CHANNEL}" != "stable" && "${CHANNEL}" != "canary" ]]; then
  echo "CHANNEL must be stable or canary" >&2
  exit 1
fi

for command_name in cargo nfpm rustup; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    echo "${command_name} is required" >&2
    exit 1
  }
done

# Prebuilt binaries are only packaged, so no cross linker is needed.
[[ -n "${PREBUILT_BINARY:-}" ]] || case "${TARGET}" in
  x86_64-unknown-linux-musl)
    command -v musl-gcc >/dev/null 2>&1 || {
      echo "musl-gcc is required (Debian/Ubuntu: sudo apt install musl-tools)" >&2
      exit 1
    }
    ;;
  aarch64-unknown-linux-musl)
    command -v aarch64-linux-musl-gcc >/dev/null 2>&1 || {
      echo "aarch64-linux-musl-gcc is required for ${TARGET}" >&2
      exit 1
    }
    ;;
  armv7-unknown-linux-musleabihf)
    command -v arm-linux-musleabihf-gcc >/dev/null 2>&1 || {
      echo "arm-linux-musleabihf-gcc is required for ${TARGET}" >&2
      exit 1
    }
    ;;
  armv7-unknown-linux-gnueabihf)
    command -v arm-linux-gnueabihf-gcc >/dev/null 2>&1 || {
      echo "arm-linux-gnueabihf-gcc is required for ${TARGET}" >&2
      exit 1
    }
    ;;
esac

VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)"
[[ -n "${VERSION}" ]] || { echo "Unable to read package version" >&2; exit 1; }
[[ "${VERSION}" =~ ^[0-9A-Za-z.+~-]+$ ]] || { echo "Unsupported package version: ${VERSION}" >&2; exit 1; }
[[ "${ITERATION}" =~ ^[0-9A-Za-z.+~]+$ ]] || { echo "Unsupported package iteration: ${ITERATION}" >&2; exit 1; }

if [[ "${CHANNEL}" == "canary" ]]; then
  PACKAGE_RELEASE="${ITERATION}.canary"
else
  PACKAGE_RELEASE="${ITERATION}"
fi
AGENT_VERSION="${VERSION}-${PACKAGE_RELEASE}"

if [[ -n "${PREBUILT_BINARY:-}" ]]; then
  BINARY="${PREBUILT_BINARY}"
  MACHINE="${TARGET%%-*}"
elif [[ -n "${TARGET}" ]]; then
  rustup target add "${TARGET}" >/dev/null
  SADAPP_AGENT_VERSION="${AGENT_VERSION}" cargo build --locked --release --target "${TARGET}"
  BINARY="target/${TARGET}/release/sadapp-host-agent"
  MACHINE="${TARGET%%-*}"
else
  SADAPP_AGENT_VERSION="${AGENT_VERSION}" cargo build --locked --release
  BINARY="target/release/sadapp-host-agent"
  MACHINE="$(uname -m)"
fi

case "${MACHINE}" in
  x86_64|amd64)
    NFPM_ARCH="amd64"
    DEB_ARCH="amd64"
    RPM_ARCH="x86_64"
    ;;
  aarch64|arm64)
    NFPM_ARCH="arm64"
    DEB_ARCH="arm64"
    RPM_ARCH="aarch64"
    ;;
  armv7*|armhf)
    NFPM_ARCH="armhf"
    DEB_ARCH="armhf"
    RPM_ARCH="armv7hl"
    ;;
  *)
    echo "Unsupported package architecture: ${MACHINE}" >&2
    exit 1
    ;;
esac

[[ -x "${BINARY}" ]] || { echo "Built binary is missing: ${BINARY}" >&2; exit 1; }

if [[ "${TARGET}" == *-linux-musl ]]; then
  command -v readelf >/dev/null 2>&1 || {
    echo "readelf is required to verify static package binaries" >&2
    exit 1
  }
  if readelf --program-headers "${BINARY}" | grep -q 'Requesting program interpreter'; then
    echo "Refusing to package a dynamically linked musl target: ${BINARY}" >&2
    exit 1
  fi
fi

OUTPUT_DIR="dist/${CHANNEL}"
STAGING_DIR="dist/.package-root"
mkdir -p "${OUTPUT_DIR}" "${STAGING_DIR}"
install -m 0755 "${BINARY}" "${STAGING_DIR}/sadapp-host-agent"

NFPM_CONFIG="$(mktemp)"
trap 'rm -f "${NFPM_CONFIG}"' EXIT
sed \
  -e "s/__NFPM_ARCH__/${NFPM_ARCH}/g" \
  -e "s/__NFPM_VERSION__/${VERSION}/g" \
  -e "s/__NFPM_RELEASE__/${PACKAGE_RELEASE}/g" \
  packaging/nfpm.yaml > "${NFPM_CONFIG}"

nfpm package \
  --config "${NFPM_CONFIG}" \
  --packager deb \
  --target "${OUTPUT_DIR}/sadapp-host-agent_${VERSION}-${PACKAGE_RELEASE}_${DEB_ARCH}.deb"
nfpm package \
  --config "${NFPM_CONFIG}" \
  --packager rpm \
  --target "${OUTPUT_DIR}/sadapp-host-agent-${VERSION}-${PACKAGE_RELEASE}.${RPM_ARCH}.rpm"

echo "Packages created in ${OUTPUT_DIR}"