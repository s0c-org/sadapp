#!/usr/bin/env bash
set -euo pipefail

# Build a compatibility-focused Linux binary for a destination machine architecture.
#
# Supported targets and aliases:
#   x86_64-unknown-linux-musl      (default)
#   archx64, x64, amd64            -> x86_64-unknown-linux-musl
#   aarch64-unknown-linux-musl
#   arm64, aarch64                 -> aarch64-unknown-linux-musl
#   armv7-unknown-linux-musleabihf
#   armv7, armhf                   -> armv7-unknown-linux-musleabihf
#   aarch64-unknown-linux-gnu
#   armv7-unknown-linux-gnueabihf
#
# musl targets avoid glibc runtime symbol/version constraints.

TARGET_INPUT="${1:-x86_64-unknown-linux-musl}"
case "${TARGET_INPUT}" in
  archx64|x64|amd64)
    TARGET="x86_64-unknown-linux-musl"
    ;;
  arm64|aarch64)
    TARGET="aarch64-unknown-linux-musl"
    ;;
  armv7|armhf)
    TARGET="armv7-unknown-linux-musleabihf"
    ;;
  *)
    TARGET="${TARGET_INPUT}"
    ;;
esac

OUT="target/${TARGET}/release/sadapp-host-agent"

command -v rustup >/dev/null 2>&1 || {
  echo "rustup is required" >&2
  exit 1
}

CC_ENV=""

case "${TARGET}" in
  x86_64-unknown-linux-musl)
    command -v musl-gcc >/dev/null 2>&1 || {
      echo "musl-gcc is required (Debian/Ubuntu: sudo apt install musl-tools)" >&2
      exit 1
    }
    CC_ENV="CC_x86_64_unknown_linux_musl=musl-gcc"
    ;;
  aarch64-unknown-linux-musl)
    command -v aarch64-linux-musl-gcc >/dev/null 2>&1 || {
      echo "aarch64-linux-musl-gcc is required for ${TARGET}" >&2
      exit 1
    }
    CC_ENV="CC_aarch64_unknown_linux_musl=aarch64-linux-musl-gcc"
    ;;
  armv7-unknown-linux-musleabihf)
    command -v arm-linux-musleabihf-gcc >/dev/null 2>&1 || {
      echo "arm-linux-musleabihf-gcc is required for ${TARGET}" >&2
      exit 1
    }
    CC_ENV="CC_armv7_unknown_linux_musleabihf=arm-linux-musleabihf-gcc"
    ;;
  aarch64-unknown-linux-gnu)
    command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 || {
      echo "aarch64-linux-gnu-gcc is required (Debian/Ubuntu: sudo apt install gcc-aarch64-linux-gnu)" >&2
      exit 1
    }
    ;;
  armv7-unknown-linux-gnueabihf)
    command -v arm-linux-gnueabihf-gcc >/dev/null 2>&1 || {
      echo "arm-linux-gnueabihf-gcc is required (Debian/Ubuntu: sudo apt install gcc-arm-linux-gnueabihf)" >&2
      exit 1
    }
    ;;
  *)
    echo "Unsupported target: ${TARGET}" >&2
    echo "Supported aliases: archx64|x64|amd64, arm64|aarch64, armv7|armhf" >&2
    echo "Supported triples: x86_64-unknown-linux-musl, aarch64-unknown-linux-musl, armv7-unknown-linux-musleabihf, aarch64-unknown-linux-gnu, armv7-unknown-linux-gnueabihf" >&2
    exit 1
    ;;
esac

rustup target add "${TARGET}"

# reqwest is configured for rustls, so this build is OpenSSL-free.
if [[ -n "${CC_ENV}" ]]; then
  env ${CC_ENV} cargo build --release --target "${TARGET}"
else
  cargo build --release --target "${TARGET}"
fi

echo
if command -v file >/dev/null 2>&1; then
  file "${OUT}" || true
fi

if command -v ldd >/dev/null 2>&1; then
  # Static musl binaries should print: "not a dynamic executable".
  ldd "${OUT}" || true
fi

echo "Built: ${OUT}"
