#!/bin/sh
set -eu

case "${1:-}" in
  remove|0)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl stop sadapp-local-network-collector.service
      systemctl disable sadapp-local-network-collector.service >/dev/null
    fi
    ;;
esac
