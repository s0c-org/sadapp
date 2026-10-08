#!/bin/sh
set -eu

case "${1:-}" in
  remove|0)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl stop sadapp-host-agent.service
      systemctl disable sadapp-host-agent.service >/dev/null
    fi
    ;;
esac
