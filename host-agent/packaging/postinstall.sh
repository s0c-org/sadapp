#!/bin/sh
set -eu

install -d -m 0700 /var/lib/sadapp-host-agent

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable sadapp-host-agent.service >/dev/null
  if systemctl is-active --quiet sadapp-host-agent.service; then
    systemctl restart sadapp-host-agent.service
  elif [ -n "${2:-}" ] || { [ "${1:-}" -eq "${1:-}" ] 2>/dev/null && [ "${1:-0}" -gt 1 ]; }; then
    systemctl start sadapp-host-agent.service
  fi
fi