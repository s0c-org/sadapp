#!/bin/sh
set -eu

install -d -m 0700 /var/lib/sadapp-local-network-collector

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable sadapp-local-network-collector.service >/dev/null
  if systemctl is-active --quiet sadapp-local-network-collector.service; then
    systemctl restart sadapp-local-network-collector.service
  fi
fi