# Troubleshooting

Start with the resource's last-seen time and source tags, then inspect the corresponding Agent, Monitoring Worker, or Local Network Collector status.

## Missing or `n/a` metrics

`n/a` means the source did not provide a valid sample for that metric. Confirm the device supports the counter, the correct source is enabled, and a recent poll completed. SNMP profiles cannot read vendor OIDs that the device does not expose. Do not treat missing data as zero.

## Local Network Collector tasks

```bash
sudo systemctl status sadapp-local-network-collector.service --no-pager
sudo journalctl -u sadapp-local-network-collector.service -n 100 --no-pager
sudo journalctl -u sadapp-local-network-collector.service -f
curl -fsS http://127.0.0.1:9168/health
```

The health endpoint is loopback-only. Check heartbeat freshness, applied configuration revision, task counters, and spool queue size. Confirm the collector's allowed CIDRs contain the target and the required capability is reported.

## Expired task lease

The control plane renews leases for tasks reported as running. A result that arrives after its lease was replaced is stale and is discarded; it cannot be attached to the newer attempt. Failed discovery tasks can be retried from collector task history, creating a new task with the saved scan parameters.

## Agent or SNMP not updating

- For Agent: inspect `sudo journalctl -u sadapp-host-agent.service -n 100 --no-pager`, then verify the server's Agent credential and last-seen time.
- For SNMP: verify v1/v2c community or v3 credentials, UDP port, target address, profile, and poller reachability.
- For worker checks: verify the assigned location is covered by an active worker.
- For LAN tasks: verify the LNC is active and the resource address remains inside its allowed CIDR.

When contacting support, include timestamps, task IDs, sanitized error messages, and version numbers. Never include community strings, passphrases, invitation tokens, or private key material.