# Local Network Collector

The Local Network Collector (LNC) is an outbound-only service for approved private networks. It enrolls with Sadapp, receives bounded tasks, validates targets against its allowed CIDRs, and returns results. It does not automatically scan merely because it has been registered.

## Enroll a collector

1. Open **Settings → Local Network Collectors**.
2. Register a collector with a name, site key, and allowed private CIDRs.
3. Copy the one-time enrollment token into the installer prompt on the machine inside that network.
4. Install the Local Network Collector package from `/install` for Debian/Ubuntu or RPM-based Linux.
5. Wait for a heartbeat; verify the collector is active, capabilities are reported, and its applied configuration revision is current.

The `siteKey` groups tasks for collector routing. It is distinct from a Monitoring Worker location.

## Discovery and checks

Discovery probes only explicitly selected ports within allowed private CIDRs. For responsive addresses, the collector also makes a best-effort reverse-DNS lookup; a hostname appears when the local resolver has a PTR record. Missing PTR data does not block discovery, and the IP remains the stable address. It creates candidates; approval or configured auto-add turns a candidate into an inventory resource. A discovered `tcp_service` represents reachability evidence, not a fully monitored host.

Unadopted LAN resources remain in **Discovery**. Open **Configure** on a discovered service to edit its TCP port, queue a one-time check, or adopt it into **Software** with a recurring interval. Adoption queues an initial check and the active collector runs subsequent checks on schedule. Existing TCP and HTTP(S) monitors may also select a linked LNC when it advertises the required `tcp` or `http` capability. DNS, TLS, and ICMP checks remain Worker-routed. Pausing a recurring LNC check returns the service to Discovery. If the IP matches a managed Server, verify that it is the same device and site before linking; private addresses may be reused. Hardware resources expose **Set up Agent** and **Set up SNMP**, which links the existing discovered resource to a managed Server instead of creating a duplicate row.

SNMP profiles selected on a managed Server are used by the Local Network Collector for its configured scalar OIDs. Automatic profile detection currently runs on Monitoring Workers; when SNMP polling is assigned to an LNC, choose the device profile explicitly. Profiles marked **Experimental** are manual-only and may have incomplete coverage. LNC SNMP collection currently does not execute profile table walks or traps.

## Task recovery

Open a collector's activity to inspect recent tasks. A failed discovery can be retried from its task row; retry creates a new task using the saved scan parameters and checks the collector's current CIDR policy.

## Logs and health

```bash
sudo systemctl status sadapp-local-network-collector.service --no-pager
sudo journalctl -u sadapp-local-network-collector.service -n 100 --no-pager
sudo journalctl -u sadapp-local-network-collector.service -f
curl -fsS http://127.0.0.1:9168/health
```

The health listener is loopback-only. It reports heartbeat, task, queue, and spool diagnostics, not secrets or task payloads. The package default is port 9168; container deployments default to 8787.

See [Troubleshooting](../troubleshooting) for expired leases, failed uploads, and stale heartbeats.