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

SNMP profiles selected on a managed Server are used by the Local Network Collector for their configured scalar OIDs. With the device profile set to **Auto**, the control plane periodically sends profile detection signatures with a collection task. The collector probes the standard SNMP `sysObjectID` and `sysDescr` identity scalars and reports the match; the control plane stores it for the next poll. Detection runs when no result exists, at least six hours have elapsed, the detection registry changes, or re-detection is requested. The poll that performs detection still uses the previously effective profile. If a successful identity probe is ambiguous or no enabled profile meets its confidence threshold, the effective profile falls back to `generic-host`. If the identity probe is unavailable, the last effective profile is retained; on first detection this is normally `generic-host`.

Profiles marked **Experimental** can be selected manually, but are not considered for automatic matching. Their vendor-specific scalar mappings are available for testing; marking a profile experimental does not guarantee complete or verified device coverage. LNC poll plans use profile scalar OIDs only; vendor-specific profile table definitions and traps are not collected. If a selected profile has no numeric scalar OIDs supported by the LNC, it polls the `generic-host` scalar plan instead; the configured profile remains visible in the task metadata. The collector may separately aggregate standard Host-Resources CPU, memory, and fixed-disk metrics using its bounded built-in walks.

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