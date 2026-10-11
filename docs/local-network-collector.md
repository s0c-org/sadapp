# Local Network Collector

The Local Network Collector (LNC) is an outbound-only service for approved private networks. It enrolls with Sadapp, receives bounded tasks, validates targets against its allowed CIDRs, and returns results. It does not automatically scan merely because it has been registered.

## Enroll a collector

1. Open **Settings → Local Network Collectors**.
2. Register a collector with a name, site key, and allowed private CIDRs.
3. Copy the one-time enrollment token into the installer prompt on the machine inside that network.
4. Install the Local Network Collector package from `/install` for Debian/Ubuntu or RPM-based Linux.
5. Wait for a heartbeat; verify the collector is active, capabilities are reported, and its applied configuration revision is current.

The `siteKey` groups tasks for collector routing. It is distinct from a Monitoring Worker location.

### Package availability on localized systems

The installer reads APT package policy in the C locale so the candidate check works
regardless of the system language. Older installers may incorrectly report
`No Local Network Collector package is published` on German-language systems,
where APT prints `Installationskandidat:` instead of `Candidate:`.
Download the updated installer, or run it with `LC_ALL=C` set on the installer
process. To check availability independently:

```bash
sudo env LC_ALL=C apt-cache policy sadapp-local-network-collector
```

If this still shows `Candidate: (none)`, the selected repository channel has no
installable candidate for that machine; do not bypass the package check.
This check runs before enrollment, so this error does not consume the token.
Enrollment tokens expire after 15 minutes; obtain a fresh token if needed.

## Discovery and checks

Discovery probes only explicitly selected ports within allowed private CIDRs. For responsive addresses, the collector also makes a best-effort reverse-DNS lookup; a hostname appears when the local resolver has a PTR record. Missing PTR data does not block discovery, and the IP remains the stable address. It creates candidates; approval or configured auto-add turns a candidate into an inventory resource. A discovered `tcp_service` represents reachability evidence, not a fully monitored host.

Unadopted LAN resources remain in **Discovery**. Open **Configure** on a discovered service to edit its TCP port, queue a one-time check, or adopt it into **Software** with a recurring interval. Adoption queues an initial check and the active collector runs subsequent checks on schedule. Existing TCP and HTTP(S) monitors may also select a linked LNC when it advertises the required `tcp` or `http` capability. DNS, TLS, and ICMP checks remain Worker-routed. Pausing a recurring LNC check returns the service to Discovery. If the IP matches a managed Server, verify that it is the same device and site before linking; private addresses may be reused. Hardware resources expose **Set up Agent** and **Set up SNMP**, which links the existing discovered resource to a managed Server instead of creating a duplicate row.

SNMP profiles selected on a managed Server are used by the Local Network Collector for their configured scalar OIDs. With the device profile set to **Auto**, the control plane periodically sends profile detection signatures with a collection task. The collector probes the standard SNMP `sysObjectID` and `sysDescr` identity scalars and reports the match; the control plane stores it for the next poll. Detection runs when no result exists, at least six hours have elapsed, the detection registry changes, or re-detection is requested. The poll that performs detection still uses the previously effective profile. If a successful identity probe is ambiguous or no enabled profile meets its confidence threshold, the effective profile falls back to `generic-host`. If the identity probe is unavailable, the last effective profile is retained; on first detection this is normally `generic-host`.

Profiles marked **Experimental** can be selected manually, but are not considered for automatic matching. Their vendor-specific scalar mappings are available for testing; marking a profile experimental does not guarantee complete or verified device coverage. LNC poll plans use profile scalar OIDs only; vendor-specific profile table definitions and traps are not collected. If a selected profile has no numeric scalar OIDs supported by the LNC, it polls the `generic-host` scalar plan instead; the configured profile remains visible in the task metadata. The collector may separately aggregate standard Host-Resources CPU, memory, and fixed-disk metrics using its bounded built-in walks.

## Task recovery

Open a collector's activity to inspect recent tasks. A failed discovery can be retried from its task row; retry creates a new task using the saved scan parameters and checks the collector's current CIDR policy.

## Collector workspace and live queues

Search the settings workspace by collector name, site, location or subnet. Each
card shows its private-network coverage; use **Manage** for policy and detailed
activity, or **Review in Discovery** for findings scoped to that collector.
Registration is a separate disclosure with a one-time, 15-minute enrollment token.

Live snapshots refresh every 15 seconds while the tab is visible, including the
open collector's tasks, telemetry receipts and configuration revision. The update
time is shown; pause updates when needed or use manual refresh. Failed refreshes
retain the last data and expose **Retry refresh**. Action errors stay visible until
dismissed or another action is attempted; background refresh does not hide them.

- **Pending tasks** counts server-side work, including future schedules and the
  shared site pool. Capabilities and CIDR policy still determine eligibility.
  Shared tasks appear for multiple collectors and must not be summed.
- **Leased tasks** counts claimed tasks, including expired leases awaiting recovery.
  Task details show lease expiry and future scheduling.
- **Running / capacity** and **Buffered uploads** come from the last heartbeat.
  Buffered uploads are results awaiting delivery, not the pending task queue.

Policy drafts survive live updates. Closing or switching with edits requires
confirmation; Save and Discard are explicit. Saving changes the desired revision:
the collector must acknowledge it on a subsequent heartbeat before it is synced.
If the policy changes elsewhere while editing, discard and reload before saving;
settings writes also check the expected revision to avoid overwriting newer policy.
Private/local CIDRs are validated by the server, and invalid scan ports can be
corrected without losing the draft.

**Drain** allows existing leases to finish without claiming new work. **Disable**
prevents new leases and requires confirmation; existing work may still finish.
**Delete** requires confirmation and removes credentials and active leases while
retaining discovery audit history. Demo accounts can inspect and refresh but
cannot change policy, register, retry, approve or delete.

## Logs and health

```bash
sudo systemctl status sadapp-local-network-collector.service --no-pager
sudo journalctl -u sadapp-local-network-collector.service -n 100 --no-pager
sudo journalctl -u sadapp-local-network-collector.service -f
curl -fsS http://127.0.0.1:9168/health
```

The health listener is loopback-only. It reports heartbeat, task, queue, and spool diagnostics, not secrets or task payloads. The package default is port 9168; container deployments default to 8787.

See [Troubleshooting](../troubleshooting) for expired leases, failed uploads, and stale heartbeats.