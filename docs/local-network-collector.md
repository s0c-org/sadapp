# Local Network Collector

The Local Network Collector (LNC) is an outbound-only service for approved private networks. It enrolls with Sadapp, receives bounded tasks, validates targets against its allowed CIDRs, and returns results. It does not automatically scan merely because it has been registered.

## Enroll a collector

1. Open **Collectors** in the workspace sidebar (`/collectors`). The Settings hub also links here.
2. Register a collector with a name, site key, and allowed private CIDRs.
3. Copy the one-time enrollment token into the installer prompt on the machine inside that network.
4. Install the Local Network Collector package from `/install` for Debian/Ubuntu or RPM-based Linux.
5. Wait for a heartbeat; verify the collector is active, capabilities are reported, and its applied configuration revision is current.

The `siteKey` groups tasks for collector routing. It is distinct from a Monitoring Worker location.

The installation page downloads the installer to a local file before execution.
Review it, then run it with the selected stable or canary channel and supply the
one-time token at the protected prompt. Manual repository commands install the
package but do not replace enrollment. Package versions are listed independently
for APT and RPM; a GitHub release-note failure does not hide those listings.

### Physical location and precise map pins

Open a collector with **Manage**, expand **Configuration**, then use **Precise Fleet Map pin** to enter a label, latitude (-90 to 90)
and longitude (-180 to 180). All three fields are required for a pin; zero is a
valid coordinate. **Clear precise pin** removes the coordinates when saved.
The physical-location note remains separate. A recognized Fleet Map region is an
approximate fallback when no precise pin is set.

Private account and staff maps use these coordinates for the collector and
eligible locationless hosts/checks. Explicit host locations are never overwritten,
and conflicting collector locations do not invent a shared host location. Changing
coordinates does not change the site key, allowed networks or check routing.
No browser GPS permission or external geolocation service is used.

Deployment requires the `20261102173000_collector_map_coordinates` database migration
before starting the updated control plane. No native collector package update is
required; map coordinates are stored and resolved by the control plane.

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

Unadopted LAN resources remain in **Discovery**. Open **Configure** on a discovered service to edit its TCP port, queue a one-time check, or adopt it into **Software** with a recurring interval. Adoption queues an initial check and the active collector runs subsequent checks on schedule. Existing ICMP, TCP and HTTP(S) monitors may also select an active LNC owned by the server owner when it advertises the required `icmp`, `tcp` or `http` capability and allows the target network. Prior discovery or a resource link is not required for these monitors. SNMP polling still requires a linked resource and verified credentials. DNS and TLS checks remain Worker-routed. Pausing a recurring LNC check returns the service to Discovery. If the IP matches a managed Server, verify that it is the same device and site before linking; private addresses may be reused. Hardware resources expose **Set up Agent** and **Set up SNMP**, which links the existing discovered resource to a managed Server instead of creating a duplicate row.

SNMP profiles selected on a managed Server are used by the Local Network Collector for their configured scalar OIDs. With the device profile set to **Auto**, the control plane periodically sends profile detection signatures with a collection task. The collector probes the standard SNMP `sysObjectID` and `sysDescr` identity scalars and reports the match; the control plane stores it for the next poll. Detection runs when no result exists, at least six hours have elapsed, the detection registry changes, or re-detection is requested. The poll that performs detection still uses the previously effective profile. If a successful identity probe is ambiguous or no enabled profile meets its confidence threshold, the effective profile falls back to `generic-host`. If the identity probe is unavailable, the last effective profile is retained; on first detection this is normally `generic-host`.

Profiles marked **Experimental** can be selected manually, but are not considered for automatic matching. Their vendor-specific scalar mappings are available for testing; marking a profile experimental does not guarantee complete or verified device coverage. LNC poll plans use profile scalar OIDs only; vendor-specific profile table definitions and traps are not collected. If a selected profile has no numeric scalar OIDs supported by the LNC, it polls the `generic-host` scalar plan instead; the configured profile remains visible in the task metadata. The collector may separately aggregate standard Host-Resources CPU, memory, and fixed-disk metrics using its bounded built-in walks.

## Task recovery

### Multi-collector site pools

Collectors with the same owner and `siteKey` share eligible work; overlapping pools
require task affinity. Stable affinity chooses a capable preferred collector with
available capacity. A fresh active preferred collector keeps its work; alternate
collectors can take over when it is stale, disabled, draining or missing.
Task claims use guarded leases so simultaneous claims have only one winner.
Expired leases may be reclaimed within the attempt limit, provided capabilities,
credentials and target policy still allow execution.

This is not instant failover, exactly-once execution or an availability SLA.
Heartbeat freshness and lease expiry control takeover timing. Pool members must
reach the same targets; a shared site key does not connect separate networks.
Draining stops new claims while current leases may finish. Shared pending counts
are visible on multiple collectors and must not be summed.

Open a collector's activity to inspect recent tasks. A failed discovery can be retried from its task row; retry creates a new task using the saved scan parameters and checks the collector's current CIDR policy.

## Collector workspace and live queues

Search the collector fleet by name, site, location or subnet. Compact, full-width
rows show network coverage, heartbeat, queues, linked resources and candidates.
Fleet cards prioritize relative last-seen age, linked resources, pending
**Needs review** candidates and 24-hour succeeded/failed task results with a
success rate. No completed results means no rate, not 100% success. Candidate
totals are not used as pending-review counts. Running work and buffered uploads
appear when nonzero; pending/leased counts and capacity remain in **Queue details**.
Lifecycle explanations are available beside the actions under **Lifecycle help**.
Multiple collectors can share a site; shared pending counts are not additive.
Use **Manage** to open that collector's focused activity view, then expand
**Configuration** to edit policy. The collector switcher moves between fleet
members; **All collectors** returns to the overview. Unsaved policy changes
require confirmation before switching or closing. Selected views have shareable
`/collectors?collector=ID` URLs and reopen after reload. Old
`/settings/local-network-collectors` links redirect to the workspace.

The selected view includes detailed activity and **Review in Discovery** for
findings scoped to that collector.
Registration is a separate disclosure with a one-time, 15-minute enrollment token.

Section links jump to health, tasks, discovery, configuration and lifecycle
controls. Recent tasks initially show five rows; filter by status or expand the
loaded history. Verbose SNMP coverage is under **Result details**. Failed-task
counts cover the preceding 24 hours and do not alone indicate a disconnected
collector. Shared site tasks can include work performed by other pool members.

### Package updates

The collector fleet's **Needs update** filter compares installed versions with
the stable Linux package reference. **Update instructions** in the selected
collector lets you compare stable or canary references and review commands for
an existing APT or RPM installation. Changing this selector does not change the
machine's repository channel. Check its configured channel, OS and architecture
before upgrading, drain for maintenance, and resume afterward. A fresh heartbeat
reporting the new version confirms the result; no upgrade commands are executed
by the web UI.

An application version without a package revision cannot prove that the package
is current. When the application matches but its package revision is unreported,
the badge says **Application version matches**, with package-level verification
still unknown. The collector reports its application version, so this is not a
heartbeat or monitoring failure. Missing metadata, unsupported version formats and differing Debian/
RPM references stay unknown rather than showing a green current badge. Versions
newer than the selected reference are shown as ahead, not as needing a downgrade.
Lookup failures expose a retry. Hardware shows equivalent agent/collector status;
its update count and filter apply to the currently loaded inventory page.
Release references refresh every five minutes while the tab is visible.
If repository metadata is unavailable, update status remains unknown; this does
not mean collector checks or heartbeats have failed. **Retry version lookup**
fetches metadata again without reusing an incomplete server-side lookup.
If Debian and RPM versions actually differ, the warning lists both versions;
verify the machine's package format in **Update instructions** rather than
assuming either version applies. Queue and heartbeat data remain available.

Tasks and discovery candidates initially show five entries each. Status filters
and **Show all** expose the remaining snapshot without overwhelming the overview.
Verbose task results and discovery observations are collapsed; discovery evidence
retains the raw payload for troubleshooting. Candidate **Approve** and **Reject**
actions are labeled explicitly. Use **Review in Discovery** for the full review
workflow.

Live snapshots refresh every 15 seconds while the tab is visible, including the
open collector's tasks, telemetry receipts and configuration revision. The update
time is shown; pause updates when needed or use manual refresh. Failed refreshes
retain the last data and expose **Retry refresh**. Action errors stay visible until
dismissed or another action is attempted; background refresh does not hide them.

Connection/activity indicators use the same colors in fleet and detail views:
green for a fresh active collector (idle or processing), yellow for buffered
uploads, awaiting leased-task progress, draining or awaiting enrollment, and red
for stale heartbeats, disabled or revoked collectors. Idle is healthy, not an
error. Text labels accompany the colored indicators; historical task failures
do not change connection status.

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
retaining discovery audit history.

## Logs and health

```bash
sudo systemctl status sadapp-local-network-collector.service --no-pager
sudo journalctl -u sadapp-local-network-collector.service -n 100 --no-pager
sudo journalctl -u sadapp-local-network-collector.service -f
curl -fsS http://127.0.0.1:9168/health
```

The health listener is loopback-only. It reports heartbeat, task, queue, and spool diagnostics, not secrets or task payloads. The package default is port 9168; container deployments default to 8787.

See [Troubleshooting](../troubleshooting) for expired leases, failed uploads, and stale heartbeats.