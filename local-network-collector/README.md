# SadApp Local Network Collector

`sadapp-local-network-collector` is an outbound-only runtime for bounded discovery and checks inside an explicitly approved local network. It enrolls with the SadApp control plane, heartbeats for leased work, validates every network target against backend-supplied CIDRs, and durably retries task results and telemetry.

## Configuration

Copy `sadapp-local-network-collector.env.example` and set:

- `CONTROL_PLANE_URL`: SadApp base URL. HTTPS is required; HTTP is accepted only for loopback development.
- `ENROLLMENT_TOKEN`: one-time token used only when no credential has been persisted.
- `COLLECTOR_ID` and `COLLECTOR_SECRET`: optional alternative to enrollment/persisted credentials. Set both or neither.
- `STATE_DIR`: credential, configuration, and spool location (default `/var/lib/sadapp-local-network-collector`).
- `HEARTBEAT_INTERVAL_SECONDS`: initial bounded interval, 5-300 seconds (default 30). The backend controls subsequent intervals.
- `MAX_CONCURRENT_TASKS`: local ceiling, 1-32 (default 4).
- `SPOOL_MAX_ITEMS` and `SPOOL_MAX_BYTES`: bounds applied independently to result and telemetry queues.
- `HEALTH_PORT`: optional loopback-only `/health` listener.

`RUST_LOG=info` enables normal operational logs. Credentials, enrollment tokens, bearer values, and lease tokens are never logged. The state directory is forced to mode `0700`; credentials and spool entries are atomically written with mode `0600`.

## Diagnostics and SNMP coverage

The packaged systemd service sends output to the journal. Info-level logs report
heartbeat summaries, task starts/completions, and acknowledged uploads. A connected
collector can be idle: registering a collector does not automatically schedule
discovery or checks. Tasks must be assigned by the control plane, and discovery
must be enabled in its policy before discovery tasks can run.

```bash
systemctl status sadapp-local-network-collector.service --no-pager
journalctl -u sadapp-local-network-collector.service -n 100 --no-pager
journalctl -u sadapp-local-network-collector.service -f
curl -fsS http://127.0.0.1:9168/health
```

The health port is configurable through `HEALTH_PORT`; the package default is
9168, while the container defaults to 8787. The listener binds only to loopback.
It reports version, uptime, successful heartbeat time, heartbeat failures,
running/completed/failed tasks, acknowledged uploads, spool counts/bytes, and
applied configuration revision without credentials or task payloads. Counters
reset on process restart. The endpoint starts after credentials are resolved;
use the journal to diagnose enrollment or startup failures.

The account UI under `/settings/local-network-collectors` refreshes visible
activity every 15 seconds. Open a collector to inspect configuration sync,
the latest 30 task states, and the latest 10 telemetry receipts. Shared pending
site tasks are not guaranteed to run on that particular collector until leased.

Discovery observations are versioned and retain every open configured TCP port
for a host, along with transport and observation time. Probes are bounded to four
ports per host concurrently, and a task is limited to 4096 hosts and 32 ports.
On Linux, discovery also reads the local `ip -j neigh show` cache without
privileges or active probes. Entries are included only when their address was in
the scanned host range and falls within the matching interface's concrete
on-link network; this avoids assigning a gateway's link-layer address to a
remote routed target. Candidate evidence may contain
`linkLayerObservations: [{macAddress, interfaceName, networkCidr,
addressFamily, source}]`, where `addressFamily` is `ipv4` or `ipv6` and `source`
is `arp` or `ndp`. Invalid, zero, multicast, incomplete, and failed neighbor
entries are omitted. These are local cache observations, not authenticated or
verified device identities. Unsupported platforms, unavailable caches, missing
interface context, and oversized caches are reported as result diagnostics
(`LINK_LAYER_UNSUPPORTED_PLATFORM`, `LINK_LAYER_CACHE_UNAVAILABLE`,
`LINK_LAYER_INTERFACE_CONTEXT_UNAVAILABLE`, or
`LINK_LAYER_CACHE_LIMIT_EXCEEDED`) and do not fail discovery. The cache command
has a two-second deadline and a 1 MiB output cap.
Detected HTTP/HTTPS ports also receive an unauthenticated `HEAD` probe, with
`OPTIONS` fallback when `HEAD` is unsupported. Redirects are disabled; no
credentials are sent. Response status, server header, and auth challenge are
recorded, so `401`/`403` means the service responded and needs credentials, not
that the host is down.

The control plane adds service names and low-confidence profile hints (for
example possible Windows, RTSP, printer, or Proxmox services). Port matches are
not device identity: they remain candidates. Auto-add requires a verified,
stable identity from a supported protocol adapter.

Discovery also sends a bounded SNMPv3 `noAuthNoPriv` sysObjectID request and
IPv4 SSDP, ONVIF WS-Discovery, and mDNS DNS-SD queries on interfaces inside the
scanned CIDR. SNMPv3 auth reports are recorded as `authentication-required`;
UDP silence remains inconclusive. ONVIF UUIDs and SSDP USNs are hashed for
correlation. Advertised HTTP locations are never fetched. IPv6 multicast and
Wi-Fi client inventory through AP/controller APIs are not implemented yet.

REST discovery does not guess API paths or send credentials. `COLLECT_SNMP`
still uses approved profiles and vaulted credentials for metric polling; the
no-auth discovery probe only reads the standard sysObjectID OID.

## Network policy

The collector starts with no allowed CIDRs and cannot perform network tasks until a valid heartbeat configuration or `REFRESH_CONFIG` task is applied. Accepted ranges are limited to RFC1918, IPv4 loopback/link-local, and IPv6 ULA/loopback/link-local. Public, CGNAT, multicast, documentation, benchmark, and unspecified ranges are rejected. Hostnames are accepted only when every resolved address is allowed, and HTTP clients are pinned to those validated addresses with redirects disabled.

`DISCOVER` uses bounded TCP probes against explicitly supplied ports. A task CIDR must be contained by collector policy and cannot exceed 4096 addresses. Candidate submissions use backend batches of at most 250.

`RUN_CHECK` supports ICMP via the system `ping` executable, TCP, and HTTP/HTTPS. Credential rotation, self-upgrade, and arbitrary DNS check payloads are unsupported by the current protocol.

## SNMP collection

`COLLECT_SNMP` supports SNMP v1, v2c, and v3 through Net-SNMP. Profile scalars are read with `snmpget`; CPU, RAM and fixed-disk capacity can also be derived from standard Host-Resources tables. Unavailable OIDs, including expected OIDs, do not discard other valid samples: the task reports missing metrics and safe table-collection diagnostics. No usable readings still fails a measurement task. Missing device counters remain unavailable rather than being reported as zero.

After matching credential verification succeeds, the control plane automatically queues a read-only `discoveryOnly` task, even when monitoring is disabled. It scans only approved standard columns and the selected profile, bypasses standard/profile metadata caches, and never writes telemetry, monitor history or polling health. A new identity match queues one follow-up scan using the newly selected profile. Editors can refresh capabilities from the device's Monitoring tab; duplicate live requests reuse the pending job. Expired jobs can be retried.

Collector and Worker use the shared capability recorder: successful rows are supported, a successful empty/no-such-object response is unsupported for the current credential/view, and timeouts, parse errors and transport failures are unknown. Reports contain only OIDs, bounded row indexes and diagnostic codes (16 groups, 256 columns, 128 indexes per column, 64 KiB), not values or credentials. The device report is saved separately from telemetry and is available to viewers; refresh requires editor access. Invalid reports are rejected before writes, and completed collector discovery is guarded by its configuration and request token. Configuration/profile edits clear saved discovery state. Reports older than 24 hours are shown as stale.

Regular successful polls refresh reports from the OIDs they actually execute; no additional unapproved probes or evidence sharing is introduced. Worker manual refresh advances the next enabled worker poll (legacy workers pick it up on their next target poll), rather than running a separate collector task. Early command failures remain explicit discovery errors. Reports do not yet filter polling: unknown or previously unsupported OIDs are not permanently suppressed. Existing metadata caches still rediscover on TTL, reboot, index or profile/endpoint/authentication changes.

Both the collector and Monitoring Worker use `sadapp-snmp-profile-engine` for numeric transformations, table transport and discovery-cache policy. v2c/v3 table collection starts with `snmpbulkwalk` at 10 repetitions, reduces to 5 on size failures, then falls back to GETNEXT `snmpwalk`. v1 uses GETNEXT only. Each walk and all its retries share a 10-second deadline, 128-row default and 1 MiB output budget; the child is killed and reaped on timeout or output-limit failure. Authentication and row-limit failures are not retried. Net-SNMP utilities are required; missing executables are reported explicitly.

Storage type and allocation-unit metadata are cached for at most one hour in a bounded 4,096-key cache. Size, used space and CPU measurements remain live on every poll. Endpoint/profile/credentials changes, a decreasing or missing uptime, or changed storage indexes invalidate metadata. Cache keys hash authentication material rather than storing credentials. Scalar transforms use the same scaled related-metric values as the worker.

Standard IF-MIB interface counters/status/speed/errors, ENTITY-SENSOR temperature/fan measurements and ENTITY-MIB inventory use shared table plans and normalization in both executors. Each standard-table group has a shared 10-second budget with at most four concurrent walks. Metadata discovery has a separate 128-key, one-hour cache; measurement columns remain live. Counter64 is preferred per interface with a 32-bit fallback, but numeric telemetry still uses floating-point values and is not lossless for very large counters.

Standard tables also include interface discards, unicast packet counters, uptime-relative last-change timestamps and named fixed-disk volume capacity/usage/free/percentage readings. Per-volume measurements are supplemental; incomplete rows must not replace strict whole-host totals.

Approved profile tables are forwarded as validated `tablePlans` and executed through `sadapp-snmp-profile-engine::profile_tables`. Plans support integer, suffix, Internet-address and MAC-address indexes, metadata columns, numeric units/scales and same-row related-metric transforms. Limits are 16 tables, 32 columns/table, 128 columns overall and declared row bounds of 1-10,000. Profile collection has a shared 10-second deadline, at most four concurrent walks and a cumulative 1 MiB output budget. Complete response prefixes remain usable with explicit response-limit/timeout diagnostics; partial metadata is never cached. A separate bounded 128-key discovery cache stores only metadata, invalidated by per-column index membership, uptime and plan/endpoint/authentication identity. String-only tables without live index evidence are rediscovered rather than assumed stable.

Profile snapshots use `table_name`/`table_index` labels and `snmp.profile` inventory. They are bounded to 2,048 metrics, 256 inventory rows and 1 MiB; standard snapshots allow 4,096 metrics, 384 inventory rows and 1.5 MiB. Hitting a bound reports partial collection rather than inventing zero readings. Existing profile states and automatic-detection rules are unchanged; declarative execution is not evidence that an experimental vendor mapping is correct.

Telemetry is split into batches of at most 500 items. Per-interface supplemental series do not create duplicate classic history rows or double-count aggregate traffic. Standard inventory is sent as `snmp.standard`; the worker uses the same canonical snapshot contract, retained in its existing profile diagnostics. Unified worker series/inventory still follow the existing shadow-write feature gate. Deploy the control plane before updated collectors/workers. Shared synthetic fixtures verify protocol parity, not new vendor/model certification; worker-specific Host-Resources CPU/GPU inference is not a generic vendor table engine.

With the device profile set to `auto`, the control plane periodically includes the approved detection signatures in a collection task. The collector probes the standard SNMP `sysObjectID` and `sysDescr` identity scalars and reports a match; the control plane saves that result for a subsequent poll. Detection runs when no result exists, at least six hours have elapsed, the detection registry changes, or a re-detection is requested. The poll that performs detection still uses the previously effective profile. Only enabled profiles are considered for automatic matching. If a successful identity probe is ambiguous or no profile meets its confidence threshold, the effective profile falls back to `generic-host`. If the identity probe is unavailable, the last effective profile is retained; on first detection that is normally `generic-host`.

Experimental profiles are available for explicit selection but are excluded from automatic matching. They are marked experimental so operators can test their vendor-specific scalar mappings before those profiles are enabled for general automatic use.

Poll plans are derived from approved monitoring-worker profiles, contain at most 128 numeric scalar OIDs, and cannot supply command flags or arbitrary walk roots. Approved vendor tables use separate validated table plans; trap definitions are not polling plans. Host-Resources walks use fixed built-in OIDs, a 256-row limit, a 128 KiB output limit, and bounded command timeouts. Every target must be an explicit IP inside the collector's allowed private CIDRs.

For v1 and v2c, the control plane leases an ephemeral community value from its secret vault. For v3, auth protocols are limited to MD5/SHA variants and privacy protocols to DES/AES variants. Passphrases exist only in the lease response, process memory, and direct process arguments; task payloads and database rows contain secret references only. Command stderr and secret-bearing runner errors are not returned or logged.

## Build and validate

```bash
cargo fmt --check
cargo test
cargo clippy -- -D warnings
```

Build Linux deb/rpm packages with `scripts/build_packages.sh`; it requires Rust, `nfpm`, and the target toolchain already installed. The script does not install system packages.