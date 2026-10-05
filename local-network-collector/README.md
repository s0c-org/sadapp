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

`COLLECT_SNMP` supports SNMP v1, v2c, and v3 through Net-SNMP. Profile scalars are read with `snmpget`; fixed-disk capacity is optionally aggregated from bounded Host-Resources table walks with `snmpwalk`. Unsupported OIDs are skipped while valid samples are retained. The generic-host profile adds Net-SNMP CPU-idle and memory-availability counters where the device exposes them. Missing device counters remain unavailable rather than being reported as zero.

Poll plans are derived from approved monitoring-worker profiles, contain at most 128 numeric OIDs, and cannot supply command flags or walk roots. Host-Resources walks use fixed built-in OIDs, a 256-row limit, a 128 KiB output limit, and bounded command timeouts. Every target must be an explicit IP inside the collector's allowed private CIDRs.

For v1 and v2c, the control plane leases an ephemeral community value from its secret vault. For v3, auth protocols are limited to MD5/SHA variants and privacy protocols to DES/AES variants. Passphrases exist only in the lease response, process memory, and direct process arguments; task payloads and database rows contain secret references only. Command stderr and secret-bearing runner errors are not returned or logged.

## Build and validate

```bash
cargo fmt --check
cargo test
cargo clippy -- -D warnings
```

Build Linux deb/rpm packages with `scripts/build_packages.sh`; it requires Rust, `nfpm`, and the target toolchain already installed. The script does not install system packages.