# SNMP devices

SNMP is suited to switches, routers, printers, storage appliances, and hosts where installing an Agent is not appropriate. Add the device from **Onboard Device** or use **Set up SNMP** from a discovered Hardware resource. Configuration is stored on its managed Server record.

## Authentication versions

- **SNMPv1** uses a community string and offers no encryption. Use it only on trusted isolated networks when the device requires it.
- **SNMPv2c** uses a community string but does not encrypt it on the wire. Prefer a restricted read-only community and a protected network path.
- **SNMPv3** uses a username and authentication protocol; privacy encryption can also be enabled when supported by the device.

The supported protocol choices depend on the selected collection path and installed release. Never put credentials in the device name, description, or a check target. Saved secrets are masked and delivered to collectors only when needed.

## Configure polling

1. Open the managed Server's **Settings → SNMP** tab.
2. Enable polling and enter the device address and UDP port (normally 161).
3. Choose the exact SNMP version configured on the device.
4. Enter the v1/v2c community or the v3 username, authentication, and optional privacy settings.
5. Select **Auto** or an appropriate device profile and save.

Only metrics exposed by the device's MIBs can be collected. The generic profile and compatible pollers can read standard CPU, memory, uptime, and storage counters; vendor metrics require a supported profile/OID. Unsupported counters remain unavailable rather than being guessed.

### Shared collection behavior

The Local Network Collector and Monitoring Worker share numeric transforms,
bounded adaptive table transport, metadata-cache rules and standard interface,
sensor and inventory table definitions. Supported IF-MIB interface measurements,
ENTITY-SENSOR temperatures/fans and ENTITY-MIB inventory use the same canonical
normalization through either executor. Unsupported sensors and incomplete storage
rows remain unavailable, never zero.

Standard interface readings also include ingress/egress discards, unicast packet
counters (high-capacity counters with a per-index 32-bit fallback), and the
uptime-relative last-change timestamp. The timestamp is not a link-change count.
Fixed-disk Host-Resources rows expose per-volume total, used, free bytes and usage
percentage when their type, allocation units and live measurements are valid.
Volume names/indexes remain attached to readings and inventory. Partial volumes
do not become successful whole-host storage totals.

SNMPv2c/v3 table reads use GETBULK with a smaller request and GETNEXT fallback on
response-size failures; v1 retains GETNEXT. Rows, output bytes and execution time
are bounded. Metadata discovery refreshes within one hour and after identity,
reboot or index changes; measurements are read on every poll.

Collector per-interface series and aggregate history are kept separate to avoid
double-counting, including when telemetry spans multiple upload batches. Worker
standard snapshots are retained in profile diagnostics; their unified
series/inventory remain subject to the existing shadow-write feature gate.
Deploy the updated control plane before updated executors. Shared synthetic
regression fixtures verify the common contract, not vendor/model certification.
Worker-specific Host-Resources CPU/GPU inference remains separate; floating-point
telemetry does not preserve every bit of very large Counter64 readings.

### Expanding a profile with tables

Approved profile `tables` now execute through the shared declarative engine,
not separate vendor-specific implementations in Collector and Worker. Define a
numeric `base_oid`, an `index_strategy`, a bounded `max_rows` and named columns.
Numeric columns declare their metric, unit, scale and optional transform;
string/object-identifier columns supply discovery metadata. Compact string column
definitions are treated as metadata, not guessed numeric measurements.

Supported index strategies are integer, numeric suffix, Internet address and MAC
address. Rows are joined by their discovered index, never a hardcoded port,
volume or sensor number. Readings carry `table_name` and `table_index` labels;
metadata is retained in `snmp.profile` inventory. Related-metric transformations
operate within the same row and use each column's scale.
Table transforms currently support scale, offset, percentage, used-from-total and
used-from-free. Aggregate and enum transforms are rejected explicitly rather
than treated as successful numeric collection.

Each task accepts at most 16 tables, 32 columns per table and 128 columns overall.
Declared row bounds range from 1 to 10,000, but response bytes, group deadlines
and snapshot cardinality also apply. A declared high row limit is not a promise
that every row will fit. Complete rows from bounded partial responses remain
usable with explicit diagnostics; partial metadata is not cached. Standard
storage totals remain strict to avoid presenting an incomplete subtotal as the
whole device.

Table-only profiles retain their selected profile identity and tables while
using generic-host scalar fallback where available. New per-row measurements are
supplemental: they do not overwrite or duplicate classic aggregate history.
Worker snapshots are retained in existing profile JSON; unified series/inventory
still require the existing shadow-write gate. Collecting additional readings does
not automatically add dedicated charts or enable alerts.
Overlapping profile and standard table definitions can still cause separately
bounded walks; common Host-Resources storage readings are reused within a poll.

## Staff diagnostics

**Admin → SNMP migration readiness** separates polling prerequisites from the
legacy scheduler migration plan. Passing prerequisites is not evidence of live
reachability or complete data. Check the last recorded poll result and timestamp,
then use **SNMP profile coverage** to review missing expected readings versus
unsupported optional OIDs. Device links open staff diagnostics and monitor controls.
Migration summary counts apply only to the displayed page and exclude devices
already off legacy from the held count. **Prepare** stages a disabled monitor;
it does not run a poll, change scheduler ownership or activate monitoring.
An explicit reviewed cutover is required to avoid duplicate polling.

### Automatic detection and profile status

With **Auto**, enabled profiles are matched against standard SNMP identity information. A Local Network Collector periodically performs this detection and saves the result for a subsequent poll; detection runs initially, every six hours, when the registry changes, or when you request re-detection. The poll that performs detection uses the previously effective profile. When an identity response is received but is ambiguous or does not meet any enabled profile's confidence threshold, automatic selection falls back to `generic-host`. If the identity probe is unavailable, the last effective profile is retained; on first detection this is normally `generic-host`.

Profiles marked **Experimental** are available for explicit manual selection but excluded from automatic matching. This status means a profile has not been enabled for general automatic selection; its vendor OIDs or coverage may still need validation. Disabled profiles cannot be selected or matched. See [Local Network Collector](local-network-collector) for collector-specific polling limits.

### UniFi Cloud Key G2 Plus

The **Ubiquiti UniFi** (`ubiquiti-unifi`) profile includes optional host metrics
verified against a UCK G2 Plus running UniFi OS 6.0.11: SNMP uptime, CPU idle/user/
system percentages, RAM total/free/buffer/cache, swap total/free, 1/5/15-minute
load averages, and interface count. Kilobyte memory readings are converted to
bytes, integer load averages are divided by 100, and uptime ticks are converted
to seconds. Existing CPU/memory projections use idle CPU and free RAM to derive
utilization and used memory; used RAM includes buffers and cache.

Select this experimental profile explicitly after the updated registry is
deployed to the control plane and Monitoring Worker. Local collectors receive
its numeric scalar poll plan from the control plane; no full-tree SNMP walk is
added to each poll. Worker poll budgets prioritize uptime, CPU, and RAM before auxiliary metrics. Other UniFi models may
omit these OIDs; missing optional readings do not fail a poll. Existing wireless
definitions remain, but the Cloud Key walk did not expose UBNT wireless OIDs.
Its generic Net-SNMP system object ID is not a UniFi-specific detection signature.

The supplied walk also contains disk I/O counters and temperature sensor rows,
but no HOST-RESOURCES storage capacity table. Disk I/O counters do not establish
free disk space. Sensor readings have inconsistent apparent scaling across
rows, so this profile does not guess Celsius conversions or pin sensor/interface
indexes from one appliance. Additional scalar series do not imply dedicated
charts for every metric.

## Troubleshoot

- Confirm UDP/161 is reachable from the selected worker or LNC.
- Confirm the collector's allowed CIDR includes the target when using an LNC.
- Check version, community, username, auth/privacy protocols, and context against the device configuration.
- Inspect the Server SNMP tab for last poll time/error and the collector task history for LNC jobs.

Local Network Collector task results update the Server's last-poll status, including failed reads.
Successful telemetry batches also populate the Server SNMP history used by hardware charts and
availability. A recent successful poll does not imply that every CPU, memory, or storage OID is
supported; unavailable readings remain empty. A rejected read is reported as a poll failure, not
as a stopped scheduler.

Collector task **Result details** preserve usable readings when another profile
OID is missing, including expected OIDs. Missing expected metrics remain partial
coverage rather than silently becoming optional. Table collection diagnostics
identify the affected group/OID and distinguish timeouts, authentication,
response limits, parse failures and unsupported tables without exposing raw
device responses. A poll with no usable readings still fails.

The staff profile-coverage report prioritizes missing expected OIDs before optional
gaps and counts each missing OID once per device. It also aggregates table
diagnostics, so successful scalar reads do not hide failed storage/CPU table
collection. This report currently includes successful Local Network Collector
tasks only, not failed tasks or Monitoring Worker observations. Do not treat it
as an all-executor fleet completeness score.

Profile changes require sanitized real-device evidence: record model, firmware,
SNMP version and relevant numeric OID/type/unit responses, removing credentials,
names, addresses, serial numbers, MAC addresses and other identifying values.
Add regression fixtures for supported and absent OIDs and validate both execution
paths. A frequently absent OID alone is not sufficient evidence to mark it optional
or to infer a vendor-specific scaling factor.

See [Local Network Collector](local-network-collector) for private-network polling and [Metrics and history](../inventory/metrics-and-history) for interpreting `n/a` values.