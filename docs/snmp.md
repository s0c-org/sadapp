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

See [Local Network Collector](local-network-collector) for private-network polling and [Metrics and history](../inventory/metrics-and-history) for interpreting `n/a` values.