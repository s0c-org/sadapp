# Metrics and history

Sadapp stores timestamped readings by resource and collection source. Inventory tables show the latest usable reading; detail views show available samples and check history.

## Sources

- **Agent** reports host-level metrics from an installed Agent.
- **SNMP** reports only the counters exposed by the device and selected MIB/profile.
- **Monitoring Workers** report scheduled ping, website, TCP, DNS, TLS, and supported SNMP checks.
- **Local Network Collector** reports bounded LAN tasks and local telemetry.

Source tags identify recorded sources; they are not promises that every metric family is available.

## Reading the values

CPU percentages are utilization readings or a supported SNMP idle counter converted to utilization. Memory percentage requires both used and total values, or a supported total/available pair. Disk percentage requires used and total capacity for at least one disk. Missing or invalid inputs display `n/a`, not zero.

`Last seen` indicates the latest resource observation, not necessarily the latest sample for every metric. Different counters may update on different schedules. A just-enrolled resource may have no readings until the first successful collection.

## Improve coverage

1. Confirm the source tag matches the intended collector.
2. Confirm the source is online and has completed a recent task/heartbeat.
3. Check whether the device exports the requested OID or Agent field.
4. For SNMP, verify the profile and credentials on the managed Server.
5. For Agent metrics, verify the service is active and reporting.

Do not interpret `0%` and `n/a` as equivalent: zero is a valid measured value; `n/a` means no valid value was received.