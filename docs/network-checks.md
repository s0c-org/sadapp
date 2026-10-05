# Checks and probes

Use checks for service reachability and response behavior. Use Agent or SNMP telemetry for machine health. A successful TCP connection does not provide CPU, memory, or disk readings.

## Worker-based checks

Managed Servers can be assigned a worker location. The Monitoring Worker runs enabled scheduled checks that its configuration and target support. Server settings can add TCP, DNS, or TLS monitors; Website and Ping lanes have their own settings. A location must be covered by a configured worker when no catch-all worker is available.

## Local one-time TCP checks

An approved LAN `tcp_service` can run a one-time TCP connection check from its active Local Network Collector. Open the resource detail page, choose a port, and select **Run TCP check**. The selected port is saved. Results report queued/running/completed state, reachability, and latency.

Discovery itself only tests the ports supplied to its scan task. Discovery approval does not automatically create a recurring check. ICMP is not supported by the current LNC build; use a Monitoring Worker for scheduled Ping checks.

## Results

Use last-seen timestamps and result history together. A stale result can indicate collector downtime, a target timeout, or an expired task lease. See the Local Network Collector task history and [Troubleshooting](../troubleshooting).