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
5. Select an automatic or appropriate device profile and save.

Only metrics exposed by the device's MIBs can be collected. The generic profile and compatible pollers can read standard CPU, memory, uptime, and storage counters; vendor metrics require a supported profile/OID. Unsupported counters remain unavailable rather than being guessed.

## Troubleshoot

- Confirm UDP/161 is reachable from the selected worker or LNC.
- Confirm the collector's allowed CIDR includes the target when using an LNC.
- Check version, community, username, auth/privacy protocols, and context against the device configuration.
- Inspect the Server SNMP tab for last poll time/error and the collector task history for LNC jobs.

See [Local Network Collector](local-network-collector) for private-network polling and [Metrics and history](../inventory/metrics-and-history) for interpreting `n/a` values.