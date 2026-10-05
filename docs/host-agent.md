# Host Agent

The Host Agent is installed on a Linux host. It authenticates with an invitation or managed key and reports the machine metrics and inventory that the host can provide. An Agent must run on the device; a network discovery result cannot install it remotely.

## Install and enroll

1. In Sadapp, create or select a managed Server and open **Settings → Access**.
2. Create or renew an invitation token.
3. Open `/install`, choose **Host Agent**, and follow the command for the host's Debian/Ubuntu or RPM-based distribution.
4. Provide the invitation token to the installer when prompted. It is written to the local protected configuration and should not be copied into support messages.
5. Confirm the service is active and that the server's last-seen time advances.

The Agent makes outbound requests to the control plane; it does not require an inbound listener on the monitored host.

## Logs and service health

```bash
sudo systemctl status sadapp-host-agent.service --no-pager
sudo journalctl -u sadapp-host-agent.service -n 100 --no-pager
sudo journalctl -u sadapp-host-agent.service -f
```

Use the journal for authentication, configuration, or connectivity failures. Do not paste credential files or invitation tokens into logs or tickets.

## Metrics

Agent telemetry can include CPU utilization, memory used/total, disk capacity, network counters, process count, load, and supported inventory. A metric appears only when the host reports a valid value. `n/a` means no usable sample is available; it is not a zero reading.

For container inventory and virtualization guests, enable the corresponding integrations on the host and confirm their payloads are present in the resource detail view. See [Metrics and history](../inventory/metrics-and-history).