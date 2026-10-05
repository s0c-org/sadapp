# Getting started

Sadapp separates managed devices from the services and checks that run against them. Begin at **Onboard Device** (`/servers/add`) when you want to add an Agent, SNMP device, ping target, or website. Use **Local Network Collectors** (`/settings/local-network-collectors`) when checks must originate inside a private network.

## Choose a collection path

- **Host Agent** runs on a Linux host and reports host metrics such as CPU, memory, disks, and interfaces.
- **SNMP** reads the metrics exposed by network devices and appliances. It does not install software on the target.
- **Monitoring workers** run scheduled reachability and service checks from registered locations.
- **Local Network Collector (LNC)** runs bounded discovery and approved checks inside an allowed private CIDR.

These sources are not interchangeable. A TCP service discovered on a LAN is not a managed host and will not have CPU or memory readings until a suitable Agent or SNMP source is configured.

## Add your first device

1. Open **Onboard Device**.
2. Choose Agent, SNMP, Ping, or Website.
3. Enter a display name and target. For worker checks, select an available worker location when required.
4. For SNMP, choose v1, v2c, or v3 and enter the matching credentials. Secrets are stored in the vault and are not shown again.
5. Save the device and follow the resulting settings or installation instructions.

For private addresses, make sure the selected worker can reach the target or use an enrolled LNC whose allowed CIDRs contain it.

## Find the result

- **Hardware** lists hosts, network devices, and appliances with host telemetry.
- **Software** lists websites, ports, and other service checks.
- Open a resource name for its details, current readings, and available actions.
- Open **Settings → Local Network Collectors** to check collector heartbeat, task state, and upload receipts.

Start with [Host Agent](devices/host-agent), [SNMP devices](devices/snmp), or [Local Network Collector](devices/local-network-collector) for setup details.