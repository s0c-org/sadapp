# Getting started

Sadapp separates managed devices from the services and checks that run against them. Begin at **Onboard Device** (`/onboarding`) when you want to add an Agent, SNMP device, ping target, or website. Use **Local Network Collectors** (`/settings/local-network-collectors`) when checks must originate inside a private network.

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

## Navigation, appearance and mobile use

The customer workspace uses a persistent, collapsible sidebar on desktop and a navigation drawer on phones. The mobile bottom bar provides shortcuts to Overview, Hardware, Software and Discovery; open the navigation drawer for settings, support and the other workspace destinations. Search is available in page headers and with **Ctrl/Cmd + K**.

Open **Settings → UI settings** to choose **Midnight cyan**, **Amber gold** or **Violet dusk**, standard or wide page width, LTR or RTL layout, and standard or larger text. Motion follows each device's accessibility setting unless you select **Reduce motion**, which also disables chart and notification-flow animations. Compact inventory rows and discovered-workload visibility share the account preferences used by Hardware and Software.

Appearance changes preview immediately. **Save preferences** stores all UI preferences on your account; other devices load them after signing in or returning to the app. A local cache prevents appearance flashing during loading and supports the installed PWA. Until your first account-wide save, existing browser appearance remains the starting point; old Forest selections become Amber. **Discard changes** or leaving the page restores the saved appearance. **Reset to defaults** changes only the draft until saved. Staff administration keeps its independent palette.

The installed app opens the dashboard, supports portrait and landscape layouts, and reserves space for device safe areas. Offline navigation shows an explicit offline page rather than a cached account dashboard; monitoring data and authenticated API responses are not stored in the service-worker cache.

Start with [Host Agent](devices/host-agent), [SNMP devices](devices/snmp), or [Local Network Collector](devices/local-network-collector) for setup details.