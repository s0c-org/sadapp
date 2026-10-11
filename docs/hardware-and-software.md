# Hardware and Software inventory

The two registers answer different questions:

- **Hardware** (`/hardware`) lists managed hosts and devices that can provide machine telemetry.
- **Software** (`/software`) lists services, websites, and configured reachability checks grouped by host. Containers and virtual machines belong in Hardware.

## Location and check execution

Server **Physical location** is a free-form inventory note. **Map region** is selected separately; choose a country, subdivision, and city for a precise pin on your private fleet map. The public map remains at coarse regional resolution. Unselected or unrecognized locations are listed as not mapped rather than guessed from their text.

**Monitoring Worker Location** controls Worker-routed checks; it is not a physical location. ICMP, TCP and HTTP(S) monitors can use any active Local Network Collector owned by the server owner that advertises the required capability and allows the target network. Prior discovery or a linked local resource is not required for these checks. SNMP additionally requires a linked resource and verified SNMP credentials. DNS and TLS checks remain Worker-routed. A private IP requires an authorized local executor.

Monitor history reports success rate and failures separately from successful-check latency percentiles. P95 requires at least 20 latency samples; P99 requires at least 1,000. A low percentile does not mean a target is reachable if the failure rate is high.

## Discovered resources

Use **Discovery** (`/discovery`) to review unconfigured Local Network Collector findings. Pending candidates record an address, detected service/device kind, and limited evidence such as an open port; approving one adds it to the local inventory. These findings do not imply CPU, memory, or disk telemetry.

Discovery separates Awaiting review, Ready for setup, Managed networks and Ignored
findings. Search and collector/site filtering preserve the origin of each finding;
collector coverage shows the actual configured CIDRs. Counts describe findings,
not confirmed physical devices, and capped lists explicitly report incomplete results.

One managed server may have LAN, Wi-Fi and additional NIC addresses. Explicitly
link local findings to the same existing host instead of creating duplicate servers.
Confirm the host and site when associating a secondary address; it must fall within
the collector's allowed private networks. Linking leaves the primary IP and monitoring
settings unchanged. Interface labels can be edited and links detached without deleting
the local resource or checks. Managed networks groups services by collector/address
under the linked server, not by hostname or private IP alone.

Agent-reported NIC names are suggestions, not verified address mappings. Collector
multicast listening interfaces are also distinct from the discovered device's NICs.
Ignore applies to one collector/address, not every network of the same host.

Approved LAN resources that have not yet been adopted stay in Discovery. Adopt a TCP service by enabling a recurring check; it then appears in Software. Link discovered hardware with Agent or SNMP to add it to Hardware. Paused or unconfigured LAN resources remain in Discovery, and adopted resources retain their `LAN` marker and available source tags.

Open a resource name for its detail page. TCP services have a saved port setting and a **Run TCP check** action. Hardware resources can be linked to a managed Server through **Set up Agent** or **Set up SNMP**; the existing resource is linked rather than duplicated. Agent setup requires installing the Agent on the host. SNMP setup requires valid device credentials.

## Resource detail and settings

### Software service workspace

Opening a grouped Software row goes to `/software/[id]?view=service`, showing the related checks rather than an arbitrary single check. Grouping follows the same host identity rules as the inventory: linked server first, then route identity, then an unambiguous normalized host address. Shared addresses belonging to multiple managed hosts are not merged automatically. Each child link opens its individual check.

- **Overview** shows the service/check state, latest observation, response time, executor, and protocol results. Service Overview graphs show the selected check; History includes all service checks.
- **Checks** provides mobile-friendly cards with targets, protocols, schedules, warnings, HTTP status, errors, and direct Results/Configure links.
- **History** has a shared one-hour, 24-hour, or seven-day window, separate latency and outcome graphs, endpoint reading trends, local check requests, and expandable results with safe protocol details and execution source. At most 500 representative observations per series are shown; these sampled results are not an uptime SLA. Missing latency does not hide a failed outcome. Heavy history is fetched when needed, not with every 30-second detail refresh.
- **Settings** (`/software/[id]/settings`) edits the selected check. Website settings include expected HTTP status and TLS verification; DNS includes expected addresses; TLS/website checks include certificate warning days. Executor choices include the server owner's active collectors, independent of the saved host IP. Change the target, select Local network collector and a collector covering the new address, then save together. Collector options show their allowed CIDRs; the API validates ownership, capabilities and networks. Primary checks still update their shared host settings.

States distinguish **Healthy**, **Warning**, **Failed**, **Waiting**, **Paused**, and **Stale**. A result becomes stale after three configured intervals with a minimum of five minutes. Paused checks never use old successful results as proof of current health. Warning results, such as filtered ICMP, do not imply a confirmed outage.

Each check's latency and outcome charts share a full-width section: side by side on desktop, stacked on phones. Outcome charts use discrete Failed / Warning / Passed ticks and unfilled steps, not a continuous filled measurement. A single check card fills its available row.

Editors can schedule a test, pause/resume, and duplicate saved check configuration without history or primary-host identity. “Check scheduled” only means queued, not passed. Viewer access remains read-only. Primary checks share target, enable state, and HTTP options with their host and cannot be deleted independently. Instead, the host owner can use **Delete service and host** in the check settings and type the host name to confirm. This permanently removes the host, all of its checks, and their history. Other members can only pause the check.

Unsaved edits have a floating Save/Discard bar and navigation confirmation. TCP services support both recurring reachability checks and separate REST readings; switching between them protects drafts. REST credentials remain in the vault and existing references are retained when fields are left blank. Failed endpoint saves retain a newly created reference for retry rather than creating duplicate credentials. Existing REST method, body credential references, and additional mappings are preserved.

Legacy checks retain a compatible editor under `/software/[id]/settings/legacy`, limited to check/network configuration without host deletion or access-management controls.

### Hardware resource settings

A Hardware host page is split into tabs. The selected tab and graph window are kept in the address, for example `/hardware/[id]?tab=performance&range=7d`, so a view can be shared or reloaded.

- **Overview** shows current CPU, memory, and storage, key facts, the three newest open incidents, a host status card (Agent version and channel, collector health, package updates), and quick tiles for GPU, the hottest sensor, current network rate, and disk health. Tiles open the tab with the details.
- **Performance** shows CPU, memory, storage, network, and GPU graphs for **1 h**, **24 h**, or **7 d**. Every graph uses the exact selected window, and GPU history opens expanded. The 7-day view refreshes on request rather than every 30 seconds. An empty window shows one message instead of empty charts.
- **Workloads** lists Docker containers and Proxmox guests for managed hosts.
- **Health & logs** shows active incidents, security and package updates, agent delivery, processes, sensors, disks, and recent host events. A badge counts open incidents.
  - Incidents are open warnings, errors, and critical alerts. Recoveries and notices stay in **Settings → Notifications → History**. Editors can **Acknowledge** or **Resolve** an incident here; a flow recovery resolves the alert its output raised.
  - Agents that cannot check package updates on their platform (for example Windows) say so; check updates on the host itself.
- **Inventory** lists storage, network interfaces, discovery records, and technical details.
- **Monitoring** shows how the device is collected, the SNMP and Agent setup, checks, sharing, and removal.

Each tab loads only the data it shows. Devices that cannot run the Agent, such as switches, printers, and IoT devices monitored by SNMP, do not offer Agent setup. Workload and Software detail pages keep a single page without tabs.

The hardware resource detail page shows its source, last-seen time, recent telemetry and configured checks. Each utilization reading uses the time of its own measurement, not the latest update from any source. CPU, memory, and storage turn amber at 80% and red at 90%. If SNMP or the Agent has not reported for more than 15 minutes, or the last SNMP poll failed, a warning appears at the top of the page with a link to the relevant settings tab. A host's own location is changed in its Settings; containers, VMs, and checks show where they inherit it from. After linking hardware to a managed Server, use its settings tabs. Hardware settings cover the host itself; website, TCP, DNS, and TLS checks for its services are managed in Software. Leaving the page with unsaved changes asks for confirmation first:

- **Access** for Agent invitation and credentials.
- **SNMP** for device version, credentials, profile, and polling options.
- **Information** for address, location, environment, and ownership metadata.

Collection changes apply to future polls; they cannot create historical measurements.

Owners can permanently remove unlinked local resources from their detail page, including active recurring checks; this also deletes their telemetry and check history. Removing a previously deleted managed-host record also removes software resources still linked to the same local collector and exact address. Deleting a managed Server removes all inventory resources and history linked to that Server. These removals cannot be undone.