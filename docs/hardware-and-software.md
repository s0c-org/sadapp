# Hardware and Software inventory

The two registers answer different questions:

- **Hardware** (`/hardware`) lists managed hosts and devices that can provide machine telemetry.
- **Software** (`/software`) lists services, websites, and configured reachability checks grouped by host. Containers and virtual machines belong in Hardware.

Host identity, Agent/SNMP credentials, access, shared alert policies and host maintenance
are available at `/hosts/[routeKey]/settings`, including for software-only hosts.
Software owns check creation, protocol configuration, testing, pause/delete and
Required/Advisory roles. Use **Add check** to open
`/software/new?host=[routeKey]`; see [Adding a check](software-add-check.md).
Shared host settings link back to Software and to SNMP trap history.

The former `/servers` interface no longer renders a separate fleet or settings
workspace. Its index redirects to Hardware, add redirects to onboarding, and host
links redirect through an access-checked destination resolver to canonical Hardware
or Software. Hosts without a canonical resource retain their telemetry detail view
under `/hosts/[routeKey]`. Bookmarked settings/trap links and query parameters remain
supported; old Checks tabs open Software and selected monitors are verified against
the authorized host before redirecting. Server APIs and database entities are unchanged.

## Location and check execution

Server **Physical location** is a free-form inventory note. **Map region** is selected separately; choose a country, subdivision, and city for a precise pin on your private fleet map. The public map remains at coarse regional resolution. Unselected or unrecognized locations are listed as not mapped rather than guessed from their text.

**Monitoring Worker Location** controls Worker-routed checks; it is not a physical location. ICMP, TCP and HTTP(S) monitors can use any active Local Network Collector owned by the server owner that advertises the required capability and allows the target network. Prior discovery or a linked local resource is not required for these checks. SNMP additionally requires a linked resource and verified SNMP credentials. DNS and TLS checks remain Worker-routed. A private IP requires an authorized local executor.

When changing an external target to an internal IP in Hardware or Software settings,
collector choices follow the new target's subnet, not the previously saved host IP.
The editor selects a matching local executor when available; the target and collector
can be saved together. A collector outside that subnet or without the required
capability is not offered.
In Hardware settings, **Configure a local check** uses the newly entered
preferred address and preselects an eligible collector.

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

Local TCP check settings also allow editing the target private IP within the assigned
collector's allowed CIDRs. Saving updates the service address, recurring check and
queued verification together; it does not change the linked host address or sibling
services. In service Settings, choose **Configure** for the individual check. Owners
can use its **Delete check** action even when the local Software resource is linked
to a host. This removes only that service and its history, leaving the host and other
checks intact; associated discovery findings are ignored.

## Resource detail and settings

### Software service workspace

Opening a grouped Software row goes to `/software/[id]?view=service`, showing the related checks rather than an arbitrary single check. Grouping follows the same host identity rules as the inventory: linked server first, then route identity, then an unambiguous normalized host address. Shared addresses belonging to multiple managed hosts are not merged automatically. Each child link opens its individual check.

- **Overview** shows the actual check count, latest observation, executor, and protocol results. Service timings are listed separately by check and protocol rather than substituting the newest ICMP, TLS, or HTTP measurement into one response-time figure. These are total check durations, not separately measured connection or handshake phases. Service Overview and History graphs include all service checks. Non-healthy checks are named explicitly without changing the existing aggregate health policy.
- **Checks** provides mobile-friendly cards with targets, protocols, executors, schedules, warnings, HTTP status, errors, and direct Results/Configure links.
- **History** has a shared one-hour, 24-hour, or seven-day window, separate latency and outcome graphs, endpoint reading trends, local check requests, and expandable results with safe protocol details and execution source. At most 500 representative observations per series are shown; these sampled results are not an uptime SLA. Missing latency does not hide a failed outcome. Visible history refreshes after every four active 30-second detail polls, rather than on every poll. Manual refresh and range changes also reload it.
- **Settings** (`/software/[id]/settings`) edits the selected check. Website settings include expected HTTP status and TLS verification; DNS includes expected addresses; TLS/website checks include certificate warning days. Executor choices include the server owner's active collectors, independent of the saved host IP. Change the target, select Local network collector and a collector covering the new address, then save together. Collector options show their allowed CIDRs; the API validates ownership, capabilities and networks. Primary checks still update their shared host settings.

Both service and check Settings now expose editable controls inline instead of a
navigation-only policy panel. The selected check's configuration appears directly
on service Settings; Configure opens the editor for another check.
**Monitoring Worker Location** uses the configured worker coverage values (for
example `eu_central`) and has a separate **Save worker location** action. This is
shared host routing for every Worker check on that host, not a per-check override;
it does not change physical placement or Local Network Collector execution.
**Host alerts** switches the existing shared notification policy on/off while
preserving its gateway and thresholds. Gateway management stays account-wide.
Inline **Maintenance** schedules or cancels windows for the linked host or one of
its Monitor checks, with explicit scope; individual check pages default to that
check, while grouped service pages default to the entire host. Team-wide windows
remain in workspace settings. Windows do not pause execution or rewrite recorded
outcomes. Viewers cannot change these controls.

Editors with a linked host can use **Add check** to open the host's check creation
form. Identity, credentials and access remain in shared host settings. Unlinked
local resources do not offer host controls; unified local TCP checks currently do
not have individual maintenance-window support. The linked host name in the
summary opens its host settings.

Supported monitor protocols and local collector capabilities are defined in
`lib/monitorProtocols.ts`, shared by the check API and both settings editors.
DNS and TLS remain worker-only. Unknown or future protocol names do not inherit
HTTP collector support. REST readings retain their separate endpoint workflow;
adding a protocol still requires its validation, executor, configuration and safe
result presentation, not just an entry in this catalog.

Check editors explain what the existing executors actually measure: ICMP
reachability, TCP connection establishment, TLS validation without HTTP or
STARTTLS, and HTTP GET/status checks. DNS is an IP address lookup through the
Worker's system resolver, not a configurable record-type/custom-resolver monitor.
All expected IPs must be present; additional answers are allowed. An empty
expectation accepts any non-empty address result. Both creation and editing
validate expected addresses as IP addresses. The schedule interval is not an
executor timeout setting.

Recorded protocol details use a shared explicit label/field allowlist. SNMP
summaries include finite, non-negative numeric CPU, memory, load, uptime,
processor-core and interface readings when reported. Labels identify percentages,
bytes and seconds. Missing readings are not filled with zero. Credentials, raw
device objects and unrecognized fields are not displayed.

States distinguish **Healthy**, **Warning**, **Failed**, **Waiting**, **Paused**, and **Stale**. A result becomes stale after three configured intervals with a minimum of five minutes. Paused checks never use old successful results as proof of current health. Warning results, such as filtered ICMP, do not imply a confirmed outage.

Configured monitor check settings include a **Service health role**:
**Required** (the default for every existing check) or **Advisory**. Only Required
checks contribute to the grouped service health badge in both the Software
inventory and service workspace. Advisory checks retain their actual individual
status, results, timing and history, including failures and warnings. A service
with only Advisory checks is **Waiting**, not Healthy, and its overview explains
that no Required checks are configured. Paused Required checks remain paused;
Advisory successes cannot make them Healthy. Unconfigured resources still report
missing monitoring coverage. This setting does not change execution, alert
delivery, maintenance, or availability calculations. Duplicate check configuration
retains the saved role. Local discovered checks without this setting remain Required.

Each check's latency and outcome charts share a full-width section: side by side on desktop, stacked on phones. Outcome charts use discrete Failed / Warning / Passed ticks and unfilled steps, not a continuous filled measurement. A single check card fills its available row.

Editors can schedule a test, pause/resume, delete individual checks, and duplicate saved check configuration without history or primary-host identity. “Check scheduled” only means queued, not passed. Viewer access remains read-only. Primary checks share target, enable state, and HTTP options with their host, but can be deleted independently after typing the check name. Deletion removes only that check and its history, cancels its outstanding collector tasks, and disables its mirrored host protocol schedule. The host and sibling checks remain; shared SNMP polling stays enabled when an enabled sibling requires it. Host saves do not recreate the deleted primary check. Use **Add check** in Software to create a replacement. Whole-host deletion remains in shared host settings.

**Waiting** means that no result has confirmed monitoring coverage, not a confirmed outage or a successful check. If it persists beyond the configured interval, verify executor availability and use **Test now**. Local TCP checks retain their recurring schedule when linked to a host.

Latest check health refreshes every 30 seconds while the page is visible,
including Settings and grouped service views. Refreshing observations preserves
unsaved check configuration and worker-routing drafts; it does not save them.

Public Monitoring Worker checks with stale results (three intervals, minimum five
minutes) can be claimed by another healthy registered worker, even outside the preferred
region. Active leases still prevent simultaneous execution. Private collector
checks never enter this fallback pool. Checks that have never returned a result
become eligible five minutes after their scheduled run.

A failed public check requests an independent worker observation before declaring
an outage. Until three consecutive failures and failures from at least two distinct
workers within the last three intervals (minimum five minutes) are available, the
result is a warning awaiting confirmation, not an outage alert. The original
failed outcome and executor remain visible. A successful alternate observation
clears the failure streak. Without another eligible worker, confirmation remains
pending rather than asserting an outage. Regional routing is a preference for these
public checks, not an isolation guarantee.

The worker region selector is shown directly below **Executor** in check settings.
It still controls routing for every Monitoring Worker check on the linked host,
not a per-check region. **Save worker location** saves routing independently of
**Save check**, and does not submit unfinished protocol fields. Local Network
Collector checks continue to use their selected collector, not this region.

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
Disabled SNMP does not produce stale-reading or failed-poll warnings, even when
old readings and collector records remain. Its source is shown as Inactive and
SNMP setup is available again; retained historical readings remain visible.

Owners can permanently remove unlinked local resources from their detail page, including active recurring checks; this also deletes their telemetry and check history. Removing a previously deleted managed-host record also removes software resources still linked to the same local collector and exact address. Deleting a managed Server removes all inventory resources and history linked to that Server. These removals cannot be undone.