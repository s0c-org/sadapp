# Hardware and Software inventory

The two registers answer different questions:

- **Hardware** (`/hardware`) lists managed hosts and devices that can provide machine telemetry.
- **Software** (`/software`) lists services, websites, containers, and configured reachability checks.

## Location and check execution

Server **Physical location** is a free-form inventory note. **Map region** is selected separately; choose a country, subdivision, and city for a precise pin on your private fleet map. The public map remains at coarse regional resolution. Unselected or unrecognized locations are listed as not mapped rather than guessed from their text.

**Monitoring Worker Location** controls Worker-routed checks; it is not a physical location. Individual TCP or HTTP(S) monitors can instead use a linked, active Local Network Collector that advertises the required capability. ICMP, DNS, and TLS remain Worker-routed. A private IP still needs a check executor with network access to that address.

Monitor history reports success rate and failures separately from successful-check latency percentiles. P95 requires at least 20 latency samples; P99 requires at least 1,000. A low percentile does not mean a target is reachable if the failure rate is high.

## Discovered resources

Use **Discovery** (`/discovery`) to review unconfigured Local Network Collector findings. Pending candidates record an address, detected service/device kind, and limited evidence such as an open port; approving one adds it to the local inventory. These findings do not imply CPU, memory, or disk telemetry.

Approved LAN resources that have not yet been adopted stay in Discovery. Adopt a TCP service by enabling a recurring check; it then appears in Software. Link discovered hardware with Agent or SNMP to add it to Hardware. Paused or unconfigured LAN resources remain in Discovery, and adopted resources retain their `LAN` marker and available source tags.

Open a resource name for its detail page. TCP services have a saved port setting and a **Run TCP check** action. Hardware resources can be linked to a managed Server through **Set up Agent** or **Set up SNMP**; the existing resource is linked rather than duplicated. Agent setup requires installing the Agent on the host. SNMP setup requires valid device credentials.

## Resource detail and settings

The resource detail page shows its source, last-seen time, recent telemetry, configured checks, and (for discovered TCP services) recent one-time results. After linking hardware to a managed Server, use its settings tabs:

- **Access** for Agent invitation and credentials.
- **SNMP** for device version, credentials, profile, and polling options.
- **Information** for address, location, environment, and ownership metadata.

Collection changes apply to future polls; they cannot create historical measurements.