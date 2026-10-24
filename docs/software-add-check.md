# Add a check in Software

Every service **Add check** action opens `/onboarding?flow=check`. With host or
service context, onboarding prefills the host, generated name, target, detected
port, interval and applicable saved check options. Without context, either create
a **New service** with a name and target, or choose an existing editable host.
New services do not require connected hardware. **Continue with new service**
creates its shared service identity, then opens the check configuration with the
target prefilled (HTTP(S) for URLs, Ping otherwise). Monitoring starts only after
**Create check**; if you leave configuration unfinished, select that service from
the existing-host list to finish later. Choosing an existing host never duplicates it.
Owners, admins, and editors can create checks; viewers cannot modify them.
**Duplicate** also opens onboarding for review rather than creating immediately.
Existing `/software/new` bookmarks redirect while preserving context.

Software uses the same Connection setup progress header, form panels and live
connection-summary sidebar as Hardware and Local Network Collector onboarding.
Choose a check type from the protocol cards before creating a service or selecting
an existing host. The selected protocol carries into configuration and remains
editable there; the summary follows the selected service, target and automatic
executor.

Links can pass `host=<routeKey>`, `resource=<resource ID>`, `type`, `target` and
`port`. The service must belong to the selected host. Unsupported protocol values
fall back to PING. Changing between a URL check and Ping/TCP converts the target
appropriately; customized names are retained.

Choose PING (ICMP), TCP, DNS, TLS, HTTP(S), or REST, a target and interval, and
**Required** or **Advisory** service-health role. DNS optionally accepts expected
IP addresses. TLS and HTTP(S) expose certificate-warning days; HTTP(S) also
exposes expected status and certificate verification. Protocol hints describe
what each check actually verifies.

Ping, TCP, Website and REST automatically choose a Local Network Collector for
private IP targets, or a Monitoring Worker for public targets. Collector choices
are recalculated when the target changes and must have the required capability,
active status and allowed CIDR. Missing coverage blocks creation instead of
sending a private target to public workers. Automatic private-network detection
uses literal IPv4/IPv6 addresses; use a private IP in local endpoint URLs rather
than an internal-only DNS name. DNS and TLS do not support local execution.
SNMP device telemetry is configured under Hardware, not Software onboarding.
The existing API remains
authoritative and displays validation or permission failures without discarding
the draft.

REST needs a JSON field path, reading name and optional stable metric key.
Local REST is enabled on creation and starts recurring polling automatically after
successful endpoint verification. Failed verification blocks recurring polling;
Checks shows that state rather than claiming no collection is configured. Review
the collector task error and correct the endpoint before retrying. **Retest REST
endpoint** in check settings queues verification using the saved URL, mappings and
vault credentials, including all saved readings. Save or discard edits first.
Successful retesting enables recurring polling, including for a previously paused endpoint.
The endpoint must return valid JSON; a missing or incorrect `Content-Type` header
is logged as a collector warning rather than blocking valid readings.
This relaxed header handling requires an updated Local Network Collector.
Values must be JSON numbers, not numeric strings. Local REST uses endpoint
verification and recurring collector polling. Public REST uses updated Monitoring
Workers advertising REST capability, accepts unauthenticated GET only, requires a
successful 2xx JSON response, disables redirects and limits responses to 1 MiB and
10 seconds. Its minimum interval is 60 seconds. Public REST checks cannot switch
to local execution in place; create a local reading through onboarding instead.
Reading cards and charts use the display name; changing it retains the metric key
and history.

Leaving a modified form warns about unsaved changes. After creation, Software
opens the new check's settings at `/software/monitor%3A<id>/settings`, where its
configuration and lifecycle controls remain available. Creation schedules
monitoring and is not proof of a successful check.
