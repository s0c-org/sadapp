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
New services can optionally set a **Fleet Map location** before continuing:
choose an approximate region or search the city directory and select a city-center
pin. This describes the service's hosting location, not the Monitoring Worker's
location or your browser's location. Existing-host checks inherit that host's
location; onboarding does not overwrite it. Unassigned local resources can inherit
their collector's location; other unknown locations remain unmapped.
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

REST supports multiple JSON field paths from one endpoint response. Add one
reading for each JSON number, boolean, or string field, with its own display name
and optional stable metric key; keys must be unique per endpoint. Paths use dot
notation and numeric array indexes, such as `sensors.0.temperature`.
Creation offers **Health and uptime**, **System metrics** and **Sensor readings**
JSON starters, each with a sample response. Select a starter and explicitly apply
its mappings; this replaces the current mappings, never the endpoint or credentials.
These are illustrative schemas, not vendor autodetection. Adjust paths to match
your endpoint, or leave **Custom JSON endpoint** selected.
Local REST settings let you select among multiple configured endpoint URLs.
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
Values must be JSON numbers, booleans, or strings up to 4,000 bytes. Strings
remain text and are not converted to numbers; nulls, arrays, and objects are not
readings. The response must still be valid JSON, so a plain-text `ok` body is not
accepted. Boolean and string readings are telemetry only and do not determine
the check result or service-health badge. Collector affinity is derived by the
backend from the endpoint host. Local REST uses endpoint
verification and recurring collector polling. Public REST uses updated Monitoring
Workers advertising REST capability, accepts GET only, requires a
successful 2xx JSON response, disables redirects and limits responses to 1 MiB and
10 seconds. Its minimum interval is 60 seconds. Public REST checks cannot switch
to local execution in place; create a local reading through onboarding instead.
Reading cards and charts use the display name; changing it retains the metric key
and history.

REST creation offers **No authentication**, **Bearer token**, or **API key / custom
header**. Only the host owner can add credentials. They are saved in the vault
before the check receives the reference, for both public workers and local collectors.
Authenticated creation requires HTTPS, including private targets. The token field
is masked, and credentials are not included in URLs, templates or browser draft storage.
An explicit retry reuses the saved vault reference while the credential is unchanged.

Public REST authentication can also be configured by the server owner in Software
settings using an authentication header name and value (for example,
`Authorization` and `Bearer <token>`). Values are stored in the encrypted secret
vault, not monitor configuration or API read-back. Empty fields preserve saved
headers; use **Remove saved authentication headers** to clear them. Authenticated
checks require HTTPS and never follow redirects. Replace or remove credentials
before changing the endpoint origin. Reserved transport/cookie/proxy headers,
line breaks and duplicate names are rejected.

This feature requires both updated control-plane code and workers reporting
`restAuth` support; older REST-capable workers are not assigned authenticated
checks. Saving settings schedules a check, not a successful authentication test.
Staff can preserve mappings but must hand endpoint/credential changes to the
owner for authenticated checks.

Leaving a modified form warns about unsaved changes. After creation, Software
opens the new check's settings at `/software/monitor%3A<id>/settings`, where its
configuration and lifecycle controls remain available. Creation schedules
monitoring and is not proof of a successful check.

In the service **Checks** tab, editors can pause or resume each linked monitor
directly. **Configure → Enable monitoring** also saves the enable state together
with target and executor changes. Pausing retains results and clears the next
scheduled check; resuming schedules a fresh check, not a successful result.
Adopting discovered hardware retains its discovering collector for ICMP when
that collector is active and advertises ICMP support. Otherwise no ping is
scheduled; it never falls back to legacy or public worker polling.
Resuming an older private worker check automatically reuses the host's linked
collector only when exactly one active, capable collector covers the target.
If coverage is missing or ambiguous, select a suitable collector in Configure,
select **Enable monitoring**, and save. Discovery alone and successful adoption
do not prove check reachability. Paused checks remain paused until resumed.
Public worker checks require a configured public target; only an actual
successful result confirms reachability. Private targets cannot resume on public
workers, including private IPv6 endpoints.
