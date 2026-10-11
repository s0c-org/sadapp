# Notifications

Notifications have three parts: a delivery gateway, a routing rule, and the event or alert that triggers delivery.

## Set up delivery

1. Open **Settings → Notifications → Gateways** and create a gateway profile for a supported provider.
2. Enter provider credentials in the secret fields and run the gateway test.
3. Add a routing rule that matches the relevant team, server, location, event type, and severity.
4. Attach an enabled notification policy to the servers that should generate infrastructure alerts.

An enabled gateway alone does not subscribe a server to alerts. Likewise, a policy without a matching route and working gateway cannot deliver a notification.

## Delivery state

Use notification history to distinguish queued, sent, retried, and failed deliveries. Provider rate limits, invalid credentials, unmatched routes, and disabled policies have different remedies. Avoid putting provider secrets in rule names or message bodies.

Manage message templates and routing under **Settings → Notifications**. For repeated failures, review the gateway test result, matching rule, and delivery record in that order.

### Overview

**Settings → Notifications** opens the Overview, with shortcuts to Gateways, Routing,
Messages, and History. Choose a statistics window or refresh to review delivery attempts,
gateway health, failures, and suppression. A quiet window or healthy gateway does not
prove routing coverage; use the routing simulator for that. Gateway setup remains under
**Gateways → Add or edit gateways**.

### Message defaults

Message templates can be customized before a gateway is configured. Switch between
**Alert** and **Recovery** without losing your draft. The preview uses synthetic samples
for threshold breaches, recovery, stale telemetry, offline servers, website failures,
or degraded workers; it is not an exact rendering of a provider's own interface.

For flow-routed messages, non-empty fields resolve in priority order: **flow output
override → gateway template → personal provider/default template → built-in**.
Title and message are resolved independently. These personal defaults do not replace
higher-priority overrides; follow the scope disclosure to edit routing or gateway
templates. Clearing or resetting a personal field keeps it on the built-in default.
Use `{{serverName}}` for the configured display name (with hostname fallback) and
`{{hostname}}` when the technical host name is specifically needed.

Search variables by name, description, or example, then insert at the cursor in the
last focused field. The floating Save bar appears for unsaved edits; discard restores
the saved draft. Switching provider or following an in-app link asks before discarding,
and closing or reloading the tab uses the browser's unsaved-changes warning.

The starter library distinguishes **general defaults** from **event-specific** text
and labels Alert/Recovery usage. General Minimal and Operations context starters work
across event types. Event-specific starters cover server outages, stale telemetry,
agent heartbeat loss, worker degradation, SMART, check failure/recovery, certificate
expiry, account security, digests, escalation, and maintenance. A recovery starter
targets recovery fields automatically, including when applied to a flow output.
Selecting a starter or preview event does not create a routing filter: use matching
conditions on a flow output to restrict event-specific messages.
An explicitly selected event uses its own reason and severity instead of an unrelated
scenario's incident description. Account, team, and data previews omit synthetic
server and metric context.

Use `{{eventLabel}}` for the readable event name and `{{eventType}}` for the internal
event code. Built-in template version 3 keeps unavailable metrics out of messages while
retaining actual zero readings and configured thresholds. Recovery describes the
cleared condition rather than asserting that the whole server is healthy. New defaults
apply only where no saved override takes precedence; personal, gateway, and flow
customizations are not rewritten.

**Send draft test**, under **Test and reset tools**, sends through an owned gateway
without saving. It bypasses routing and saved overrides and uses the gateway test's
synthetic values, not the selected on-screen scenario. Tests are recorded as
`TEST_MESSAGE`. Do not interpret them as validation of an effective routed message.

### History

History separates incident lifecycle status from delivery outcome. **Sent** requires
a successful delivery attempt; **Has failed attempts** includes earlier failures even
if a retry later succeeded. Filter by event, severity, lifecycle, delivery, or time,
and expand an alert for the rendered message, recorded template source, trigger
reasoning, redacted errors, retry timing, and troubleshooting links. On phones, filters
collapse and alerts use cards; page selection and bulk actions remain available.
Changing pages or filters clears selection to avoid acting on hidden alerts.

## Recovery notifications

Enable **Notify on recovery** in the server policy to receive a confirmed return to
healthy state. In the authoritative control-plane pipeline, a recovery is not a
low-severity breach or a repeated problem: the gateway's minimum breach severity and
the server's repeat interval do not discard it. Disabling recovery in the policy is
recorded as `EVENT_TYPE_FILTERED` with an explicit server-policy explanation.

Explicit gateway event subscriptions, maintenance/quiet hours, duplicate protection,
gateway health and delivery budgets still apply. A queued or successful delivery in
an isolated `NOTIFICATION_DELIVERY_MODE=sink` environment proves pipeline processing,
not delivery to a real provider.

## Scheduled maintenance

Open **Settings → Maintenance** to schedule a one-time window for a server, an entire
team workspace, or one check. Windows can start immediately or be scheduled up to one
year ahead and may last up to seven days. Server editors may manage server/check windows;
team admins may manage a workspace window. Applicable active windows suppress alert
delivery while preserving a `MAINTENANCE_WINDOW` entry in notification history. Public
check-history uptime charts omit samples taken during scheduled downtime. Monitoring
continues, and the window can be cancelled before it ends.