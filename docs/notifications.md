# Notifications

Notifications have three parts: a delivery gateway, a routing rule, and the event or alert that triggers delivery.

## Set up delivery

1. Open **Settings → Notifications** and create a gateway profile for a supported provider.
2. Enter provider credentials in the secret fields and run the gateway test.
3. Add a routing rule that matches the relevant team, server, location, event type, and severity.
4. Attach an enabled notification policy to the servers that should generate infrastructure alerts.

An enabled gateway alone does not subscribe a server to alerts. Likewise, a policy without a matching route and working gateway cannot deliver a notification.

## Delivery state

Use notification history to distinguish queued, sent, retried, and failed deliveries. Provider rate limits, invalid credentials, unmatched routes, and disabled policies have different remedies. Avoid putting provider secrets in rule names or message bodies.

Manage message templates and routing under **Settings → Notifications**. For repeated failures, review the gateway test result, matching rule, and delivery record in that order.

Message templates can be customized before a gateway is configured. Provider-specific templates apply when that provider is used; a template configured directly on a gateway takes precedence, and built-in templates are the fallback. Use `{{serverName}}` for the configured display name (with hostname fallback) and `{{hostname}}` when the technical host name is specifically needed.

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