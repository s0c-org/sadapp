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