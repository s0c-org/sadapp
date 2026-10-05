# API and integrations

Sadapp exposes authenticated APIs for supported enrollment, resource, telemetry, and workspace workflows. The live API catalog is available to administrators in **Admin → API Docs**; the application pages and catalog are the source of truth for route availability and request schemas.

## Integration guidance

- Use the supported Agent invitation/install flow instead of embedding a long-lived secret in scripts.
- Use Local Network Collector enrollment for private-network tasks; its signed requests and CIDR policy are enforced server-side.
- Keep all API and collector credentials in a secret manager. Never put them in query strings, client-side source, or support logs.
- Respect owner/team access boundaries and server-side quotas.
- Treat retry responses and task idempotency as part of the API contract; do not assume a timed-out request was not accepted.

Public API behavior can change between releases. Consult the deployed API catalog for the version your workspace runs rather than relying on old copied examples.