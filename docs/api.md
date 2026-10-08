# API and integrations

Sadapp exposes authenticated APIs for supported enrollment, resource, telemetry, and workspace workflows. The live API catalog is available to administrators in **Admin → API Docs**; the application pages and catalog are the source of truth for route availability and request schemas.

## Integration guidance

- Use the supported Agent invitation/install flow instead of embedding a long-lived secret in scripts.
- Use Local Network Collector enrollment for private-network tasks; its signed requests and CIDR policy are enforced server-side.
- Keep all API and collector credentials in a secret manager. Never put them in query strings, client-side source, or support logs.
- Respect owner/team access boundaries and server-side quotas.
- Treat retry responses and task idempotency as part of the API contract; do not assume a timed-out request was not accepted.

Public API behavior can change between releases. Consult the deployed API catalog for the version your workspace runs rather than relying on old copied examples.

## Public creator profiles

`GET /api/public/profiles/{username}` returns only opted-in, active, non-demo profiles and
their published templates. The optional positive integer `page` query selects a page of
up to 24 templates, with pagination metadata in the response. Private or inactive profiles
are not discoverable through this endpoint; voting also rejects templates whose creator
has hidden their profile.

## Own gallery templates

Authenticated, active accounts can list their own published and unpublished entries through
`GET /api/user/templates?page=1`. Pages contain at most 24 entries; the response has
`templates`, `publisher` (username and public-profile visibility), and `pagination`
(`page`, `pageSize`, `total`, `pages`).

Non-demo owners may use `PATCH /api/user/templates/{id}` with one or more of:
`title` (trimmed, 1-120 characters), `summary` (up to 500 characters or null), `category`
(up to 80 characters or null), and `published` (boolean). Publishing requires an enabled
public profile and username. Unknown fields and malformed bodies are rejected.

`DELETE /api/user/templates/{id}` permanently removes the owner's template and its votes,
but leaves source and installed status pages intact. Mutations return `{ "success": true }`;
unknown templates and another owner's templates both return 404. Layout edits use the
status-page republish endpoint, not this metadata API.