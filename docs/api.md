# API reference and integrations

Use the [client API reference](/docs/api) to search endpoints by path, method or
summary. Select a group for Account, Resources, Servers & checks, Notifications,
Status pages, Support, Teams, Templates or Public. Expand an operation to see its
authentication requirement, path/query parameters, request and response examples,
and a copyable curl command. **Download OpenAPI JSON** exports the complete
client document, even while the reference is filtered.

## Authentication and safe examples

Protected client operations use the session cookie issued by browser sign-in.
They do **not** accept an arbitrary bearer API key. Public operations need no
session unless the operation explicitly requires one (for example gallery voting).
Signed acknowledgement links and password-protected status pages have their own
inline verification, documented alongside each operation.

Replace `https://example.com`, placeholder IDs and credential placeholders before
using examples. For session curl samples, set `SADAPP_SESSION_COOKIE` locally to
the entire cookie name/value pair. Never paste real cookies or provider secrets
into shared logs, source control or support reports. Examples are illustrative,
not credentials or live probe results; dates and current revision/hash values
must be refreshed before mutations.

A signed-in user can retrieve the same client OpenAPI 3.1 document with
`GET /api/user/api-docs`. The JSON endpoint is private/no-store and requires a
session. The reference itself is publicly readable within the docs shell.
Server/team permissions, account state, quotas and rate limits still apply.
Agent, worker, Local Network Collector protocol, system, cron, auth and staff
administration routes are deliberately excluded. Resource collector *configuration*
is a user operation and remains included; collector enrollment/ingestion is not.
The current client v1 namespaces are notifications and status pages; they use
sessions or explicitly documented public access. Do not use internal
worker/system keys as client API credentials.

## Common workflows

- Use stable server `routeKey` values rather than deprecated hostname routing.
- Fetch layout versions before atomic status-page edits; stale writes return 409.
- Simulate notification graphs and submit the returned hash with the unchanged
  graph before saving. Simulations do not deliver notifications.
- Public creator profiles expose only opted-in active profiles and published
  templates. Profile/template listing is paginated, with 24 entries per page.
- Gallery metadata changes and deletion affect the owner's gallery entry, not
  source/installed status pages. Use status-page template publication for layouts.
- Resource history supports persisted hourly Agent/SNMP host rollups for up to
  90 days, with no synthetic raw fallback. Docker does not retain hourly rollups;
  its API returns an explicit history message. SNMP hourly traffic rates are
  estimates from mean-counter deltas.
- Use supported agent/collector enrollment workflows instead of embedding
  long-lived credentials in scripts.

## Maintaining this reference

The build already runs `scripts/generate-api-catalog.mjs` before Next.js. The
catalog captures exported HTTP methods and source routes. After adding or changing
an endpoint:

1. Run `npm run generate:api-catalog` from `control-plane`.
2. Review the single audience boundary in `lib/apiDocs/audience.ts`. New public,
   user and support operations are included automatically except excluded
   infrastructure namespaces. New v1 namespaces require explicit audience review.
3. Read the actual handler and its validators/helpers, then add an explicit
   method/path entry to `lib/apiDocs/clientMetadata.ts`. Supply a summary, short
   description, auth mode, group, query parameters, actual response example and
   status/content type. POST/PATCH/PUT also require a request example. For a
   bodyless action use `{}` with `requestBodyRequired: false`; for DELETE with a
   body document that body explicitly. Use only placeholder identifiers and
   example.com addresses. Preserve array versus object envelopes and XML feeds.
4. Run `npx vitest run tests/api/client-api-docs.test.ts tests/api/client-api-examples.test.ts`
   and `npx vitest run -c vitest.ui.config.ts tests/ui/client-api-reference.test.tsx`.

The catalog coverage guard lists every missing method/path and required metadata
field, so a newly generated client operation cannot silently inherit a generic
summary or empty response example. Example-validation tests exercise the actual
request parsers for shared validation-heavy workflows. The administrator reference
continues to cover the full catalog separately.
