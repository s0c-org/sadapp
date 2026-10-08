# Status pages

Status pages publish selected service and incident information to viewers. They are separate from the private Hardware and Software registers.

## Create a page

1. Open **Status pages** from the workspace navigation and create a page.
2. Choose blank, built-in or community starting content and assign the services the page should expose.
3. Use **Layout** to add/configure cards and arrange them; use **Preview** to inspect saved content at desktop, tablet and mobile widths.
4. Configure visibility and the public slug in **Settings**, then explicitly **Save settings** to publish.
5. Open the public `/s/<slug>` URL in a signed-out browser to verify the published view.

Only add services and status details intended for public disclosure. Private host inventory, credentials, local addresses, and internal telemetry are not appropriate public-page content.

Use the page editor to update components and status messaging. Publishing a status page does not change monitoring configuration or alert routing.

## Builder workflow

The builder uses persistent sections at `/status-pages/<id>` (Layout), `/preview`,
`/settings`, `/incidents` and `/integrations`. Switching sections preserves unsaved inputs.
Old `/settings/status-pages/**` and `/status-pages/<id>/canvas` links remain compatible.
The header distinguishes Draft, Live, Suspended, saving and unsaved states.

**Advanced controls** reveal precise canvas/threshold/appearance configuration without
resetting hidden settings. Webhook and domain configuration lives in **Integrations**.
Settings use an explicit save; failed saves retain their inputs. Only metadata settings
are recoverable in the current browser tab after reload. Passwords, webhook secrets,
incident text and unsaved card configuration are not persisted in browser storage.
Recovery over changed server metadata requires an explicit restore/discard decision.
Leaving through a navigation link or reloading warns about unsaved changes.

Layout operations save one revision-checked atomic batch. Concurrent edits do not silently
overwrite a newer layout: reload the confirmed page or explicitly reapply your pending
change. Undo/redo uses the same confirmed save pipeline, not an independent local layout.
It does not undo page deletion or external webhook effects. Use list editing on mobile or
with a keyboard; ordinary card content can be selected/scrolled without dragging it.

Private preview uses the same rendering and authorized source data as the public page.
It shows **saved** data, never publishes a draft, and does not create a public share token
or reuse a visitor's password-unlock cookie. Save pending changes before refreshing it.
Unassigned or missing measurements are shown as missing data, not simulated uptime.
Live pages retain immediate-edit semantics: saved changes appear publicly immediately;
there is no separate hidden release draft.

Administrators can temporarily choose **List only** for the audited platform setting
`STATUS_PAGE_BUILDER_CANVAS_MODE`. List mode retains the atomic save pipeline, existing
widgets and public layouts; it does not restore the obsolete parallel canvas saver.

Password-protected pages require a password before publishing. Re-saving an unchanged
custom domain preserves its existing ownership verification; a changed domain needs a
new TXT verification. TXT verification confirms ownership, not routing or TLS readiness.

Incident reports support scheduled, active and resolved states, impact changes and
start timestamps. Resolving sets the resolution time; reopening clears it. Scheduled
maintenance reports do not schedule monitoring work or suppress alerts.

## Measurement cards and customization

The searchable card library groups cards by their data source. Source choices respect
service capabilities and page ownership; assigning a service does not grant access to it.

| Card | Content and options |
|---|---|
| Metric gauge | Latest available CPU, memory, disk, load or ping value; radial or bar display, warning/critical thresholds and a maximum where applicable. |
| Metric statistic | Latest, average, minimum or maximum recorded metric over the selected time window, with the number of available samples. |
| Metric chart | Recorded metric history, line or bar style, legend, color and optional thresholds. |
| Check history chart | Recorded TCP, TLS or DNS checks, or all supported check types; availability or response time, time window, line/bar style, legend and color. |
| Existing status/content cards | Service groups, uptime/status, incident information, text, images and the existing specialized monitoring cards remain available. |

Metrics include CPU utilization, memory utilization and disk utilization (percent),
one-minute load and ping latency (milliseconds), where supported by the assigned
Agent/SNMP/Ping source. Thresholds use the selected metric's unit; changing a label does
not convert units. Graphs do not install new protocol checks or run new probes.

Card titles and accent colors can be customized independently of their data source.
Advanced controls expose supported thresholds, graph appearance and precise layout
without resetting values when switched off. The external inspector leaves the card's
rendered preview unobstructed. Duplicate, reorder, compact and undo/redo are available;
deletion preserves existing gaps until **Compact** is requested.

No eligible service, unassigned service and missing measurements are not healthy states.
An empty history is shown explicitly rather than generating synthetic successful checks.
Statistics use available recorded samples, not an assumption of continuous monitoring.
Canvas previews and private/public pages share the same renderer. Graphs have accessible
names and numeric summaries, and measurement cards do not expose inventory or secrets.

Portable exports and gallery templates retain card type, graph/gauge options and layout
but remove real service IDs. Imported measurement cards need service assignment.
Template-gallery sample previews are illustrative, not measurements from the publisher.

## Manage gallery templates

**Publish to gallery** exports the page's portable layout to your public profile without
real server IDs. An active, non-demo account with a username and enabled public profile is
required. The live status page and the gallery template are separate: a draft/private
status page can provide a layout without exposing its live telemetry.

Open **My gallery templates** from the template store, status-page management or public
profile settings. This owner-only page also lists unpublished templates and allows you to:

- Edit the gallery title, summary and category without changing the source page.
- **Unpublish template** to hide just that template, preserving its votes and install count.
- **Publish template** to restore an unpublished template while your public profile is enabled.
- **Delete template** after confirmation to permanently remove it and its votes. Source pages
  and pages already installed from the template are not deleted.

To change widgets/layout, edit the source status page and **Publish to gallery** again.
Republishing replaces the gallery details/layout and makes that template public again.
Keep the source page's URL slug unchanged to update the same gallery entry; changing the
slug creates a separate entry. Unpublish or delete the old entry explicitly if needed.

Gallery/profile APIs and public template previews are not cached so new requests respect
unpublishing immediately. Copies already installed, downloaded, or loaded by visitors
cannot be recalled. Hiding the entire public profile continues to hide all its templates.