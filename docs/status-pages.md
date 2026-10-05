# Status pages

Status pages publish selected service and incident information to viewers. They are separate from the private Hardware and Software registers.

## Create a page

1. Open **Settings → Status pages** and create a page.
2. Add components for services the page should expose.
3. Configure visibility and the public slug, then publish.
4. Open the public `/s/<slug>` URL in a signed-out browser to verify the published view.

Only add services and status details intended for public disclosure. Private host inventory, credentials, local addresses, and internal telemetry are not appropriate public-page content.

Use the page editor to update components and status messaging. Publishing a status page does not change monitoring configuration or alert routing.