# Plans, quotas, and data retention

Workspace plans can enforce limits on resources such as managed Servers, credentials, and telemetry storage. The Settings and quota views show the applicable limit and current usage when those policies are enabled.

The public **Pricing** page shows base alpha allowances from the published plan
assigned to the alpha program. Fair-use values are guidance, not unlimited
capacity. Personal/team overrides can differ; **Settings / Plan & usage** shows
the effective allowances for your workspace. Public pricing does not expose
internal catalog notes, prices, memberships or account overrides. If the alpha
plan is unavailable, the page says so rather than substituting example limits.

## Telemetry retention

Retention policies control how long supported telemetry and check history is kept. Removing old samples is independent of disabling a source; a disabled Agent or poller stops future collection but does not itself erase historical data.

Before reducing retention or deleting resources, export any records your organization needs to keep. Account deletion and data requests are handled through the account/support workflows; team ownership and retention policies can affect what remains accessible.

If a quota blocks onboarding, review current usage, remove only resources your team no longer needs, or contact the workspace administrator about the plan policy.