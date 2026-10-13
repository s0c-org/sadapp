# Teams, access, and security

Sadapp separates account ownership, team membership, and server membership. Give each person the least privilege needed for their work.

## Server access

Server access roles are Owner, Admin, Editor, and Viewer. Owners control transfer and deletion; Admins manage configuration and access; Editors change operational settings; Viewers can inspect information without changing it. Team access can grant members access to multiple owned resources.

Use **Settings → Workspace & access → Teams** to manage teams, **Server access** for account-wide access administration, and **Server settings → Access** for a device's members and Agent credentials. Removing a person or revoking a credential takes effect independently of whether an Agent process is still running.

Team owners and admins can use **Teams → Shared resources → Add server** to grant
Viewer, Editor or Admin access to a server they own or administer. This shares
the host and its linked workloads and checks with every team member without
changing ownership, billing or quotas. Selecting an already shared server updates
its grant. Use **Hardware settings → Access → Team access** to select recipient
teams, update grants or remove access; only active teams you own or administer
are eligible.

The separate **Hardware settings → Info → Workspace** selector moves an owned
server between personal and team billing workspaces. This changes the plan,
quotas and retention that apply; it is not a team-access grant. Team-loading
failures are displayed with a retry action rather than hiding the selector.

## Settings workspace

The Settings home groups destinations into Account, Workspace & access, Monitoring,
and Alerting & communication. Search matches names, descriptions and related terms
(for example, "SNMP collector"). The account summary keeps email verification,
multi-factor status, connected sign-in methods and profile editing together.
Account identity is separate from the explicitly published Public profile.

Each settings page has a breadcrumb back to Settings, related section links and a
cross-group destination selector. Notification pages keep their own Overview,
Gateways, Routing, Messages, History and Preferences navigation. Legacy profile
and status-page URLs retain their redirects.

Agent registrations separate Awaiting agent, Expired and Completed enrollment
links. Active links are hidden until revealed; copying, renewal and revocation
report their results. Revocation requires confirmation and does not remove an
already connected device. Renewal returns the link to use next.

Maintenance uses local browser time, validates a positive duration of at most
7 days and asks for confirmation before cancellation. Cancelled maintenance
resumes alerting unless another applicable window remains active. Demo accounts
show a read-only explanation.

## Account security

Enable multi-factor authentication and store recovery codes securely. Invitation tokens and Agent keys are secrets: share them only with the intended host/operator, rotate them if exposed, and do not paste them into logs or tickets.

SNMP community strings and v3 passphrases are stored in the secret vault and are masked after saving. Use read-only SNMP credentials where the device supports them.

**Sign out** is available in desktop navigation, the sidebar (including collapsed mode),
and the mobile bottom navigation. A failed sign-out is reported so you can retry; a
successful sign-out returns to the sign-in page.

## Public profile

Open **Settings → Public profile** to configure a username, biography, and explicit public
visibility. **My public profile** (`/u`) opens your published profile; if it is not configured
or is private, it opens profile settings instead. Signed-out visitors are prompted to sign
in before using that personal shortcut.

Public profiles show only public account fields and published status-page templates, not
email addresses or private inventory. Template listings have page navigation (24 items per
page). Hiding the profile also hides its templates from public discovery and voting.
Use **My gallery templates** to edit gallery details, unpublish individual templates,
republish, or delete them after confirmation without deleting the source status pages.
Website/social fields are not currently available.