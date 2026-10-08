# Teams, access, and security

Sadapp separates account ownership, team membership, and server membership. Give each person the least privilege needed for their work.

## Server access

Server access roles are Owner, Admin, Editor, and Viewer. Owners control transfer and deletion; Admins manage configuration and access; Editors change operational settings; Viewers can inspect information without changing it. Team access can grant members access to multiple owned resources.

Use **Settings → Teams & access** to manage teams and **Server settings → Access** for a device's members and Agent credentials. Removing a person or revoking a credential takes effect independently of whether an Agent process is still running.

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