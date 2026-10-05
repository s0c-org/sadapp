# Teams, access, and security

Sadapp separates account ownership, team membership, and server membership. Give each person the least privilege needed for their work.

## Server access

Server access roles are Owner, Admin, Editor, and Viewer. Owners control transfer and deletion; Admins manage configuration and access; Editors change operational settings; Viewers can inspect information without changing it. Team access can grant members access to multiple owned resources.

Use **Settings → Teams & access** to manage teams and **Server settings → Access** for a device's members and Agent credentials. Removing a person or revoking a credential takes effect independently of whether an Agent process is still running.

## Account security

Enable multi-factor authentication and store recovery codes securely. Invitation tokens and Agent keys are secrets: share them only with the intended host/operator, rotate them if exposed, and do not paste them into logs or tickets.

SNMP community strings and v3 passphrases are stored in the secret vault and are masked after saving. Use read-only SNMP credentials where the device supports them.