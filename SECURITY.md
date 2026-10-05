# Security policy

Please **do not** open public issues for security problems.

Report vulnerabilities privately via GitHub Security Advisories ("Report a vulnerability" on the *Security* tab) or by e-mail to **security@sadapp.org**. Include affected component, version, and reproduction steps.

We aim to acknowledge reports within 3 business days and to ship fixes for confirmed high/critical issues within 30 days.

## Supported versions

Only the latest released versions of `sadapp-host-agent` and `sadapp-local-network-collector` from the stable package channel receive security fixes.

## Package integrity

Packages from `deb.sadapp.org` / `rpm.sadapp.org` are signed with the key fingerprint
`2B2333E4F37359BADD4F72A6394AA75F2815A5C3`. The installers in [`install/`](install/) verify this fingerprint before trusting the repository.
