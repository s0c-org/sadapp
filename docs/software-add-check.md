# Add a check in Software

Open **Add check** for a host-linked service in Software. The creation page is
`/software/new?host=<server routeKey>`; a preselected host is required and there is
no host picker. Owners, admins, and editors can create checks; viewers see a
read-only form. **Host settings** returns to `/hosts/<server routeKey>/settings`.
Hardware can pass `type=PING&target=<address>` to preserve an entered address.
The optional protocol must be in the supported catalog; unsupported values fall
back to PING. Without a target override the saved host address is used.
Collector eligibility is recalculated for the entered target.

Choose PING (ICMP), SNMP, TCP, DNS, TLS, or HTTP(S), a target, interval, and
**Required** or **Advisory** service-health role. DNS optionally accepts expected
IP addresses. TLS and HTTP(S) expose certificate-warning days; HTTP(S) also
exposes expected status and certificate verification. Protocol hints describe
what each check actually verifies.

Private targets require an active Local Network Collector with the protocol
capability and allowed network. DNS and TLS do not support local execution.
SNMP additionally requires linked, verified host credentials and enabled polling;
the creation form does not edit credentials. The existing API remains
authoritative and displays validation or permission failures without discarding
the draft.

Leaving a modified form warns about unsaved changes. After creation, Software
opens the new check's settings at `/software/monitor%3A<id>/settings`, where its
configuration and lifecycle controls remain available. Creation schedules
monitoring and is not proof of a successful check.
