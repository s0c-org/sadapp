# Troubleshooting

Start with the resource's last-seen time and source tags, then inspect the corresponding Agent, Monitoring Worker, or Local Network Collector status.

## Missing or `n/a` metrics

`n/a` means the source did not provide a valid sample for that metric. Confirm the device supports the counter, the correct source is enabled, and a recent poll completed. SNMP profiles cannot read vendor OIDs that the device does not expose. Do not treat missing data as zero.

## Local Network Collector tasks

```bash
sudo systemctl status sadapp-local-network-collector.service --no-pager
sudo journalctl -u sadapp-local-network-collector.service -n 100 --no-pager
sudo journalctl -u sadapp-local-network-collector.service -f
curl -fsS http://127.0.0.1:9168/health
```

The health endpoint is loopback-only. Check heartbeat freshness, applied configuration revision, task counters, and spool queue size. Confirm the collector's allowed CIDRs contain the target and the required capability is reported.

## Expired task lease

The control plane renews leases for tasks reported as running. A result that arrives after its lease was replaced is stale and is discarded; it cannot be attached to the newer attempt. Failed discovery tasks can be retried from collector task history, creating a new task with the saved scan parameters.

## Agent or SNMP not updating

- For Agent: inspect `sudo journalctl -u sadapp-host-agent.service -n 100 --no-pager`, then verify the server's Agent credential and last-seen time.
- For SNMP: verify v1/v2c community or v3 credentials, UDP port, target address, profile, and poller reachability.
- For worker checks: verify the assigned location is covered by an active worker.
- For LAN tasks: verify the LNC is active and the resource address remains inside its allowed CIDR.

After an audited forced Agent re-enrollment, reporting remains interrupted until a server administrator retrieves the new invitation from **Server settings → Access** and re-runs the Host Agent installer on that machine. Never share the invitation token with staff or include it in a support request.

When contacting support, include timestamps, task IDs, sanitized error messages, and version numbers. Never include community strings, passphrases, invitation tokens, or private key material.

For a staff investigation, include the response's `x-sadapp-request-id` header. Staff with an active, audited tenant debug session can search this ID in Admin V2 → Tenant inventory → tenant details → **API errors by request ID**. Only errors attributed to that tenant are returned, and IP addresses, email addresses, and credential-like values are redacted. Error records are retained for 14 days.

## Support and community feedback

Open **Support & feedback** from navigation. Use a private ticket for account-specific
investigations and select Monitoring, Notifications, Account, or Status pages. Include the
assigned resource name, timestamp, expected behavior, version, and Request ID where
available. Do not include credentials or invitation tokens.

Bug reports can be kept private or explicitly shared with the community. Feature
suggestions and their discussions are public to signed-in community members; comments
do not display account identity. Ticket messages remain private to the requester and
authorized support staff.

If a section or discussion cannot load, its error/reload action lets you retry without
recreating the request. Failed comments and ticket replies retain entered text. **Export
support data** exports only support records; use **Settings → Security → Your data** for
the full account export or deletion workflow.

### Support conversations

The support workspace separates existing conversations from **New support ticket**.
Search by subject and filter by status; **Needs your response** counts tickets waiting
for you across all pages. Hiding the new-ticket form preserves its draft on the current
page. Drafts are not saved across navigation or browser reloads.

- **Waiting for support**: support needs to review your request or latest reply.
- **Waiting for your reply**: staff have replied and need your response.
- **Resolved**: replying reopens the request for support.
- **Closed**: the conversation is read-only; create a new ticket and include the old
  ticket reference if you need further assistance.

Lists show 25 tickets per page; conversations show the latest 50 messages, with
**Older messages** and **Newer messages** controls. Internal staff notes are excluded
from customer conversations and message counts. The center and latest conversation
refresh every 20 seconds while visible, without clearing drafts or failed-action errors.
Older conversation pages refresh manually so reading is not interrupted.

Staff can filter the inbox to unassigned tickets needing support or tickets waiting for
customers, refresh conversations, and add public replies or clearly marked internal
notes. Single-ticket triage changes and their audit records are committed together.
The displayed ticket-age triage target is not a contractual or measured response-time
SLA. Staff updates to closed tickets do not automatically reopen them.

Messages accept up to 20,000 characters and ticket subjects up to 200. Do not include
credentials. Attachments, unread tracking, email delivery, and measured response-time
targets are not available in this core rollout.