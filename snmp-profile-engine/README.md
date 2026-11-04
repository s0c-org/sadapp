# Shared SNMP table execution

`profile_tables` validates camelCase `TablePlan` / `ColumnPlan` wire plans and
provides a transport-independent parser and normalizer. `ProfileColumns` maps
table name → column name → numeric OID suffix string → raw net-snmp value.
`parse_profile_column` returns `{ rows, issues }`;
`normalize_profile_tables` returns `(ProfileSnapshot, Vec<TableIssue>)`.
`plans_from_profile_json` converts schema-v1 `tables` maps.

Plans permit 16 tables, 32 columns per table, 128 columns total, and declared
`maxRows` of 1–10000. Executors separately enforce their transport budgets.
Indices are discovered, never pinned: `suffix`, `integer`, `inet_address`, and
`mac_address` validate numeric suffixes while retaining their wire identity.
Only numeric OIDs are executable. No shell, expression, or symbolic OID evaluation
is supported.

Numeric object columns produce their configured metric key, scale, unit and
shared scalar transform. Percentage and used-from transforms resolve related
columns within the same row, using each column's own scale. Aggregate/enum
transforms produce explicit invalid-plan diagnostics rather than guessed values.
STRING/object-identifier columns and compact string suffixes are metadata:
they have no metric key and become bounded `column_<name>` labels. All samples
also have `table_name` and `table_index`. Inventory indices remain strings, so
compound indices are not collapsed to integers.

Profile snapshots are bounded to 2048 metrics, 256 inventory rows, and 1 MiB.
Limit, malformed-value and incomplete-row issues are explicit; successful rows
remain usable. Missing values never become zero. Diagnostics contain configured
table/column names and stable codes, never raw tool/device output or credentials.

`standard_tables` supplies interface, ENTITY sensor/inventory, and HOST-RESOURCES
fixed-disk volume plans. Interfaces include octets, operational status, speed,
errors, discards, HC-unicast packet counters (32-bit fallback; canonical
`network.interface.receive.unicast_packets_total` and
`network.interface.transmit.unicast_packets_total`), and last change
as seconds since agent boot—not wall-clock time. Volumes expose total, used,
free bytes and used percent with `volume_index` / `name` labels and `volume`
inventory. Missing used values do not fabricate free/percentage values.
Standard limits are 128 rows per column, 4096 metrics, 384 inventory rows,
and 1.5 MiB. Use `normalize_standard_tables_with_issues` when retaining diagnostics.

`table_transport::execute_table_command_partial` kills/reaps bounded children
and retains complete stdout rows on size/deadline limits. Callers must report
the returned `limit` and must not cache partial discovery as complete.
`execute_table_command` retains the stricter all-or-error interface.
`DiscoveryCache<V, K>` permits per-column membership keys: a union of indices
alone is insufficient to detect row movement between columns/tables.

The JSON fixtures are synthetic protocol tests, not real-device acceptance.

## Capability discovery reports

`capability_discovery` builds bounded, privacy-preserving capability reports from the
columns a poll actually executed (approved standard tables plus the selected profile; no
full walks). Callers record one outcome per OID with `CapabilityRecorder::record_column`
and call `finish(profileChecksum, observedAt)`.

- `supported`: at least one valid row index was returned (a limit code may accompany it).
- `unsupported`: the request succeeded with no rows (noSuchObject/noSuchInstance/endOfMibView).
- `unknown`: timeout, auth, transport, parse or skipped outcomes. A timeout is never `unsupported`.
- Group status is the shared column status, or `partial` when columns differ.

Wire shape (`schemaVersion: 1`): `{schemaVersion, profileChecksum, observedAt, groups:[{name,
status, columns:[{oid, status, indexes, code?}]}]}`. Reports hold at most 16 groups, 256
columns, 128 indexes per column (64 characters each) and 64 KiB of JSON; only OIDs, row
indexes, statuses and known codes (`CAPABILITY_CODES`) are retained, never values.
`validate_report` accepts only that exact shape. `report_is_fresh` and `columns_to_poll` let
future polls skip `unsupported` OIDs only for the same profile checksum, within the 24-hour
TTL and without a reboot; `unknown` OIDs are always polled. Polling does not use them yet.
