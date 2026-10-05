# SNMP profile catalog

Declarative JSON profiles that tell SadApp how to detect a device (sysObjectID / sysDescr evidence) and which scalars, tables and traps to collect.

- `profiles/*.json` – one profile per device family
- `snmp-profile.schema.json` – JSON Schema (draft 2020-12) every profile must satisfy
- `scripts/check-profiles.mjs` – quick structural check (`node scripts/check-profiles.mjs profiles`)
- `scripts/normalize-snmp-profiles.mjs` – normalizes vendor/device-class metadata

Profile `state` is one of `enabled`, `experimental`, `disabled`. New contributions start as `experimental`. Full semantic validation (OID syntax, metric names, detection weights) runs in the SadApp monitoring worker before a profile is enabled in production.
