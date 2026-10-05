# Contributing

Thanks for helping improve SadApp's open components.

1. Open an issue first for larger changes so we can agree on the approach.
2. Keep pull requests focused: one component, one concern.
3. Run the checks from the [README](README.md#build) before submitting.
4. New SNMP profiles go into `snmp-profiles/profiles/<vendor_device>.json`, must satisfy `snmp-profiles/snmp-profile.schema.json`, and should start with `"state": "experimental"`.

This repository is a mirror of a private upstream. Accepted pull requests are applied upstream and arrive back here with the next sync, so your PR shows as *closed* rather than *merged*. Your authorship is kept via a `Co-authored-by` trailer.

By contributing you agree that your contribution is licensed under the Apache License 2.0.
