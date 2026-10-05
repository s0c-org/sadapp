# SadApp – open components

This repository contains the **open-source parts of [SadApp](https://sadapp.org)**, the infrastructure monitoring platform: everything that runs inside *your* network, so you can audit exactly what is installed on your hosts.

| Path | What it is |
|---|---|
| [`host-agent/`](host-agent/) | Rust agent installed on Linux servers. Reports inventory, metrics, Docker/SMART/package state to the SadApp API. Shipped as signed `.deb`/`.rpm`. |
| [`local-network-collector/`](local-network-collector/) | Rust service for LAN discovery and SNMP/ICMP/TCP collection inside private networks. Pulls signed tasks from SadApp, uploads results. |
| [`snmp-profile-engine/`](snmp-profile-engine/) | Rust library for SNMP device detection and profile evaluation, shared by the collector and the hosted monitoring worker. |
| [`snmp-profiles/`](snmp-profiles/) | Vendor SNMP profile catalog (JSON) and its JSON Schema. Contributions welcome. |
| [`install/`](install/) | The installer scripts served at `https://sadapp.org/install-*.sh`. |
| [`docs/`](docs/) | Customer documentation. |

The SadApp control plane (web app/API) and the hosted monitoring worker are **not** part of this repository.

## Build

Requirements: Rust stable (see each crate's `Cargo.toml` for the edition), Node.js ≥ 20 for profile tooling.

```bash
cargo test --locked --manifest-path snmp-profile-engine/Cargo.toml
cargo test --locked --manifest-path local-network-collector/Cargo.toml
cargo test --locked --manifest-path host-agent/Cargo.toml
node snmp-profiles/scripts/check-profiles.mjs snmp-profiles/profiles
```

Packaging (`nfpm`) and cross-compilation notes live in each component's README.

## How this repository is maintained

This is a **read-only mirror** generated from SadApp's private source repository. Every sync is a single snapshot commit. Pull requests are welcome: maintainers review them here and apply accepted changes upstream, and the next sync then publishes them.

## Security

Please report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). "SadApp" and the SadApp logo are trademarks and are not licensed under Apache-2.0.
