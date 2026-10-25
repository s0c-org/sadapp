# SadApp – open components

[![CI](https://github.com/s0c-org/sadapp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/s0c-org/sadapp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/s0c-org/sadapp)](https://github.com/s0c-org/sadapp/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

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

## Releases and CI

Download accepted packages from [Releases](https://github.com/s0c-org/sadapp/releases).
Linux package promotion requires successful platform, native-package, and public
source CI checks. Version tags initiate signed package drafts; stable publication
still requires operator review. Verify the signed checksum manifest against an
independently trusted signing-key fingerprint before installing.
GitHub release assets do not imply that APT/RPM repositories were updated.

CI runs on a repository-scoped self-hosted runner for trusted main pushes and
version tags only. Pull requests do not execute automatically on that host;
maintainers review and validate contributions before merging.

## How this repository is maintained

This is a **read-only mirror** generated from SadApp's private source repository. Every sync is a single snapshot commit. Pull requests are welcome: maintainers review them here and apply accepted changes upstream, and the next sync then publishes them.

## Security

Please report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). "SadApp" and the SadApp logo are trademarks and are not licensed under Apache-2.0.
