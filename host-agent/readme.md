SadApp host agent quick usage

Windows x64 service/MSI prototype
-------------------------------

The Windows prototype runs under LocalService with a dedicated service SID.
See `packaging/windows/README.md` for self-signed MSI builds, explicit certificate
trust, native CI validation and limitations. This is not a Store/WinGet release.

After MSI installation, use an elevated PowerShell console:

```powershell
& "$env:ProgramFiles\Sadapp\HostAgent\sadapp-host-agent.exe" --configure
& "$env:ProgramFiles\Sadapp\HostAgent\sadapp-host-agent.exe" --validate-config
Start-Service SadappHostAgent
```

Configuration prompts hide the invitation/key secret; do not put credentials in
installer arguments. The HTTPS endpoint must not contain credentials, query or
fragment, and certificate validation stays enabled. Machine-DPAPI configuration
and service-specific Windows ACLs protect local enrollment.

Mutable state lives under `%ProgramData%\Sadapp\HostAgent\state`; logs are bounded
and queue replacement is atomic. Stop the service before changing configuration
or using `--purge-state`. Upgrades and ordinary uninstall retain protected data.

The Windows prototype explicitly marks ports, sensors, GPU, Docker/virtualization,
system logs, SMART and package-update collectors unsupported. It does not publish
Linux-only feature flags, VM type or load averages as Windows facts. Native Windows
runtime tests are separate from a successful Linux-to-Windows cross-build.

Linux/manual console usage
--------------------------

1) First registration (one run, then exits)
Use the values from /servers/add (invitation link + key pair).

cargo run -- \
	--invitation-link=https://sadapp.org/api/v1/agent?invite_token=YOUR_TOKEN \
	--key-id=YOUR_KEY_ID \
	--key-secret=YOUR_KEY_SECRET \
	--interval=30

You can also pass only a token:

cargo run -- --invite-token=YOUR_TOKEN

Or with the legacy alias:

cargo run -- --invitation=YOUR_TOKEN

2) Ongoing monitoring (continuous)

cargo run -- \
	--endpoint=https://sadapp.org/api/v1/agent \
	--key-id=YOUR_KEY_ID \
	--key-secret=YOUR_KEY_SECRET \
	--interval=30

Environment variable equivalents:

API_ENDPOINT=https://sadapp.org/api/v1/agent
API_KEY_ID=YOUR_KEY_ID
API_KEY_SECRET=YOUR_KEY_SECRET
API_INTERVAL_SECONDS=30
API_MEDIUM_COLLECTOR_INTERVAL_SECONDS=120
API_SLOW_COLLECTOR_INTERVAL_SECONDS=3600
DOCKER_HOST=unix:///var/run/docker.sock
API_UPDATE_CHANNEL=stable
API_DESIRED_AGENT_VERSION=
API_UPDATE_STATE_PATH=/var/lib/sadapp-host-agent/update-state.json
API_QUEUE_PATH=/var/lib/sadapp-host-agent/telemetry-queue.json
API_QUEUE_MAX_SAMPLES=200

The heartbeat lane refreshes CPU, memory, load, uptime, and process data. Docker, disk, network,
GPU, and log collection run in a background lane every 120 seconds by default. SMART and package update
checks run in a background lane every hour. Static host inventory is collected once at startup.
Install `smartmontools` to enable SMART collection; the agent continues without SMART data when
`smartctl` is unavailable. One-time registration waits for complete collector snapshots before it
submits and exits.

Docker inventory is read through the Docker Engine API over `DOCKER_HOST` (Unix sockets only); the Docker CLI is not required. Access to the Docker socket grants host-root-equivalent control, so keep the agent service restricted and do not expose an unauthenticated TCP Docker API. On Proxmox VE nodes, the agent uses local `pvesh` read queries to collect QEMU and LXC guest state and utilization. The packaged service runs as root to access local PVE data. Other hypervisors do not yet have guest enumeration adapters.

GPU telemetry supports multiple devices and reports identity, driver, PCI address, utilization,
dedicated memory, temperature, power, and fan speed when the installed driver exposes them. NVIDIA
metrics use the driver-provided `nvidia-smi` command. AMD and Intel metrics use Linux DRM/sysfs, so
no vendor SDK is required. Unsupported measurements remain absent rather than being reported as
zero, and hosts without a supported GPU report an empty device list.

Stable and canary updates use the operating system package manager. APT Release/Packages metadata
and RPM packages/repository metadata are signed, so artifact verification remains in the native
package trust chain. The setup scripts record the selected channel in the agent environment file.
On startup, the agent persists its installed version and reports upgrades, desired-version drift,
and successful rollback when a lower version replaces the previous binary. SIGINT and SIGTERM
interrupt the polling wait, trigger one final heartbeat attempt, and leave failed delivery in the
persistent queue before exit.

Failed heartbeats are persisted atomically and replayed oldest first, one per collection cycle.
Retries use exponential backoff with jitter. The queue keeps at most 200 samples by default and
drops the oldest sample when full. Packaged installations create the state directory with mode
0700; queue files use mode 0600. Override `API_QUEUE_PATH` for unprivileged manual runs.

Optional invite env vars:

API_INVITATION_LINK=https://sadapp.org/api/v1/agent?invite_token=YOUR_TOKEN
API_INVITE_TOKEN=YOUR_TOKEN

3) ARM cross-compilation notes

The `aarch64-unknown-linux-gnu` and `armv7-unknown-linux-gnueabihf` builds are GNU/glibc-targeted.
They will run on systems with a compatible glibc, but the exact minimum version depends on the
sysroot used at build time.

If you need compatibility with glibc 2.31-13, build on a Debian 11 / bullseye sysroot or inside a
matching container image. Host builds on newer distributions can pick up newer GLIBC symbols and
produce binaries that will not run on older ARM systems.

If you need a binary that avoids glibc compatibility issues entirely, use a musl-based target and a
static build toolchain instead.

4) Debian 11 x64 build for old Linux hosts

If you must run on older kernels/userspace (for example Linux 3.18) and want to avoid glibc symbol
constraints such as GLIBC_2.13, build a static musl binary.

Run:

./scripts/build_debian11_x64_legacy.sh

Output:

target/x86_64-unknown-linux-musl/release/sadapp-host-agent

Note: A Debian 11 GNU/glibc dynamic build cannot be capped to GLIBC_2.13 reliably. For that strict
constraint, static musl is the practical and supported path in this project.