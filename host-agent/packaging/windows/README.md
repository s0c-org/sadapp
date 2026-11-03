# Sadapp Host Agent for Windows (alpha)

## Alpha installation (recommended)

The alpha MSI targets Windows 10/11 and Windows Server 2019+ (x64). It uses
the same self-signed EXE/MSI bundle as native acceptance, not a separately
rebuilt unsigned package. Self-signing does not establish a trusted publisher:
Windows SmartScreen can still show "Unknown publisher". This remains an
evaluation release, not certification of every listed Windows edition.

1. Download `sadapp-host-agent-<version>-windows-x64.msi` and `CHECKSUMS` from
   the Sadapp install page or the GitHub release.
2. Optionally compare the hash with the `CHECKSUMS` entry:
   `Get-FileHash .\sadapp-host-agent-*-windows-x64.msi -Algorithm SHA256`
3. Verify the certificate thumbprint using an independent trusted channel;
   see [verification](#verify-and-install) before deciding whether to trust it.
   The installer never imports certificates automatically.
4. Install the MSI, then open **Start → Sadapp → Set up Sadapp Host Agent**.
   Approve UAC and follow the console prompts to enroll and start the service.
   No PowerShell commands or credentials in installer properties are required.

Updates: install the newer MSI the same way; configuration and queued data
are kept. Remove via **Settings → Apps → Sadapp Host Agent → Uninstall**.

Self-signed package trust is separate from API HTTPS trust. Never disable TLS
certificate validation to install or enroll this agent. A future trusted
publisher certificate can replace self-signing without changing enrollment,
the service identity or the MSI UpgradeCode. New builds use an ephemeral
certificate unless an operator explicitly supplies an existing signing identity;
do not assume the previous build's thumbprint remains valid.

## Self-signed evaluation signing

The self-signed **prototype** bundle is used for native CI and near-term alpha
evaluation. It is not a production-trusted enterprise distribution.
There is no Winget package, Microsoft Store package, or production-trusted
signing identity.

## Verify and install

Download the MSI named
`sadapp-host-agent-<version>-windows-x64.msi`, signed `sadapp-host-agent.exe`,
`prototype-signing.cer`, `Install-HostAgent.ps1`, `CHECKSUMS`, and
this document from the same trusted artifact source. Check
the MSI, executable, certificate, and helper script
hashes against `CHECKSUMS` before trusting the certificate. The prototype
certificate thumbprint is published by the build workflow; compare that
thumbprint over an independent trusted channel before importing it. A
self-signed certificate does not establish publisher identity by itself.
The package build does not add this certificate to a root store. The isolated
Windows CI smoke test temporarily trusts the certificate to verify the MSI and
executable, then removes that trust if the test added it.

From an elevated PowerShell session, after verifying the hash and thumbprint,
you may manually trust the certificate for code signing and install the MSI:

```powershell
$msi = Get-ChildItem .\sadapp-host-agent-*-windows-x64.msi | Select-Object -First 1
Get-Content .\CHECKSUMS
Get-FileHash $msi.FullName -Algorithm SHA256
Get-FileHash .\sadapp-host-agent.exe -Algorithm SHA256
Get-FileHash .\prototype-signing.cer -Algorithm SHA256
Get-FileHash .\Install-HostAgent.ps1 -Algorithm SHA256
Get-FileHash .\README.md -Algorithm SHA256
$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
  (Resolve-Path .\prototype-signing.cer).Path
)
$cert.Thumbprint
Import-Certificate .\prototype-signing.cer Cert:\LocalMachine\Root
.\Install-HostAgent.ps1 -MsiPath $msi.FullName
```

Compare the displayed thumbprint with the value printed in the corresponding
GitHub Actions run before importing the certificate. Verify the SHA-256 entries
for all downloaded files listed in `CHECKSUMS`.

The installer registers `SadappHostAgent` as an automatic (delayed-start)
service running as `NT AUTHORITY\LocalService`. It does not start the service
or accept credentials. The executable is installed under
`%ProgramFiles%\Sadapp\HostAgent`. The first-run configuration is encrypted
with machine-scope DPAPI and stored at
`FOLDERID_ProgramData\Sadapp\HostAgent\config.dpapi`, with access restricted to
Administrators, SYSTEM, and the service-specific SID. The service itself runs
as `NT AUTHORITY\LocalService` with its service SID set to `UNRESTRICTED`; the
installer test checks the SCM-reported SID type and the enabled SID in the
running service process token. That SID has read-only access to the config so
the service cannot replace enrollment credentials, while other LocalService
processes do not receive the config ACL grant.

The runtime resolves `FOLDERID_ProgramData` with `SHGetKnownFolderPath`
(rather than relying on an environment-variable override). Mutable application
state is separated from the protected config under
`FOLDERID_ProgramData\Sadapp\HostAgent\state\` (usually
`%ProgramData%\Sadapp\HostAgent\state\`):

- `telemetry-queue.json` — durable telemetry queued during network outages.
- `update-state.json` — update and rollback state.
- `event-log-state.json` — acknowledged Event Log bookmarks and pending delivery batch.
- `agent.log` and `agent.log.old` — service logs.

The service-specific SID has write access to this state directory; ordinary
users do not have access. These files persist through MSI upgrades and
uninstall.

## Capability and trust limits

The Windows prototype reports unsupported status for its unimplemented
optional collectors: sensors, Docker, and virtualization.
It omits load and feature booleans and VM type
rather than presenting those unsupported facts as collected data. The Windows
binary does not make a runtime Authenticode assertion; reports that require
this check identify it as `external_authenticode_check_required`. The build
workflow separately verifies the prototype executable and MSI signatures.

Version 0.2.9 adds NVIDIA GPU telemetry through the driver-provided
`nvidia-smi.exe` and AMD Radeon telemetry through the driver's System32
`atiadlxx.dll` ADL API. No separate AMD SMI installation is required on Windows.
Driver-dependent readings include utilization, edge/hotspot temperatures,
core/memory clocks, VRAM, power and fan percentage. Missing sensors remain
unavailable, not zero; Intel Windows GPU telemetry is not yet supported.
Queries are read-only and isolated with an eight-second deadline. The service
does not search the working directory or a user-controlled PATH for tools/DLLs.
Hardware and Server detail pages automatically show reported GPU gauges and
history, or explain collector unavailability. MSI upgrades preserve enrollment;
use `Install-HostAgent.ps1` without `--configure` or `--purge-state`.

### Windows Update and SMART (0.2.13)

The hourly slow lane reads **cached** Windows Update applicability through the
Windows Update Agent COM API, using the system Windows PowerShell executable.
Because WUA denies LocalService access on the native runner, the MSI installs
`SadappHostAgentInventory`, a **separate LocalSystem read-only service** using
the dedicated `--update-inventory-service` entrypoint. It starts independently
of enrollment, queries hourly, and atomically writes only
`%ProgramData%\Sadapp\HostAgent\windows-update-inventory.json` (both update and
optional SMART inventory). It has no
enrollment/configuration input, IPC listener, telemetry, update downloader or
installer path. The monitoring service remains LocalService and reads the
snapshot; its service SID has read-only access and cannot replace files in
the protected parent directory. Temporary snapshots are protected before
writing, not only after publication. Both services stop/remove on MSI
upgrade/uninstall; snapshots are retained through uninstall. Explicit purge
requires both services stopped and removes this known snapshot.

The monitoring slow lane waits up to 120 seconds for the initial snapshot and
rejects snapshots older than two hours, future-dated/malformed data and producer
errors. Reports retain the producer's observation timestamp. Helper write or
startup failures stop the helper with a nonzero SCM status and bounded recovery,
not a healthy fallback. Stop/shutdown cancels any in-flight subprocess. Console
collection queries WUA and optional SMART directly with the
console user's existing privileges. No helper is added to Linux builds.

It counts pending non-hidden software updates and the locale-independent
Security Updates classification, samples at most 15 titles, and reads WUA's
reboot-required flag. This is not a complete third-party application inventory
or a fresh online scan; cached results can be stale. The collector does not
download/install updates, change policy, start services explicitly, bypass
PowerShell execution policy, or elevate the monitoring service. WUA access/search errors,
partial search results, and the 60-second subprocess deadline mark `packages`
unavailable instead of reporting healthy zero counts. Agent lifecycle upgrade
timestamps remain agent upgrade timestamps, not fabricated Windows Update history.

SMART is optional: separately install trusted smartmontools in its standard
`ProgramFiles\smartmontools\bin\smartctl.exe` location. The agent does not search
PATH/current directory, install tools, elevate or change the monitoring service's
LocalService identity. The same read-only inventory helper performs the bounded
SMART queries with its existing System privileges, without granting raw-disk
access to the monitoring service. Missing tools and storage/driver access
failures report explicit health errors. Physical-disk
success still requires acceptance on the target hardware/controller and account.
Virtual disks, storage bridges and drivers may not expose SMART.

Queries are read-only (`--scan`, then `-a -j -n standby`), never self-tests or
setting changes. Up to eight drives are queried, with a five-second process
deadline each (including a separate scan deadline), 1 MiB stdout/16 KiB stderr
limits, and no intentional standby-drive wakeup. SMART failure/attribute bits
are accepted as disk health, not mistaken for tool failure; command/open/read
errors are explicit. Standby/unsupported drives without health are unavailable,
not healthy. Partial results are retained while collector health reports the
failure or device-budget limitation. Only sanitized existing health/temperature/
sector summaries are sent, never serial numbers or raw smartctl JSON.

### Ports and Event Log (0.2.12)

Native IP Helper calls collect TCP listeners and bound UDP endpoints for IPv4
and IPv6. The existing `{ protocol, port }` payload is sorted, deduplicated and
limited to 100, matching Linux's projection. UDP endpoints are bound sockets,
not proof that an application is accepting traffic. Remote addresses, process
owners and established TCP connections are not included. Native table allocation
is capped at 16 MiB and retries at four attempts.

The native Event Log API reads System and Application Critical/Error/Warning
events, up to 40 per channel per medium cycle (120 seconds by default). Read
loops have a two-second per-channel budget; individual native API calls are
synchronous, so this is not a hard wall-clock guarantee. Each native render
buffer is limited to 64 KiB; message text is limited to 4000 UTF-8 bytes.
Source/provider, original timestamp, severity and channel/event ID appear using
the existing Logs UI. Missing message metadata is reported in the event text.
Security, Information/Verbose events and arbitrary custom channels are excluded.
Collection does not clear logs, change their ACLs or request administrator rights.

First collection looks back 15 minutes. Service mode atomically persists the
pending batch and acknowledged bookmarks under the existing protected state
directory, with a 1 MiB state cap. Pending batches retry unchanged; bookmarks
advance only after a successful logs API response and durable acknowledgement.
This is at-least-once delivery: an API acceptance followed by a failed local
checkpoint write can result in a duplicate on retry. Console/test runs keep
in-memory state and do not read or overwrite the installed service's bookmarks.

Expired/cleared bookmarks trigger an explicitly reported 15-minute recovery
lookback. Events already lost to Windows retention/clear, or older than the
initial lookback, cannot be recovered. Access failures, invalid state and query
errors are reported as unavailable collection with diagnostics rather than
healthy empty measurements. One channel may still deliver when the other fails.
The new collectors do not add a subprocess per poll or run on Linux builds.

## Enroll and start

The installed Start-menu shortcut launches `sadapp-host-agent.exe --setup`.
Setup requests elevation, hides invitation/key secrets, saves the existing
DPAPI-protected configuration and offers to start the service. When enrollment
already exists, keeping it is the default; replacing it requires confirmation
and stopping a running service. Declining startup leaves the service stopped.
Setup is an interactive console wizard, not a graphical form.

The equivalent command is:

```powershell
& "$env:ProgramFiles\Sadapp\HostAgent\sadapp-host-agent.exe" --setup
```

For manual administration, enroll from an elevated console, then start the service:

```powershell
& "$env:ProgramFiles\Sadapp\HostAgent\sadapp-host-agent.exe" --configure
& "$env:ProgramFiles\Sadapp\HostAgent\sadapp-host-agent.exe" --validate-config
Start-Service SadappHostAgent
Get-Service SadappHostAgent
```

Configuration prompts for the endpoint and invitation token. A blank endpoint
uses `https://sadapp.org/api/v1/agent`. A blank token follows the agent's
interactive key-pair setup. Do not put credentials on the command line or in
installer properties.

### Service recovery and repair

The MSI configures delayed automatic startup and SCM restart attempts after
15 seconds for each of the first two crashes or error exits, then no further restart until
the failure count resets after one failure-free day. Normal service stops do
not trigger recovery. This prevents a permanently invalid configuration from
causing an unlimited restart loop. An operator can start the service manually
after correcting the failure.
Recovery actions use the pinned WiX Util extension rather than Windows
Installer's built-in failure-actions configuration, which fails with error 1939
on the native acceptance runner. Install it alongside WiX 5.0.2 with
`wix extension add -g WixToolset.Util.wixext/5.0.2` before manual package builds.

`--validate-service` checks the actual SCM recovery configuration. Re-running
Windows Installer in repair mode restores the executable, setup shortcut and
recovery configuration without replacing enrollment or queued telemetry.
For command-line repair, use `msiexec /famus <installed-version.msi>`; `/fa`
alone forces file replacement but does not request shortcut recreation.
No install or repair starts a fresh or deliberately stopped service. The
installation helper resumes a service that was running before an MSI upgrade.

A running service is not proof of API enrollment. Confirm fresh telemetry in
Sadapp and inspect `%ProgramData%\Sadapp\HostAgent\state\agent.log` for errors.

## Upgrade and removal

Run the included `Install-HostAgent.ps1` elevated for both initial installation
and updates. It does not start a fresh install; for upgrades it remembers
whether the service was running, lets Windows Installer stop it, then starts
it again. Configuration and other application data remain outside the MSI and
are retained during updates and uninstall.

### Reusing a signing identity

For a repeatable manual signing identity, create or provision a valid code
signing certificate in the build user's `Cert:\CurrentUser\My` store with its
private key. Pass only its thumbprint to the build script:

```powershell
.\Build-Prototype.ps1 -AgentExe .\sadapp-host-agent.exe -Version 0.2.6 `
  -OutputDirectory .\prototype-output -ExistingCertThumbprint <40-hex-thumbprint>
```

The build reuses but does not remove a caller-supplied certificate. Only its
public certificate is exported as `prototype-signing.cer`; no PFX, private
key, or key password is written to an artifact or passed in process arguments.
Without `-ExistingCertThumbprint`, the build creates a short-lived,
non-exportable certificate in `CurrentUser\My` and deletes its certificate and
private key from the runner during cleanup.

### Uninstall and purge

Uninstall from an elevated PowerShell session:

```powershell
$msi = Get-ChildItem .\sadapp-host-agent-*-windows-x64.msi | Select-Object -First 1
msiexec.exe /x $msi.FullName
```

The MSI stops and removes the service and installed executable but leaves the
DPAPI config and application data under
`FOLDERID_ProgramData\Sadapp\HostAgent`. Remove that state only after confirming it is no longer needed. The MSI removes
the installed executable, so retain the signed executable from the downloaded
artifact. From an elevated console, use its explicit purge command:

```powershell
& .\sadapp-host-agent.exe --purge-state
```

The MSI never collects credentials and does not purge state.

After evaluation, remove the manually trusted prototype certificate only if
it is no longer needed:

```powershell
Remove-Item "Cert:\LocalMachine\Root\$($cert.Thumbprint)"
```

Do not trust certificates automatically from an installer. Do not use this
prototype certificate as a production signing identity.

## Native prototype acceptance

Private Windows x64 run `37660227593` at source `96adb85` passed installed EXE/MSI
signature checks, LocalService/dedicated SID and delayed start, DPAPI/config/state
ACLs, running/stopped MSI upgrades, retained queued sample IDs, uninstall and
known-files-only purge. A real logged-on ordinary user and a separate LocalService
SCM service without the agent SID were denied file reads, directory enumeration
and writes. The independent ACL helper uses the runner's .NET Framework compiler
only for testing; the installed Rust agent does not require that helper or .NET.

The upgrade fixture reuses the runtime binary with different MSI versions. This
does not certify changed-binary upgrades, reboot, live HTTPS enrollment/replay or
every Windows client/server edition. The accepted bundle remains an explicitly
self-signed evaluation prototype, not publicly trusted production signing.

The foundation changes add native acceptance assertions for the Start-menu
shortcut, guided setup (including keeping enrollment and declining startup),
exact recovery configuration, actual process-crash recovery, deliberate stop,
and repair of a missing shortcut and altered recovery settings. These are
required gates for the new source, not results from the historical run above.

### Local validation from WSL

WSL can cross-build Windows x64 binaries using Rust's `x86_64-pc-windows-gnu`
target and a MinGW-w64 compiler, then execute those `.exe` files through Windows
interop. This is native Windows execution, unlike a cross-check alone; it does
not validate the MSVC packaging target or MSI service lifecycle.

On a standard-user Windows host, the portable unit-test subset can run without
changing the installed service. The queue and atomic-replacement tests apply
the production administrator/service-SID ACLs and require elevation; do not run
those tests unelevated or weaken the ACLs just to pass them.

`Test-Installer.ps1` is for an isolated elevated Windows VM/runner only. It
temporarily adds certificate trust, installs/removes a service, creates an ACL
test user and deliberately crashes its test service. It refuses machines with
existing agent state or a registered agent service. Never stop or uninstall a
real agent to make the test pass. Respect local script-execution policy; parsing
scripts is not the same as executing the native lifecycle gate.

## Windows equivalence rollout

The shared Rust core and native per-platform builds remain the architecture.
Windows-specific modules and dependencies are excluded from Linux builds.
Self-signed evaluation signing remains supported throughout this rollout.

1. **Installer/service foundation (0.2.11):** discoverable guided console
   enrollment, explicit service startup, bounded recovery, repair checks, and
   one signed, lifecycle-tested artifact for both prototype and alpha downloads.
2. **Everyday collectors:** native TCP/UDP endpoints and checkpointed/bounded
   System/Application Event Log land in 0.2.12. Cached pending/security updates,
   reboot state and optional read-only SMART land in 0.2.13. Preserve explicit
   unsupported/unavailable/permission-denied reporting.
3. **Managed upgrades:** verify signatures against an explicitly authorized
   publisher, preserve state, recover failed upgrades, and keep privileged
   updating separate from the LocalService monitoring process.
4. **Workloads/hardware:** protected Docker named-pipe transport, Hyper-V guest
   inventory, Intel GPU support and reliable additional hardware sensors.
5. **Release acceptance:** native changed-binary upgrade and rollback tests,
   reboot/sleep/resume, live HTTPS enrollment and outage replay, multi-day soak
   tests, measured CPU/RAM/I/O/network budgets, and an explicit tested OS matrix.

The three remaining unsupported optional collectors remain unsupported until their
individual implementations and native tests land. Windows stays experimental;
Linux regression checks or cross-compilation alone do not close native gates.

## Production signing preparation (not prototype CI)

The same payload authoring supports an operator-provisioned code-signing identity
without exporting its private key. Supply a publicly trusted certificate in
`CurrentUser\My`, its thumbprint and the CA's HTTPS RFC3161 timestamp endpoint:

```powershell
.\Build-Prototype.ps1 -AgentExe .\sadapp-host-agent.exe -Version 0.2.6 `
  -OutputDirectory .\signed-candidate -ExistingCertThumbprint <40-hex-thumbprint> `
  -TimestampUrl https://timestamp.example.com/rfc3161 -ProductionSigning
```

Replace the example URL with the signing provider's supported endpoint. Production
mode refuses missing identity/timestamp settings, self-signed identities and
untrusted/revoked chains. It does not provision a certificate, make a service
production-ready or publish a release. The existing output names/instructions
remain prototype-oriented; review production release documentation and acceptance
separately. Provider key custody, long-lived identity, renewal and expiry/revocation
acceptance are operator-owned gates. Prototype CI continues using self-signed
certificates and never disables normal API TLS verification.
