# Sadapp Host Agent for Windows (alpha)

## Alpha installation (recommended)

The alpha MSI for Windows 10/11 and Windows Server 2019+ (x64) is a normal
Windows installer. It is **not code-signed yet**, so Windows SmartScreen shows
"Windows protected your PC" / "Unknown publisher". This is expected for the
alpha; no certificate has to be imported or trusted.

1. Download `sadapp-host-agent-<version>-windows-x64.msi` and `CHECKSUMS` from
   the Sadapp install page or the GitHub release.
2. Optionally compare the hash with the `CHECKSUMS` entry:
   `Get-FileHash .\sadapp-host-agent-*-windows-x64.msi -Algorithm SHA256`
3. Double-click the MSI. In SmartScreen choose **More info** → **Run anyway**,
   then confirm the administrator (UAC) prompt.
4. Enroll and start the service from an elevated PowerShell (see
   [enrollment](#enroll-and-start) below).

Updates: install the newer MSI the same way; configuration and queued data
are kept. Remove via **Settings → Apps → Sadapp Host Agent → Uninstall**.

Do **not** import any certificate into `Root` for the alpha MSI. A trusted
publisher signature will replace the SmartScreen warning in a later release.

## Self-signed prototype (CI evaluation only)

The self-signed **prototype** bundle below is only used by the native CI
acceptance test. It is not intended for customers or enterprise distribution.
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
- `agent.log` and `agent.log.old` — service logs.

The service-specific SID has write access to this state directory; ordinary
users do not have access. These files persist through MSI upgrades and
uninstall.

## Capability and trust limits

The Windows prototype reports unsupported status for its unimplemented
optional collectors: ports, sensors, GPU, Docker, virtualization, host logs,
SMART, and package inventory. It omits load and feature booleans and VM type
rather than presenting those unsupported facts as collected data. The Windows
binary does not make a runtime Authenticode assertion; reports that require
this check identify it as `external_authenticode_check_required`. The build
workflow separately verifies the prototype executable and MSI signatures.

## Enroll and start

Enroll the machine from an elevated console, then start the service:

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
