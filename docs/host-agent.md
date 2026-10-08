# Host Agent

The Host Agent is installed on the monitored host. Linux packages are available through
the signed repositories; Windows x64 service/MSI support is a self-signed prototype, not
a production or Microsoft Store release. It authenticates with an invitation or managed
key and reports the machine metrics and inventory that the host can provide. An Agent
must run on the device; a network discovery result cannot install it remotely.

## Install and enroll

1. In Sadapp, create or select a managed Server and open **Settings → Access**.
2. Create or renew an invitation token.
3. Open `/install`, choose **Host Agent**, and follow the command for the host's Debian/Ubuntu or RPM-based distribution.
4. Provide the invitation token to the installer when prompted. It is written to the local protected configuration and should not be copied into support messages.
5. Confirm the service is active and that the server's last-seen time advances.

The Agent makes outbound requests to the control plane; it does not require an inbound listener on the monitored host.

If staff force a credential reset during a time-bound, audited support investigation, the current Agent key stops working immediately. A server administrator can retrieve the replacement invitation under **Server settings → Access** and re-run the installer on the host to enroll it again. The invitation token is never shown to staff; do not send it in a support ticket.

## Logs and service health

```bash
sudo systemctl status sadapp-host-agent.service --no-pager
sudo journalctl -u sadapp-host-agent.service -n 100 --no-pager
sudo journalctl -u sadapp-host-agent.service -f
```

Use the journal for authentication, configuration, or connectivity failures. Do not paste credential files or invitation tokens into logs or tickets.

## Windows x64 prototype

Obtain the MSI and its public signing certificate/checksums from an authorized operator.
Self-signed means **not trusted by default**: verify the certificate fingerprint through
a separate trusted channel before explicitly trusting it on a test machine. Do not import
an unknown certificate to make an installation warning disappear. The certificate is for
code signing only; HTTPS certificate verification remains enabled. SmartScreen warnings
can remain even after explicit certificate trust.

The per-machine installer registers **SadappHostAgent** as an automatic, delayed-start
Windows service under **LocalService**, with a dedicated service SID. Fresh installation
does not start an unenrolled service. In an elevated PowerShell console, configure it:

```powershell
& "$env:ProgramFiles\Sadapp\HostAgent\sadapp-host-agent.exe" --configure
& "$env:ProgramFiles\Sadapp\HostAgent\sadapp-host-agent.exe" --validate-config
Start-Service SadappHostAgent
Get-Service SadappHostAgent
```

Enter the HTTPS API endpoint (blank uses the default), then the invitation token.
Leaving the token blank prompts for the key ID and secret instead. Secret prompts do
not echo input. Do not pass credentials through MSI properties or command-line arguments.
To rotate credentials, stop the service, run `--configure` again and restart it.
`--validate-config` checks decryption and configuration structure, not backend acceptance.
After starting, confirm successful sends in the log and an advancing last-seen timestamp
in Sadapp; a Running service alone does not prove that enrollment succeeded.

Configuration is stored as machine-DPAPI ciphertext in
`%ProgramData%\Sadapp\HostAgent\config.dpapi`. Administrators and SYSTEM have full access;
the specific service SID can read the configuration but cannot replace it. Mutable
telemetry queue, update state and logs live in the protected `state` subdirectory.
The service does not need LocalSystem, an inbound listener or a login session.
Machine-DPAPI configuration is not a portable backup of enrollment credentials.

```powershell
Get-Content "$env:ProgramData\Sadapp\HostAgent\state\agent.log" -Tail 100
Stop-Service SadappHostAgent
```

Use the verified, downloaded `Install-HostAgent.ps1` helper for MSI installation and
updates. It leaves a fresh install stopped and restarts an upgraded service only if it
was running before the update:

```powershell
.\Install-HostAgent.ps1 -MsiPath .\sadapp-host-agent-0.2.6-windows-x64.msi
```

The helper does not import or trust a certificate; complete the package's independent
fingerprint/hash verification and explicit prototype trust procedure first.
Updates preserve enrollment and queued measurements. Normal uninstall retains protected
data so reinstalling does not lose enrollment. To deliberately remove known local
configuration, logs and queued telemetry, stop the service and run `--purge-state` before
uninstalling. This command does not recursively delete the directory or unrelated files.
It does not delete the server record from Sadapp.

The prototype reports CPU, RAM, uptime, process and filesystem/network information
available to LocalService. Protected-process details may be inaccessible. Ports, hardware
sensors, GPU, SMART, Docker/Hyper-V guests, Windows Event Logs and Windows Update inventory
are explicitly **unsupported** in this prototype, not healthy empty measurements.
Linux load averages, CPU feature flags and VM-type detection are not asserted on Windows.
Unsupported collectors remain visible without generating false stale-collector warnings.
Update health requires an external Authenticode check; it does not claim the running
binary independently verified its own signature.

Native installation/update/uninstallation tests are defined in Windows CI. Until a green
native run and reboot test on a supported Windows machine, treat downloadable prototype
packages as experimental. There is no WinGet, enterprise deployment or Store publishing
in this prototype.

## Metrics

Agent telemetry can include CPU utilization, memory used/total, disk capacity, network counters, process count, load, and supported inventory. A metric appears only when the host reports a valid value. `n/a` means no usable sample is available; it is not a zero reading.

For container inventory and virtualization guests, enable the corresponding integrations on the host and confirm their payloads are present in the resource detail view. See [Metrics and history](../inventory/metrics-and-history).