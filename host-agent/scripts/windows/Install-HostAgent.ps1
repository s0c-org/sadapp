[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $MsiPath
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer helper from an elevated PowerShell session.'
}

$MsiPath = (Resolve-Path -LiteralPath $MsiPath).Path
$service = Get-Service -Name 'SadappHostAgent' -ErrorAction SilentlyContinue
$wasRunning = $null -ne $service -and $service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running

$installer = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" `
    -ArgumentList @('/i', "`"$MsiPath`"", '/qn', '/norestart') -Wait -PassThru
if ($installer.ExitCode -notin @(0, 3010)) {
    throw "Windows Installer failed with exit code $($installer.ExitCode)."
}

if ($wasRunning) {
    Start-Service -Name 'SadappHostAgent'
    $service = Get-Service -Name 'SadappHostAgent'
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
}

if ($installer.ExitCode -eq 3010) {
    Write-Output 'Installation succeeded; Windows requires a restart to complete it.'
} else {
    Write-Output 'Installation succeeded.'
}
