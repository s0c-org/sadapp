[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $MsiPath,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $UpgradeMsiPath,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $CertificatePath,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $ChecksumPath,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $AgentExe,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $InstallScriptPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string] $AgentVersion
)

$ErrorActionPreference = 'Stop'
$MsiPath = (Resolve-Path -LiteralPath $MsiPath).Path
$UpgradeMsiPath = (Resolve-Path -LiteralPath $UpgradeMsiPath).Path
$CertificatePath = (Resolve-Path -LiteralPath $CertificatePath).Path
$ChecksumPath = (Resolve-Path -LiteralPath $ChecksumPath).Path
$AgentExe = (Resolve-Path -LiteralPath $AgentExe).Path
$InstallScriptPath = (Resolve-Path -LiteralPath $InstallScriptPath).Path

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The native installer test requires an elevated runner.'
}

$serviceName = 'SadappHostAgent'
$installDirectory = Join-Path $env:ProgramFiles 'Sadapp\HostAgent'
$installedExe = Join-Path $installDirectory 'sadapp-host-agent.exe'
$null = Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class SadappKnownFolders
{
    private static readonly Guid ProgramDataFolderId = new Guid("62AB5D82-FDC1-4DC3-A9DD-070D1D495D97");

    [DllImport("shell32.dll")]
    private static extern int SHGetKnownFolderPath(
        [MarshalAs(UnmanagedType.LPStruct)] Guid folderId,
        uint flags,
        IntPtr token,
        out IntPtr path);

    [DllImport("ole32.dll")]
    private static extern void CoTaskMemFree(IntPtr memory);

    public static string GetProgramData()
    {
        IntPtr path;
        int result = SHGetKnownFolderPath(ProgramDataFolderId, 0, IntPtr.Zero, out path);
        if (result != 0)
        {
            Marshal.ThrowExceptionForHR(result);
        }

        try
        {
            return Marshal.PtrToStringUni(path);
        }
        finally
        {
            CoTaskMemFree(path);
        }
    }
}
'@
$programDataPath = [SadappKnownFolders]::GetProgramData()
if ([string]::IsNullOrWhiteSpace($programDataPath) -or -not [IO.Path]::IsPathRooted($programDataPath)) {
    throw "SHGetKnownFolderPath returned an invalid ProgramData directory: '$programDataPath'."
}
$dataDirectory = Join-Path $programDataPath 'Sadapp\HostAgent'
$sadappDirectory = Join-Path $programDataPath 'Sadapp'
$configPath = Join-Path $dataDirectory 'config.dpapi'
$stateDirectory = Join-Path $dataDirectory 'state'
$queuePath = Join-Path $stateDirectory 'telemetry-queue.json'
$updateStatePath = Join-Path $stateDirectory 'update-state.json'
$logPath = Join-Path $stateDirectory 'agent.log'
$sentinelPath = Join-Path $stateDirectory 'unrecognized-test-state.txt'
$expectedSids = @('S-1-5-18', 'S-1-5-32-544')
$ownerRightsSid = 'S-1-3-4'
$sha1 = [Security.Cryptography.SHA1]::Create()
try {
    $serviceSidDigest = $sha1.ComputeHash([Text.Encoding]::Unicode.GetBytes('SADAPPHOSTAGENT'))
} finally {
    $sha1.Dispose()
}
$serviceSidParts = for ($offset = 0; $offset -lt $serviceSidDigest.Length; $offset += 4) {
    [BitConverter]::ToUInt32($serviceSidDigest, $offset)
}
$serviceSid = 'S-1-5-80-' + ($serviceSidParts -join '-')
$importedCert = $null
$addedRootTrust = $false
$signTool = Get-ChildItem -Path (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin\*\x64\signtool.exe') -ErrorAction Stop |
    Sort-Object { [version]$_.Directory.Parent.Name } -Descending |
    Select-Object -First 1 -ExpandProperty FullName
$testUser = 'SadappMsiAclTest'
$testUserCreated = $false
$installed = $false
$installedMsiPath = $MsiPath

$null = Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class SadappServiceTokenInspector
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;
    private const int TokenGroupsInformation = 2;
    private const uint GroupEnabled = 0x00000004;

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        IntPtr token, int informationClass, IntPtr information, int informationLength, out int returnLength);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr stringSid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    public static bool HasEnabledGroup(int processId, string expectedSid)
    {
        IntPtr process = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (process == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess failed");
        }

        try
        {
            IntPtr token;
            if (!OpenProcessToken(process, TokenQuery, out token))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed");
            }

            try
            {
                int requiredLength;
                GetTokenInformation(token, TokenGroupsInformation, IntPtr.Zero, 0, out requiredLength);
                int error = Marshal.GetLastWin32Error();
                if (requiredLength <= 0 || error != 122)
                {
                    throw new Win32Exception(error, "Cannot size the service token group buffer");
                }

                IntPtr information = Marshal.AllocHGlobal(requiredLength);
                try
                {
                    if (!GetTokenInformation(
                        token, TokenGroupsInformation, information, requiredLength, out requiredLength))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "GetTokenInformation failed");
                    }

                    uint count = unchecked((uint)Marshal.ReadInt32(information));
                    int groupsOffset = IntPtr.Size == 8 ? 8 : 4;
                    int groupSize = Marshal.SizeOf(typeof(SidAndAttributes));
                    for (uint index = 0; index < count; index++)
                    {
                        IntPtr entry = IntPtr.Add(information, groupsOffset + checked((int)index * groupSize));
                        SidAndAttributes group = (SidAndAttributes)Marshal.PtrToStructure(
                            entry, typeof(SidAndAttributes));
                        if ((group.Attributes & GroupEnabled) == 0)
                        {
                            continue;
                        }

                        IntPtr text;
                        if (!ConvertSidToStringSidW(group.Sid, out text))
                        {
                            throw new Win32Exception(Marshal.GetLastWin32Error(), "ConvertSidToStringSidW failed");
                        }

                        try
                        {
                            if (String.Equals(
                                Marshal.PtrToStringUni(text), expectedSid, StringComparison.OrdinalIgnoreCase))
                            {
                                return true;
                            }
                        }
                        finally
                        {
                            LocalFree(text);
                        }
                    }

                    return false;
                }
                finally
                {
                    Marshal.FreeHGlobal(information);
                }
            }
            finally
            {
                CloseHandle(token);
            }
        }
        finally
        {
            CloseHandle(process);
        }
    }
}
'@

function Assert-Condition {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) {
        throw $Message
    }
}

function Assert-ChecksumManifest {
    param([string] $Sums)

    $directory = Split-Path -Parent $Sums
    $listedNames = @()
    foreach ($line in Get-Content -LiteralPath $Sums) {
        if ($line -notmatch '^([0-9a-fA-F]{64})  ([^\\/:]+)$') {
            throw 'SHA256SUMS contains an invalid entry.'
        }
        $expectedHash = $Matches[1].ToLowerInvariant()
        $fileName = $Matches[2]
        $listedNames += $fileName
        $path = Join-Path $directory $fileName
        Assert-Condition (Test-Path -LiteralPath $path -PathType Leaf) "SHA256SUMS file is missing: $fileName."
        $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-Condition ($expectedHash -eq $actualHash) "SHA-256 checksum mismatch for $path."
    }
    foreach ($fileName in @(
        [IO.Path]::GetFileName($MsiPath),
        [IO.Path]::GetFileName($AgentExe),
        [IO.Path]::GetFileName($CertificatePath),
        [IO.Path]::GetFileName($InstallScriptPath),
        'README.md'
    )) {
        Assert-Condition ($listedNames -contains $fileName) "SHA256SUMS has no entry for $fileName."
    }
}

function Assert-ConfigAcl {
    $acl = Get-Acl -LiteralPath $configPath
    Assert-Condition $acl.AreAccessRulesProtected 'The DPAPI config DACL must not inherit broader permissions.'

    $rules = @($acl.Access)
    $actualSids = @($rules | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    $expected = @($expectedSids + $serviceSid + $ownerRightsSid | Sort-Object)
    Assert-Condition (($actualSids -join ',') -eq ($expected -join ',')) `
        "Config DACL principals differ from Administrators, SYSTEM, Owner Rights, and the service SID: $($actualSids -join ',')."
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        Assert-Condition ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) `
            "Config DACL contains an unexpected deny ACE for $sid."
        if ($sid -eq $ownerRightsSid) {
            Assert-Condition ($rule.FileSystemRights -eq [Security.AccessControl.FileSystemRights]::ReadPermissions) `
                'Owner Rights must be limited to read-control on config.'
        } elseif ($sid -eq $serviceSid) {
            $forbiddenRights = [Security.AccessControl.FileSystemRights]::WriteData -bor
                [Security.AccessControl.FileSystemRights]::AppendData -bor
                [Security.AccessControl.FileSystemRights]::Delete -bor
                [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                [Security.AccessControl.FileSystemRights]::TakeOwnership
            Assert-Condition (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData) -ne 0) `
                'The service SID cannot read the protected config.'
            Assert-Condition (($rule.FileSystemRights -band $forbiddenRights) -eq 0) `
                'The service SID can modify or replace the protected config.'
        } else {
            Assert-Condition (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
                [Security.AccessControl.FileSystemRights]::FullControl) 'Administrators and SYSTEM must have full control of config.'
        }
    }
}

function Assert-ReadOnlyServiceAcl {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [switch] $Directory
    )

    $acl = Get-Acl -LiteralPath $Path
    Assert-Condition $acl.AreAccessRulesProtected "$Path must have a protected DACL."
    $ownerSid = ([Security.Principal.NTAccount]::new($acl.Owner)).Translate(
        [Security.Principal.SecurityIdentifier]
    ).Value
    Assert-Condition ($ownerSid -eq 'S-1-5-32-544') "$Path must be owned by Administrators, not $ownerSid."

    $rules = @($acl.Access)
    $actualSids = @($rules | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    $expected = @($expectedSids + $serviceSid + $ownerRightsSid | Sort-Object)
    Assert-Condition (($actualSids -join ',') -eq ($expected -join ',')) `
        "$Path DACL principals differ from Administrators, SYSTEM, Owner Rights, and the service SID: $($actualSids -join ',')."

    $forbiddenRights = [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        Assert-Condition ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) `
            "$Path DACL contains an unexpected deny ACE for $sid."
        if ($sid -eq $ownerRightsSid) {
            Assert-Condition ($rule.FileSystemRights -eq [Security.AccessControl.FileSystemRights]::ReadPermissions) `
                "Owner Rights must be limited to read-control on $Path."
        } elseif ($sid -eq $serviceSid) {
            Assert-Condition (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData) -ne 0) `
                "$Path does not grant the service read access."
            if ($Directory) {
                Assert-Condition (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ExecuteFile) -ne 0) `
                    "$Path does not grant the service traverse access."
            }
            Assert-Condition (($rule.FileSystemRights -band $forbiddenRights) -eq 0) `
                "$Path grants the service write, delete, ownership, or ACL-change access."
        } else {
            Assert-Condition (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
                [Security.AccessControl.FileSystemRights]::FullControl) `
                "Administrators and SYSTEM must have full control of $Path."
        }
    }
}

function Assert-StateFileAcl {
    param([string] $Path)

    $acl = Get-Acl -LiteralPath $Path
    Assert-Condition $acl.AreAccessRulesProtected "$Path must not inherit broader permissions."
    $rules = @($acl.Access)
    $actualSids = @($rules | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    $expected = @($expectedSids + $serviceSid + $ownerRightsSid | Sort-Object)
    Assert-Condition (($actualSids -join ',') -eq ($expected -join ',')) `
        "State-file DACL principals differ from Administrators, SYSTEM, Owner Rights, and the service SID: $($actualSids -join ',')."
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        Assert-Condition ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) `
            "State-file DACL contains an unexpected deny ACE for $sid."
        if ($sid -eq $ownerRightsSid) {
            Assert-Condition ($rule.FileSystemRights -eq [Security.AccessControl.FileSystemRights]::ReadPermissions) `
                'Owner Rights must be limited to read-control on state files.'
        } else {
            Assert-Condition (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
                [Security.AccessControl.FileSystemRights]::FullControl) 'Administrators, SYSTEM, and the service SID must have full control of state files.'
        }
    }
}

function Assert-StateDirectoryAcl {
    $acl = Get-Acl -LiteralPath $stateDirectory
    Assert-Condition $acl.AreAccessRulesProtected 'The mutable state directory must have a protected DACL.'
    $ownerSid = ([Security.Principal.NTAccount]::new($acl.Owner)).Translate(
        [Security.Principal.SecurityIdentifier]
    ).Value
    Assert-Condition ($ownerSid -eq 'S-1-5-32-544') 'The mutable state directory must be owned by Administrators.'

    $rules = @($acl.Access)
    $actualSids = @($rules | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    $expected = @($expectedSids + $serviceSid + $ownerRightsSid | Sort-Object)
    Assert-Condition (($actualSids -join ',') -eq ($expected -join ',')) `
        "Mutable state-directory DACL principals differ from Administrators, SYSTEM, Owner Rights, and the service SID: $($actualSids -join ',')."
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        Assert-Condition ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) `
            "Mutable state-directory DACL contains an unexpected deny ACE for $sid."
        if ($sid -eq $ownerRightsSid) {
            Assert-Condition ($rule.FileSystemRights -eq [Security.AccessControl.FileSystemRights]::ReadPermissions) `
                'Owner Rights must be limited to read-control on the mutable state directory.'
        } else {
            Assert-Condition (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
                [Security.AccessControl.FileSystemRights]::FullControl) `
                'Administrators, SYSTEM, and the service SID must have full control of mutable state.'
        }
    }
}

$null = Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

public static class SadappUserAclInspector
{
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LogonUser(
        string username, string domain, string password, int logonType, int provider,
        out SafeAccessTokenHandle token);

    private static void RequireDenied(Action action)
    {
        try
        {
            action();
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }
        catch (SecurityException)
        {
            return;
        }
        throw new InvalidOperationException("Ordinary-user ACL probe unexpectedly succeeded.");
    }

    public static void Verify(
        string username, string domain, string password, string expectedSid,
        string[] files, string[] directories, string[] writes)
    {
        SafeAccessTokenHandle token;
        if (!LogonUser(username, domain, password, 2, 0, out token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot log on ACL test user");
        }
        using (token)
        {
            VerifyToken(token, expectedSid, files, directories, writes);
        }
    }

    private static void VerifyToken(
        SafeAccessTokenHandle token, string expectedSid,
        string[] files, string[] directories, string[] writes)
    {
        WindowsIdentity.RunImpersonated(token, () =>
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                var principal = new WindowsPrincipal(identity);
                if (identity.User.Value != expectedSid ||
                    principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    throw new InvalidOperationException("ACL probe did not use the expected non-admin token without elevated groups.");
                }
            }
            foreach (string path in files)
            {
                RequireDenied(() => { File.ReadAllBytes(path); });
            }
            foreach (string path in directories)
            {
                RequireDenied(() => { Directory.GetFileSystemEntries(path); });
            }
            foreach (string path in writes)
            {
                RequireDenied(() => { File.WriteAllText(path, "unauthorized"); });
            }
        });
    }
}
'@

function Assert-UserCannotReadConfig {
    $password = ConvertTo-SecureString ("Sadapp-CI-" + [guid]::NewGuid().ToString('N') + 'aA1!') -AsPlainText -Force
    $null = New-LocalUser -Name $testUser -Password $password -AccountNeverExpires -PasswordNeverExpires `
        -Description 'Temporary Windows installer ACL test account'
    $script:testUserCreated = $true
    $usersGroup = Get-LocalGroup -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'))
    Add-LocalGroupMember -Group $usersGroup -Member $testUser
    $credential = [Management.Automation.PSCredential]::new("$env:COMPUTERNAME\$testUser", $password)
    [SadappUserAclInspector]::Verify(
        $testUser, $env:COMPUTERNAME, $credential.GetNetworkCredential().Password,
        (Get-LocalUser -Name $testUser).SID.Value,
        @($configPath, $queuePath, $logPath), @($dataDirectory, $stateDirectory),
        @((Join-Path $dataDirectory 'acl-user-root-probe.tmp'), (Join-Path $stateDirectory 'acl-user-state-probe.tmp'))
    )
}

function Assert-PlainLocalServiceCannotAccessAgentData {
    $probeName = 'SadappAclProbe' + [guid]::NewGuid().ToString('N')
    $probeDirectory = Join-Path ([IO.Path]::GetTempPath()) $probeName
    $null = New-Item -ItemType Directory -Path $probeDirectory
    $resultDirectory = Join-Path $probeDirectory 'result'
    $null = New-Item -ItemType Directory -Path $resultDirectory
    $probeExe = Join-Path $probeDirectory 'probe.exe'
    $resultPath = Join-Path $resultDirectory 'result.txt'
    $created = $false
    try {
        $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
        & $compiler /nologo /target:exe /reference:System.ServiceProcess.dll `
            "/out:$probeExe" (Join-Path $PSScriptRoot 'LocalServiceAclProbe.cs')
        if ($LASTEXITCODE -ne 0) { throw 'Cannot compile the independent LocalService ACL probe.' }
        & icacls.exe $probeDirectory /grant '*S-1-5-19:(OI)(CI)RX' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot grant LocalService read access to its isolated probe binary.' }
        & icacls.exe $resultDirectory /grant '*S-1-5-19:(OI)(CI)M' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot grant LocalService write access to its isolated probe result.' }
        $arguments = @($probeExe, $probeName, $serviceSid, $resultPath, $configPath, $queuePath,
            $logPath, $dataDirectory, $stateDirectory,
            (Join-Path $dataDirectory 'acl-service-root-probe.tmp'),
            (Join-Path $stateDirectory 'acl-service-state-probe.tmp'))
        $binaryPath = ($arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
        & sc.exe create $probeName binPath= $binaryPath obj= 'NT AUTHORITY\LocalService' start= demand | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot create the independent LocalService ACL probe service.' }
        $created = $true
        & sc.exe sidtype $probeName none | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot disable the probe service SID.' }
        & sc.exe start $probeName | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot start the independent LocalService ACL probe service.' }
        $deadline = [DateTime]::UtcNow.AddSeconds(60)
        while (-not (Test-Path -LiteralPath $resultPath)) {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'LocalService ACL probe did not report a result within 60 seconds.' }
            Start-Sleep -Milliseconds 200
        }
        $result = Get-Content -LiteralPath $resultPath -Raw
        if ($result -ne 'PASS') { throw "Independent LocalService ACL probe failed: $result" }
        (Get-Service -Name $probeName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    finally {
        if ($created) {
            $probeService = Get-Service -Name $probeName
            if ($probeService.Status -ne 'Stopped') {
                Stop-Service -Name $probeName
                $probeService.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
            }
            & sc.exe delete $probeName | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Cannot remove the temporary LocalService ACL probe service.' }
        }
        Remove-Item -LiteralPath $probeDirectory -Recurse -Force
    }
}

function Assert-InstalledExecutable {
    $signature = Get-AuthenticodeSignature -FilePath $installedExe
    Assert-Condition ($signature.Status -eq 'Valid' -and $signature.SignerCertificate.Thumbprint -eq $thumbprint) `
        'The installed executable must have the expected valid Authenticode signature.'
    $expectedHash = (Get-FileHash -LiteralPath $AgentExe -Algorithm SHA256).Hash
    $installedHash = (Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash
    Assert-Condition ($installedHash -eq $expectedHash) `
        'The MSI must install the exact signed executable distributed alongside it.'
}

function Invoke-MsiUninstall {
    $candidates = @($installedMsiPath, $MsiPath, $UpgradeMsiPath) | Select-Object -Unique
    foreach ($candidate in $candidates) {
        $installer = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" `
            -ArgumentList @('/x', "`"$candidate`"", '/qn', '/norestart') -Wait -PassThru
        if ($installer.ExitCode -in @(0, 3010)) {
            return
        }
        if ($installer.ExitCode -ne 1605) {
            throw "MSI uninstall failed with exit code $($installer.ExitCode)."
        }
    }
    throw 'No installed Sadapp Host Agent MSI product could be removed.'
}

try {
    Assert-Condition (-not (Test-Path -LiteralPath $dataDirectory)) `
        'Refusing to run on a machine with pre-existing Sadapp Host Agent state.'
    Assert-Condition ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -eq $null) `
        'Refusing to run on a machine with a pre-existing SadappHostAgent service.'
    Assert-ChecksumManifest -Sums $ChecksumPath

    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
    $existingTrustedCert = Get-ChildItem Cert:\LocalMachine\Root |
        Where-Object Thumbprint -eq $certificate.Thumbprint |
        Select-Object -First 1
    if ($null -eq $existingTrustedCert) {
        $importedCert = Import-Certificate -FilePath $CertificatePath -CertStoreLocation 'Cert:\LocalMachine\Root'
        $addedRootTrust = $true
    } else {
        $importedCert = $existingTrustedCert
    }
    $thumbprint = $importedCert.Thumbprint
    foreach ($signedFile in @($AgentExe, $MsiPath, $UpgradeMsiPath)) {
        & $signTool verify /pa /all /v $signedFile
        if ($LASTEXITCODE -ne 0) {
            throw "Offline Authenticode verification failed for $signedFile."
        }
        $signature = Get-AuthenticodeSignature -FilePath $signedFile
        Assert-Condition ($signature.Status -eq 'Valid' -and $signature.SignerCertificate.Thumbprint -eq $thumbprint) `
            "Unexpected Authenticode signer or invalid signature on $signedFile."
    }

    $installer = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" `
        -ArgumentList @('/i', "`"$MsiPath`"", '/qn', '/norestart') -Wait -PassThru
    if ($installer.ExitCode -notin @(0, 3010)) {
        throw "Initial MSI install failed with exit code $($installer.ExitCode)."
    }
    $installed = $true
    Assert-Condition (Test-Path -LiteralPath $installedExe) 'The MSI did not install the agent executable.'
    Assert-InstalledExecutable
    $resolvedServiceSid = ([Security.Principal.NTAccount]::new('NT SERVICE\SadappHostAgent')).Translate(
        [Security.Principal.SecurityIdentifier]
    ).Value
    Assert-Condition ($resolvedServiceSid -eq $serviceSid) `
        "Computed service SID $serviceSid does not match Windows account resolution $resolvedServiceSid."

    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    Assert-Condition ($null -ne $service) 'The MSI did not register SadappHostAgent.'
    Assert-Condition ($service.StartName -eq 'NT AUTHORITY\LocalService') "Unexpected service account: $($service.StartName)."
    Assert-Condition ($service.StartMode -eq 'Auto') "Expected automatic service startup, got $($service.StartMode)."
    Assert-Condition ($service.PathName -match '(?i)sadapp-host-agent\.exe.*--service') `
        "Unexpected service executable or arguments: $($service.PathName)."
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    Assert-Condition ((Get-ItemProperty -LiteralPath $serviceKey -Name DelayedAutoStart).DelayedAutoStart -eq 1) `
        'The service is not configured for delayed automatic startup.'
    Assert-Condition ((Get-ItemProperty -LiteralPath $serviceKey -Name ServiceSidType).ServiceSidType -eq 1) `
        'The service SID is not enabled as unrestricted.'
    $sidTypeOutput = @(& sc.exe qsidtype $serviceName 2>&1)
    if ($LASTEXITCODE -ne 0 -or ($sidTypeOutput -join "`n") -notmatch '(?i)unrestricted') {
        throw "SCM did not report an unrestricted service SID: $($sidTypeOutput -join ' ')."
    }
    $showSidOutput = @(& sc.exe showsid $serviceName 2>&1)
    if ($LASTEXITCODE -ne 0 -or ($showSidOutput -join "`n") -notmatch [regex]::Escape($serviceSid)) {
        throw "SCM service SID does not match ${serviceSid}: $($showSidOutput -join ' ')."
    }
    $lookupSidOutput = @(& sc.exe qsidtype $serviceName 2>&1)
    if ($LASTEXITCODE -ne 0 -or ($lookupSidOutput -join "`n") -notmatch '(?i)unrestricted') {
        throw "Windows account lookup resolved the service SID, but SCM does not report it enabled: $($lookupSidOutput -join ' ')."
    }
    Assert-Condition ((Get-Service -Name $serviceName).Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped) `
        'A fresh install must register, but must not start, the service before enrollment.'

    $endpoint = 'https://127.0.0.1:1/api/v1/agent'
    $token = 'ci-synthetic-enrollment-token-never-for-a-real-account'
    @($endpoint, $token) | & $installedExe --configure
    if ($LASTEXITCODE -ne 0) {
        throw "Agent --configure failed with exit code $LASTEXITCODE."
    }
    Assert-Condition (Test-Path -LiteralPath $configPath) 'Enrollment did not create the DPAPI config file.'
    & $installedExe --validate-config
    if ($LASTEXITCODE -ne 0) {
        throw "Agent --validate-config failed with exit code $LASTEXITCODE."
    }
    Assert-ReadOnlyServiceAcl -Path $sadappDirectory -Directory
    Assert-ReadOnlyServiceAcl -Path $dataDirectory -Directory
    Assert-ReadOnlyServiceAcl -Path $configPath
    Assert-StateDirectoryAcl
    Assert-ConfigAcl

    $versionOutput = @(& $AgentExe --version)
    if ($LASTEXITCODE -ne 0) {
        throw "Agent --version failed with exit code $LASTEXITCODE."
    }
    Assert-Condition (($versionOutput -join "`n").Trim() -eq "Sadapp Host Agent $AgentVersion") `
        "Unexpected --version output: $($versionOutput -join ' ')."

    $originalConfig = [IO.File]::ReadAllBytes($configPath)
    try {
        $tamperedConfig = [byte[]]$originalConfig.Clone()
        Assert-Condition ($tamperedConfig.Length -gt 0) 'Protected config is unexpectedly empty.'
        $tamperedConfig[0] = $tamperedConfig[0] -bxor 1
        [IO.File]::WriteAllBytes($configPath, $tamperedConfig)
        & $installedExe --validate-config *> $null
        $tamperedExitCode = $LASTEXITCODE
        Assert-Condition ($tamperedExitCode -ne 0) 'DPAPI accepted a modified protected config.'
    } finally {
        [IO.File]::WriteAllBytes($configPath, $originalConfig)
    }
    & $installedExe --validate-config
    if ($LASTEXITCODE -ne 0) {
        throw "The restored protected config failed --validate-config (exit code $LASTEXITCODE)."
    }
    Assert-ConfigAcl
    $configHashBeforeUpgrade = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Running,
        [TimeSpan]::FromSeconds(30)
    )
    $runningService = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    Assert-Condition ($runningService.ProcessId -gt 0) 'The running service has no process ID.'
    Assert-Condition ([SadappServiceTokenInspector]::HasEnabledGroup($runningService.ProcessId, $serviceSid)) `
        "The running service process token does not contain enabled SID $serviceSid."
    $queueDeadline = (Get-Date).AddSeconds(30)
    while (-not (Test-Path -LiteralPath $queuePath -PathType Leaf) -and (Get-Date) -lt $queueDeadline) {
        Start-Sleep -Seconds 1
    }
    Assert-Condition ((Get-Service -Name $serviceName).Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) `
        'The service did not remain running during the offline endpoint test.'
    Assert-Condition (Test-Path -LiteralPath $queuePath -PathType Leaf) `
        'The offline service run did not persist its telemetry queue under ProgramData.'
    Assert-Condition (Test-Path -LiteralPath $logPath -PathType Leaf) `
        'The Windows service did not write its log under ProgramData\Sadapp\HostAgent\state.'
    Assert-StateFileAcl -Path $logPath
    if (Test-Path -LiteralPath $updateStatePath -PathType Leaf) {
        Assert-StateFileAcl -Path $updateStatePath
    }
    Assert-StateFileAcl -Path $queuePath
    Assert-UserCannotReadConfig
    Assert-PlainLocalServiceCannotAccessAgentData
    [IO.File]::WriteAllText($sentinelPath, 'This unrecognized file must survive the known-files-only purge.')
    $sentinelAcl = Get-Acl -LiteralPath $sentinelPath
    $sentinelAcl.SetAccessRuleProtection($true, $true)
    Set-Acl -LiteralPath $sentinelPath -AclObject $sentinelAcl
    Assert-StateFileAcl -Path $sentinelPath
    $persistentFiles = @(Get-ChildItem -LiteralPath $dataDirectory -File -Recurse |
        Where-Object { $_.FullName -ne $configPath })
    $persistentRelativePaths = @($persistentFiles | ForEach-Object { $_.FullName.Substring($dataDirectory.Length).TrimStart('\') })
    $queueBeforeUpgrade = Get-Content -LiteralPath $queuePath -Raw | ConvertFrom-Json
    $queuedIdsBeforeUpgrade = @($queueBeforeUpgrade.items | Select-Object -ExpandProperty id)
    Assert-Condition ($queuedIdsBeforeUpgrade.Count -gt 0) `
        'The offline test must retain actual telemetry samples, not merely an empty queue file.'

    & $InstallScriptPath -MsiPath $UpgradeMsiPath
    $installedMsiPath = $UpgradeMsiPath
    Assert-InstalledExecutable
    $queueAfterUpgrade = Get-Content -LiteralPath $queuePath -Raw | ConvertFrom-Json
    $queuedIdsAfterUpgrade = @($queueAfterUpgrade.items | Select-Object -ExpandProperty id)
    foreach ($queuedId in $queuedIdsBeforeUpgrade) {
        Assert-Condition ($queuedIdsAfterUpgrade -contains $queuedId) `
            "The MSI upgrade lost queued telemetry sample $queuedId."
    }
    Assert-Condition (Test-Path -LiteralPath $configPath) 'The MSI upgrade removed the protected config.'
    Assert-Condition ((Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash -eq $configHashBeforeUpgrade) `
        'The MSI upgrade changed the protected config.'
    foreach ($relativePath in $persistentRelativePaths) {
        $statePath = Join-Path $dataDirectory $relativePath
        Assert-Condition (Test-Path -LiteralPath $statePath -PathType Leaf) `
            "The MSI upgrade removed application state: $relativePath."
        Assert-StateFileAcl -Path $statePath
    }
    Assert-ConfigAcl
    Assert-ReadOnlyServiceAcl -Path $sadappDirectory -Directory
    Assert-ReadOnlyServiceAcl -Path $dataDirectory -Directory
    Assert-ReadOnlyServiceAcl -Path $configPath
    Assert-StateDirectoryAcl
    Assert-StateFileAcl -Path $queuePath
    $service = Get-Service -Name $serviceName
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
    $runningService = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    Assert-Condition ([SadappServiceTokenInspector]::HasEnabledGroup($runningService.ProcessId, $serviceSid)) `
        "The upgraded service process token does not contain enabled SID $serviceSid."
    & $installedExe --validate-config
    if ($LASTEXITCODE -ne 0) {
        throw "The upgraded agent --validate-config failed with exit code $LASTEXITCODE."
    }

    Stop-Service -Name $serviceName -Force
    (Get-Service -Name $serviceName).WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Stopped,
        [TimeSpan]::FromSeconds(30)
    )
    $queueHashBeforeUninstall = (Get-FileHash -LiteralPath $queuePath -Algorithm SHA256).Hash
    Invoke-MsiUninstall
    $installed = $false

    Assert-Condition ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -eq $null) `
        'MSI uninstall left the Windows service registered.'
    Assert-Condition (-not (Test-Path -LiteralPath $installedExe)) 'MSI uninstall left the agent executable installed.'
    Assert-Condition (Test-Path -LiteralPath $configPath) 'MSI uninstall removed the protected enrollment config.'
    Assert-Condition (Test-Path -LiteralPath $queuePath) 'MSI uninstall removed the persisted telemetry queue.'
    Assert-Condition ((Get-FileHash -LiteralPath $queuePath -Algorithm SHA256).Hash -eq $queueHashBeforeUninstall) `
        'MSI uninstall modified the persisted telemetry queue.'
    Assert-Condition (Test-Path -LiteralPath $sentinelPath) 'MSI uninstall removed unrelated application state.'
    foreach ($relativePath in $persistentRelativePaths) {
        $statePath = Join-Path $dataDirectory $relativePath
        Assert-Condition (Test-Path -LiteralPath $statePath -PathType Leaf) `
            "MSI uninstall removed application state: $relativePath."
        Assert-StateFileAcl -Path $statePath
    }
    Assert-ConfigAcl
    Assert-ReadOnlyServiceAcl -Path $sadappDirectory -Directory
    Assert-ReadOnlyServiceAcl -Path $dataDirectory -Directory
    Assert-ReadOnlyServiceAcl -Path $configPath
    Assert-StateDirectoryAcl
    & $AgentExe --purge-state
    if ($LASTEXITCODE -ne 0) {
        throw "Agent --purge-state failed with exit code $LASTEXITCODE."
    }
    Assert-Condition (-not (Test-Path -LiteralPath $configPath)) 'Explicit state purge left the protected config behind.'
    Assert-Condition (-not (Test-Path -LiteralPath $queuePath)) 'Explicit state purge left the telemetry queue behind.'
    Assert-Condition (-not (Test-Path -LiteralPath $updateStatePath)) 'Explicit state purge left update state behind.'
    Assert-Condition (-not (Test-Path -LiteralPath $logPath)) 'Explicit state purge left its known log behind.'
    Assert-Condition (Test-Path -LiteralPath $sentinelPath) 'Explicit state purge removed unrelated application state.'
    Remove-Item -LiteralPath $sentinelPath
    Write-Output 'Windows MSI install, enrollment, ACL, service, upgrade, and uninstall checks passed.'
} finally {
    if ($testUserCreated) {
        Remove-LocalUser -Name $testUser -ErrorAction SilentlyContinue
    }
    if ($installed) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $service -and $service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        }
        Invoke-MsiUninstall
    }
    if ($addedRootTrust -and $null -ne $importedCert) {
        Remove-Item -LiteralPath "Cert:\LocalMachine\Root\$($importedCert.Thumbprint)" -ErrorAction Stop
    }
}
