[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $AgentExe,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string] $Version,

    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [Parameter()]
    [ValidatePattern('^(?i)[0-9a-f]{40}$')]
    [string] $ExistingCertThumbprint,

    [Parameter()]
    [ValidatePattern('^https://[A-Za-z0-9.-]+(?::[0-9]+)?(?:/[^?#]*)?$')]
    [string] $TimestampUrl,

    [Parameter()]
    [switch] $ProductionSigning,

    # Alpha distribution without Authenticode: Windows SmartScreen will show an
    # "unknown publisher" warning, but no certificate has to be trusted by the user.
    [Parameter()]
    [switch] $Unsigned
)

$ErrorActionPreference = 'Stop'

if ($Unsigned -and ($ProductionSigning -or $ExistingCertThumbprint -or $TimestampUrl)) {
    throw 'Unsigned alpha builds cannot be combined with signing parameters.'
}

function Invoke-WixBuild {
    param(
        [Parameter(Mandatory = $true)][string] $PackageVersion,
        [Parameter(Mandatory = $true)][string] $Destination
    )

    & wix build `
        -arch x64 `
        -d "ProductVersion=$PackageVersion" `
        -d "AgentExe=$script:SignedAgentExe" `
        -o $Destination `
        (Join-Path $PSScriptRoot '..\..\packaging\windows\host-agent.wxs')
    if ($LASTEXITCODE -ne 0) {
        throw "WiX failed to build version $PackageVersion (exit code $LASTEXITCODE)."
    }
}

function Invoke-Sign {
    param([Parameter(Mandatory = $true)][string] $Path)

    if ($Unsigned) {
        return
    }
    $timestampArguments = @()
    if ($TimestampUrl) {
        $timestampArguments = @('/tr', $TimestampUrl, '/td', 'SHA256')
    }
    & $script:SignTool sign /sha1 $script:Thumbprint /s My /fd SHA256 @timestampArguments /v $Path
    if ($LASTEXITCODE -ne 0) {
        throw "Authenticode signing failed for $Path (exit code $LASTEXITCODE)."
    }
}

function Get-NextPatchVersion {
    param([string] $Current)

    $parts = $Current.Split('.')
    if (@($parts | Where-Object { [int]$_ -gt 255 }).Count -gt 0) {
        throw "MSI version fields cannot exceed 255: $Current"
    }
    $patch = [int] $parts[2]
    if ($patch -ge 255) {
        throw "The MSI patch version cannot be incremented past 255: $Current"
    }
    return "$($parts[0]).$($parts[1]).$($patch + 1)"
}

$AgentExe = (Resolve-Path -LiteralPath $AgentExe).Path
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$testDirectory = Join-Path $OutputDirectory 'upgrade-test'
$null = New-Item -ItemType Directory -Force -Path $OutputDirectory, $testDirectory

if (-not $Unsigned) {
    $SignTool = Get-ChildItem -Path (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin\*\x64\signtool.exe') -ErrorAction Stop |
        Sort-Object { [version]$_.Directory.Parent.Name } -Descending |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $SignTool) {
        throw 'Windows SDK signtool.exe was not found.'
    }
}

$cert = $null
$createdCert = $false
if ($ProductionSigning -and (-not $ExistingCertThumbprint -or -not $TimestampUrl)) {
    throw 'Production signing requires an existing trusted certificate and an explicit HTTPS RFC3161 timestamp URL.'
}
try {
    if ($Unsigned) {
        # No signing identity.
    } elseif ([string]::IsNullOrWhiteSpace($ExistingCertThumbprint)) {
        $cert = New-SelfSignedCertificate `
            -Subject 'CN=Sadapp Host Agent Prototype Code Signing' `
            -Type CodeSigningCert `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -KeyAlgorithm RSA `
            -KeyLength 3072 `
            -HashAlgorithm SHA256 `
            -KeyExportPolicy NonExportable `
            -NotAfter (Get-Date).AddDays(90)
        $createdCert = $true
    } else {
        $cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$ExistingCertThumbprint" -ErrorAction Stop
        if (-not $cert.HasPrivateKey -or $cert.NotAfter -le (Get-Date) -or $cert.NotBefore -gt (Get-Date)) {
            throw 'The selected CurrentUser\My certificate must be currently valid and have an associated private key.'
        }
        $eku = @($cert.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] })
        if ($eku.Count -eq 0 -or -not @($eku[0].EnhancedKeyUsages | Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.3' }).Count) {
            throw 'The selected CurrentUser\My certificate must include the Code Signing EKU.'
        }
    }
    if ($ProductionSigning) {
        if ($cert.Subject -eq $cert.Issuer) {
            throw 'A self-signed prototype certificate cannot be used for production signing.'
        }
        $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
        try {
            if (-not $chain.Build($cert)) {
                throw 'Production code-signing certificate chain is not trusted or fails revocation validation.'
            }
        } finally {
            $chain.Dispose()
        }
    }
    if (-not $Unsigned) {
        $script:Thumbprint = $cert.Thumbprint
    }

    $agentCopy = Join-Path $OutputDirectory 'sadapp-host-agent.exe'
    Copy-Item -LiteralPath $AgentExe -Destination $agentCopy -Force
    Invoke-Sign -Path $agentCopy
    $script:SignedAgentExe = $agentCopy

    $msiPath = Join-Path $OutputDirectory "sadapp-host-agent-$Version-windows-x64.msi"
    Invoke-WixBuild -PackageVersion $Version -Destination $msiPath
    Invoke-Sign -Path $msiPath

    $upgradeVersion = Get-NextPatchVersion -Current $Version
    $upgradeMsi = Join-Path $testDirectory "sadapp-host-agent-$upgradeVersion-windows-x64.msi"
    Invoke-WixBuild -PackageVersion $upgradeVersion -Destination $upgradeMsi
    Invoke-Sign -Path $upgradeMsi

    $certificatePath = Join-Path $OutputDirectory 'prototype-signing.cer'
    if (-not $Unsigned) {
        Export-Certificate -Cert $cert -FilePath $certificatePath -Type CERT | Out-Null
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\..\packaging\windows\README.md') `
        -Destination (Join-Path $OutputDirectory 'README.md')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Install-HostAgent.ps1') `
        -Destination (Join-Path $OutputDirectory 'Install-HostAgent.ps1')

    $files = @(
        (Get-Item -LiteralPath $msiPath),
        (Get-Item -LiteralPath $agentCopy),
        (Get-Item -LiteralPath (Join-Path $OutputDirectory 'README.md')),
        (Get-Item -LiteralPath (Join-Path $OutputDirectory 'Install-HostAgent.ps1'))
    )
    if (-not $Unsigned) {
        $files += Get-Item -LiteralPath $certificatePath
    }
    $lines = foreach ($file in $files) {
        '{0}  {1}' -f (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $file.Name
    }
    [IO.File]::WriteAllLines(
        (Join-Path $OutputDirectory 'CHECKSUMS'),
        [string[]] $lines,
        [Text.Encoding]::ASCII
    )

    Write-Output "MSI: $msiPath"
    Write-Output "Upgrade-test MSI: $upgradeMsi"
    if ($Unsigned) {
        Write-Output 'Unsigned alpha build: no Authenticode signature was applied.'
    } else {
        Write-Output "Public signing certificate thumbprint: $script:Thumbprint"
    }
} finally {
    if ($createdCert -and $null -ne $cert) {
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey -ErrorAction Stop
    }
}
