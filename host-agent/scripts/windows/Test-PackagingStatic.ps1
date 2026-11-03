[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot
$repoRoot = [IO.Path]::GetFullPath((Join-Path $scriptRoot '..\..\..'))
$scriptsDirectory = Join-Path $repoRoot 'host-agent\scripts\windows'
$workflowPath = Join-Path $repoRoot '.github\workflows\host-agent-windows.yml'
$wixPath = Join-Path $repoRoot 'host-agent\packaging\windows\host-agent.wxs'
$readmePath = Join-Path $repoRoot 'host-agent\packaging\windows\README.md'
$updateScriptPath = Join-Path $repoRoot 'host-agent\src\windows_update_inventory.ps1'

function Assert-Static {
    param(
        [Parameter(Mandatory = $true)][bool] $Condition,
        [Parameter(Mandatory = $true)][string] $Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

foreach ($file in @((Get-ChildItem -LiteralPath $scriptsDirectory -Filter '*.ps1' -File)) + @(Get-Item -LiteralPath $updateScriptPath)) {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $file.FullName,
        [ref] $tokens,
        [ref] $errors
    )
    Assert-Static ($errors.Count -eq 0) "$($file.Name) has PowerShell parser errors: $($errors -join '; ')"
    if ($file.Name -eq 'Test-Installer.ps1') {
        $inspectors = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
            ($node.Value.Contains('public static class SadappUserAclInspector') -or
             $node.Value.Contains('public static class SadappServiceTokenInspector'))
        }, $true)
        Assert-Static ($inspectors.Count -eq 2) 'Both native token inspectors must be present.'
        foreach ($inspector in $inspectors) {
            Add-Type -TypeDefinition $inspector.Value
        }
    }
}
$updateScript = Get-Content -LiteralPath $updateScriptPath -Raw
Assert-Static ($updateScript.Contains('$searcher.Online = $false') -and
    -not $updateScript.Contains('CreateUpdateDownloader') -and
    -not $updateScript.Contains('CreateUpdateInstaller')) `
    'Windows Update inventory must remain cached/read-only with no downloader or installer.'

[xml] $wix = Get-Content -LiteralPath $wixPath -Raw
$namespace = [Xml.XmlNamespaceManager]::new($wix.NameTable)
$namespace.AddNamespace('w', 'http://wixtoolset.org/schemas/v4/wxs')
$namespace.AddNamespace('util', 'http://wixtoolset.org/schemas/v4/wxs/util')
$service = $wix.SelectSingleNode('//w:ServiceInstall', $namespace)
$serviceConfig = $service.SelectSingleNode('w:ServiceConfig', $namespace)
$serviceControl = $wix.SelectSingleNode('//w:ServiceControl', $namespace)
$installDirectory = $wix.SelectSingleNode('//w:Directory[@Id="INSTALLFOLDER"]', $namespace)
Assert-Static ($null -ne $service) 'The MSI must install the Windows service.'
Assert-Static ($service.GetAttribute('Name') -eq 'SadappHostAgent') 'Unexpected service name.'
Assert-Static ($service.GetAttribute('Account') -eq 'NT AUTHORITY\LocalService') 'The service must run as LocalService.'
Assert-Static ($service.GetAttribute('Arguments') -eq '--service') 'The service must be launched with --service.'
Assert-Static ($serviceConfig.GetAttribute('DelayedAutoStart') -eq 'yes') 'The service must use delayed automatic startup.'
Assert-Static ($serviceConfig.GetAttribute('ServiceSid') -eq 'unrestricted') 'The service SID must be unrestricted.'
Assert-Static ($serviceConfig.GetAttribute('FailureActionsWhen') -eq 'failedToStopOrReturnedError') `
    'Recovery must cover crashes and error exits, not normal stops.'
$recovery = $service.SelectSingleNode('util:ServiceConfig', $namespace)
Assert-Static ($null -ne $recovery -and $recovery.GetAttribute('ResetPeriodInDays') -eq '1' -and
    $recovery.GetAttribute('RestartServiceDelayInSeconds') -eq '15' -and
    $recovery.GetAttribute('FirstFailureActionType') -eq 'restart' -and
    $recovery.GetAttribute('SecondFailureActionType') -eq 'restart' -and
    $recovery.GetAttribute('ThirdFailureActionType') -eq 'none') `
    'WiX Util must configure two 15-second retries followed by no action, reset after one day.'
Assert-Static ($null -eq $service.SelectSingleNode('w:ServiceConfigFailureActions', $namespace)) `
    'Do not use the broken MSI built-in failure-actions configuration path.'
$shortcut = $wix.SelectSingleNode('//w:File[@Id="HostAgentExecutable"]/w:Shortcut', $namespace)
Assert-Static ($null -ne $shortcut -and $shortcut.GetAttribute('Arguments') -eq '--setup' -and
    $shortcut.GetAttribute('Directory') -eq 'SadappProgramMenuFolder') `
    'The MSI must expose native guided setup in the Start menu without enrollment arguments.'
Assert-Static ($serviceConfig.GetAttribute('OnInstall') -eq 'yes' -and
    $serviceConfig.GetAttribute('OnReinstall') -eq 'yes') `
    'MSI must apply the service configuration on installation and repair.'
Assert-Static ($null -eq $serviceControl.GetAttributeNode('Start')) 'The MSI must not start a fresh unenrolled service.'
$inventoryService = $wix.SelectSingleNode('//w:ServiceInstall[@Name="SadappHostAgentInventory"]', $namespace)
Assert-Static ($null -ne $inventoryService -and
    $inventoryService.GetAttribute('Account') -eq 'LocalSystem' -and
    $inventoryService.GetAttribute('Arguments') -eq '--update-inventory-service') `
    'Only the dedicated read-only Windows Update inventory service may run as LocalSystem.'
$inventoryControl = $wix.SelectSingleNode('//w:ServiceControl[@Name="SadappHostAgentInventory"]', $namespace)
Assert-Static ($null -ne $inventoryControl -and $inventoryControl.GetAttribute('Start') -eq 'install' -and
    $inventoryControl.GetAttribute('Stop') -eq 'both' -and $inventoryControl.GetAttribute('Remove') -eq 'uninstall') `
    'The read-only inventory service must start, stop and uninstall with the MSI.'
Assert-Static ($serviceControl.GetAttribute('Stop') -eq 'both') 'The MSI must stop the service on install and uninstall.'
Assert-Static ($serviceControl.GetAttribute('Remove') -eq 'uninstall') 'The MSI must remove the service on uninstall.'
Assert-Static ($installDirectory.GetAttribute('Name') -eq 'HostAgent') 'The fixed installation directory must end in Sadapp\HostAgent.'

$buildScript = Get-Content -LiteralPath (Join-Path $scriptsDirectory 'Build-Prototype.ps1') -Raw
$installerScript = Get-Content -LiteralPath (Join-Path $scriptsDirectory 'Install-HostAgent.ps1') -Raw
$smokeScript = Get-Content -LiteralPath (Join-Path $scriptsDirectory 'Test-Installer.ps1') -Raw
$workflow = Get-Content -LiteralPath $workflowPath -Raw
$readme = Get-Content -LiteralPath $readmePath -Raw
Assert-Static ($buildScript.Contains('-ext WixToolset.Util.wixext') -and
    $workflow.Contains('extension add -g WixToolset.Util.wixext/5.0.2')) `
    'The build and native acceptance must use the pinned WiX Util extension.'

Assert-Static ($buildScript.Contains('sadapp-host-agent-$Version-windows-x64.msi')) 'The MSI filename must identify the version and Windows x64 architecture.'
Assert-Static ($buildScript.Contains('prototype-signing.cer')) 'The public prototype certificate filename changed.'
Assert-Static ($buildScript.Contains("'CHECKSUMS'")) 'The package must emit CHECKSUMS.'
Assert-Static ($buildScript.Contains('-KeyExportPolicy NonExportable')) 'The ephemeral signing key must not be exportable.'
Assert-Static ($buildScript.Contains('Export-Certificate')) 'The public certificate must be exported without its private key.'
Assert-Static (-not $buildScript.Contains('Export-PfxCertificate')) 'The package build must never export a private signing key.'
Assert-Static ($buildScript.Contains('ExistingCertThumbprint')) 'The build must support an explicitly selected repeatable signing identity.'
Assert-Static ($buildScript.Contains('/sha1 $script:Thumbprint /s My')) 'Signing must select the certificate by thumbprint from CurrentUser\My.'
Assert-Static ($buildScript.Contains("@('/tr', `$TimestampUrl, '/td', 'SHA256')") -and
    $buildScript.Contains('$ProductionSigning -and (-not $ExistingCertThumbprint -or -not $TimestampUrl)')) `
    'Production signing must require a trusted existing identity and SHA-256 RFC3161 timestamping.'
Assert-Static ($buildScript.Contains('-d "AgentExe=$script:SignedAgentExe"') -and
    $buildScript.Contains('$script:SignedAgentExe = $agentCopy')) `
    'The MSI must embed the signed executable copy, not the unsigned build input.'
Assert-Static ($buildScript.Contains('-DeleteKey')) 'CI cleanup must remove a generated certificate private key.'
Assert-Static ($buildScript.Contains('$createdCert -and $null -ne $cert')) `
    'Cleanup must not remove a caller-supplied persistent signing identity.'
Assert-Static (-not $buildScript.Contains('Cert:\CurrentUser\Root')) `
    'Package creation must not add the signing certificate to a root trust store.'
Assert-Static ($buildScript.Contains('-NotAfter (Get-Date).AddDays(90)')) `
    'A newly generated prototype signing identity must be short-lived.'
Assert-Static (-not $installerScript.Contains('Import-Certificate')) 'Installation must not silently trust the prototype certificate.'
Assert-Static ($installerScript.Contains('-Wait -PassThru') -and
    $installerScript.Contains('$installer.ExitCode')) `
    'The installation helper must wait for Windows Installer and use its actual exit code.'
Assert-Static ($smokeScript.Contains('-Wait -PassThru') -and
    -not $smokeScript.Contains('& "$env:SystemRoot\System32\msiexec.exe"')) `
    'Native lifecycle assertions must wait for MSI GUI processes to finish.'
Assert-Static ($smokeScript.Contains("Cert:\LocalMachine\Root")) 'Only the isolated native smoke test may temporarily trust the prototype certificate.'
Assert-Static ($smokeScript.Contains('$addedRootTrust = $true')) 'The smoke test must track whether it introduced root trust.'
Assert-Static ($smokeScript.Contains('if ($addedRootTrust -and $null -ne $importedCert)')) `
    'The smoke test must remove only root trust it added.'
Assert-Static ($workflow.Contains('runs-on: windows-latest')) 'Native installer checks must run on Windows.'
Assert-Static ($workflow.Contains("if (`$LASTEXITCODE -ne 0) { throw 'Native Windows tests failed.' }") -and
    $workflow.Contains("if (`$LASTEXITCODE -ne 0) { throw 'Native Windows formatting failed.' }") -and
    $workflow.Contains("if (`$LASTEXITCODE -ne 0) { throw 'Native Windows release build failed.' }")) `
    'PowerShell must stop after each failed native Rust command rather than publish a success-shaped build.'
Assert-Static ($workflow.Contains('Test-PackagingStatic.ps1')) 'The portable static tests must be wired into CI.'
Assert-Static (-not $workflow.Contains('contents: write')) 'Prototype CI must not publish a release.'
Assert-Static ($smokeScript.Contains('sc.exe showsid')) 'The smoke test must compare the SCM service SID.'
Assert-Static ($smokeScript.Contains('NT SERVICE\SadappHostAgent')) 'The smoke test must resolve the native service account SID.'
Assert-Static ($smokeScript.Contains('HasEnabledGroup($runningService.ProcessId, $serviceSid)')) `
    'The smoke test must inspect enabled service SID membership in the process token.'
Assert-Static ($smokeScript.Contains('[SadappKnownFolders]::GetProgramData()')) `
    'The smoke test must resolve ProgramData using the native known-folder API.'
Assert-Static ($smokeScript.Contains('Assert-PlainLocalServiceCannotAccessAgentData')) `
    'The native smoke test must verify the shared LocalService account cannot access agent data.'
$serviceProbe = Get-Content -LiteralPath (Join-Path $scriptsDirectory 'LocalServiceAclProbe.cs') -Raw
Assert-Static ($smokeScript.Contains('sc.exe sidtype $probeName none') -and
    $smokeScript.Contains("obj= 'NT AUTHORITY\LocalService'") -and
    $serviceProbe.Contains('identity.User.Value != "S-1-5-19"') -and
    $serviceProbe.Contains('principal.IsInRole(new SecurityIdentifier(arguments[1]))')) `
    'The shared LocalService ACL probe must run as a real independent SCM service without the agent SID.'
Assert-Static ($smokeScript.Contains("'S-1-3-4'")) 'ACL checks must allow the Owner Rights SID (S-1-3-4).'
Assert-Static ($smokeScript.Contains('$expectedSids + $serviceSid + $ownerRightsSid')) `
    'ACL allowlists must include the explicit Owner Rights ACE alongside BA, SYSTEM, and the service SID.'
Assert-Static ($smokeScript.Contains('ReadPermissions')) 'Owner Rights ACEs must be validated as read-control-only.'
Assert-Static (-not $smokeScript.Contains("'S-1-5-19'")) 'ACL allowlists must not grant the shared LocalService SID.'
Assert-Static ($smokeScript.Contains('Assert-UserCannotReadConfig')) 'The smoke test must verify an ordinary user is denied access.'
Assert-Static ($smokeScript.Contains('WindowsIdentity.RunImpersonated(token') -and
    $smokeScript.Contains('identity.User.Value != expectedSid') -and
    $smokeScript.Contains('IsInRole(WindowsBuiltInRole.Administrator)')) `
    'Ordinary-user ACL probes must verify a real logged-on non-admin token, not inherit the runner identity.'
Assert-Static ($smokeScript.Contains('function Assert-InstalledExecutable') -and
    $smokeScript.Contains('Get-AuthenticodeSignature -FilePath $installedExe') -and
    $smokeScript.Contains('$installedHash -eq $expectedHash')) `
    'Native tests must verify the installed signed executable, not only the outer MSI.'
Assert-Static ($smokeScript.Contains('$queuedIdsAfterUpgrade -contains $queuedId') -and
    $smokeScript.Contains('.Hash -eq $queueHashBeforeUninstall')) `
    'Native lifecycle tests must prove queued samples survive upgrade and uninstall.'
Assert-Static ($smokeScript.Contains('GetFileSystemEntries')) 'The ordinary user and LocalService probes must test directory access.'
Assert-Static ($smokeScript.Contains('WriteAllText')) 'The ordinary user and LocalService probes must test state write access.'
Assert-Static ($readme.Contains('prototype-signing.cer') -and $readme.Contains('CHECKSUMS')) `
    'The download instructions must use the published certificate and checksum filenames.'
Assert-Static ($readme.Contains('Do not use this') -and $readme.Contains('production signing identity')) `
    'The self-signed prototype trust limitation must be documented.'

Assert-Static ($buildScript.Contains('[switch] $Unsigned') -and
    $buildScript.Contains('Unsigned alpha builds cannot be combined with signing parameters.')) `
    'Explicit legacy unsigned builds must refuse signing parameters.'
Assert-Static (-not $workflow.Contains('-Unsigned') -and -not $workflow.Contains('steps.alpha.outputs.output')) `
    'Alpha downloads must reuse the signed, lifecycle-tested package rather than rebuilding an unsigned MSI.'
Assert-Static ($smokeScript.Contains('--setup') -and $smokeScript.Contains('--validate-service') -and
    $smokeScript.Contains('Stop-Process -Id $runningService.ProcessId') -and
    $smokeScript.Contains("'/famus'")) `
    'Native acceptance must cover guided setup, actual crash recovery and MSI repair.'
Assert-Static ($readme.Contains('SmartScreen')) 'The alpha download instructions must explain the SmartScreen warning.'

Write-Output 'Windows packaging static checks passed.'
