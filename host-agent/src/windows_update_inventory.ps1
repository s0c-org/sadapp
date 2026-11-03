$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $searcher.Online = $false
    $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    if ([int]$result.ResultCode -ne 2) {
        throw "Cached Windows Update search was incomplete (result $($result.ResultCode))."
    }
    if ($result.Updates.Count -gt 10000) {
        throw 'Cached Windows Update inventory exceeds the 10000-entry budget.'
    }
    $security = 0
    $sample = @()
    for ($index = 0; $index -lt $result.Updates.Count; $index++) {
        $update = $result.Updates.Item($index)
        $isSecurity = $false
        foreach ($category in $update.Categories) {
            # Security Updates classification ID is independent of the display language.
            if ($category.CategoryID -eq '0fa1201d-4330-4fa8-8ae9-b877473b6441') {
                $isSecurity = $true
            }
        }
        if ($isSecurity) { $security++ }
        if ($sample.Count -lt 15) {
            $title = [string]$update.Title
            $sample += $title.Substring(0, [Math]::Min(300, $title.Length))
        }
    }
    $systemInfo = New-Object -ComObject Microsoft.Update.SystemInfo
    @{
        pending_updates = [long]$result.Updates.Count
        pending_security_updates = [long]$security
        reboot_required = [bool]$systemInfo.RebootRequired
        sample = @($sample)
        inventory_source = 'windows_update_cached'
    } | ConvertTo-Json -Compress -Depth 3
} catch {
    [Console]::Error.WriteLine("Windows Update inventory unavailable: $($_.Exception.Message)")
    exit 1
}
