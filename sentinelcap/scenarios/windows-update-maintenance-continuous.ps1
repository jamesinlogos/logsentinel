#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
  Continuous Windows Update maintenance on a bare Windows Server lab VM.
  Re-enable Windows Update when the baseline disabled its service or local
  NoAutoUpdate policy. Start the update services, then search, download and
  install assigned software updates every 60-120 minutes. Stop with Ctrl+C.
  Reboot is left to the operator after the capture session.
  Another update policy can override these local settings.
#>
[CmdletBinding()]
param(
    [ValidateRange(60, 120)]
    [int]$UpdateIntervalMinutes = 90,

    [ValidateRange(5, 30)]
    [int]$HealthIntervalMinutes = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
if ($os.ProductType -eq 1) {
    throw 'Run this script on a Windows Server lab VM.'
}

$runRoot = Join-Path $env:ProgramData 'SentinelCap\windows-update-maintenance'
$runDirectory = Join-Path $runRoot (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
New-Item -ItemType Directory -Path $runDirectory -ErrorAction Stop | Out-Null
$logPath = Join-Path $runDirectory 'activity.jsonl'

function Write-ActivityRecord {
    param([System.Collections.IDictionary]$Record)
    $Record['timestamp_utc'] = (Get-Date).ToUniversalTime().ToString('o')
    $Record | ConvertTo-Json -Compress -Depth 4 | Add-Content -LiteralPath $logPath -Encoding UTF8
}

$auPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
$wuPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'

# Let this script perform the download/install; do not schedule a separate
# automatic installation or reboot. Do not alter WSUS server selection.
New-Item -Path $wuPolicy -Force | Out-Null
New-Item -Path $auPolicy -Force | Out-Null
New-ItemProperty -Path $auPolicy -Name NoAutoUpdate -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $auPolicy -Name AUOptions -Value 2 -PropertyType DWord -Force | Out-Null
$accessPolicy = Get-ItemProperty -Path $wuPolicy -ErrorAction Stop
if ($null -ne $accessPolicy.PSObject.Properties['DisableWindowsUpdateAccess']) {
    New-ItemProperty -Path $wuPolicy -Name DisableWindowsUpdateAccess -Value 0 `
        -PropertyType DWord -Force | Out-Null
}

function Assert-UpdatePolicy {
    $au = Get-ItemProperty -Path $auPolicy -ErrorAction Stop
    if ($au.NoAutoUpdate -ne 0 -or $au.AUOptions -ne 2) {
        throw 'Windows Update policy changed; check local or managed update policy.'
    }
    $wu = Get-ItemProperty -Path $wuPolicy -ErrorAction Stop
    $accessBlock = $wu.PSObject.Properties['DisableWindowsUpdateAccess']
    if ($null -ne $accessBlock -and $accessBlock.Value -eq 1) {
        throw 'Windows Update access is disabled again; check local or managed update policy.'
    }
}

function Start-UpdateServices {
    foreach ($name in @('wuauserv', 'BITS')) {
        $service = Get-Service -Name $name -ErrorAction Stop
        if ($service.StartType -eq 'Disabled') {
            Set-Service -Name $name -StartupType Manual -ErrorAction Stop
        }
        $service.Refresh()
        if ($service.Status -ne 'Running') {
            Start-Service -Name $name -ErrorAction Stop
        }
    }

    # UsoSvc is protected on some Windows Server builds. Do not edit its
    # service registry key or repeatedly restart it.
    $orchestrator = Get-Service -Name UsoSvc -ErrorAction SilentlyContinue
    if ($null -ne $orchestrator) {
        try {
            if ($orchestrator.StartType -eq 'Disabled') {
                Set-Service -Name UsoSvc -StartupType Manual -ErrorAction Stop
            }
            if ($orchestrator.Status -ne 'Running') {
                Start-Service -Name UsoSvc -ErrorAction Stop
            }
        }
        catch {
            Write-Warning ("UsoSvc could not be started directly: {0}" -f $_.Exception.Message)
        }
    }
}

function Invoke-UpdateMaintenance {
    $session = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'SentinelCap Windows Server update maintenance'
    $searcher = $session.CreateUpdateSearcher()
    $search = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software' and IsAssigned=1")
    if ([int]$search.ResultCode -ne 2) {
        throw "Windows Update search failed (result=$($search.ResultCode))."
    }

    $selected = New-Object -ComObject Microsoft.Update.UpdateColl
    $skipped = 0
    for ($i = 0; $i -lt $search.Updates.Count; $i++) {
        $update = $search.Updates.Item($i)
        # Do not accept new license terms or block on interactive UI.
        if (-not $update.EulaAccepted -or $update.InstallationBehavior.CanRequestUserInput) {
            $skipped++
            continue
        }
        if ([int]$update.InstallationBehavior.Impact -eq 2) {
            # An exclusive update must be installed alone; retry the rest on
            # the next cycle after this one completes.
            $selected = New-Object -ComObject Microsoft.Update.UpdateColl
            $null = $selected.Add($update)
            break
        }
        $null = $selected.Add($update)
    }

    $summary = [ordered]@{
        kind = 'update_maintenance'
        available_updates = [int]$search.Updates.Count
        selected_updates = [int]$selected.Count
        skipped_updates = $skipped
        downloaded_updates = 0
        installed_updates = 0
        failed_updates = 0
        reboot_required = $false
        updates = @()
    }
    if ($selected.Count -eq 0) {
        $summary['status'] = 'no_eligible_updates'
        return $summary
    }

    $downloader = $session.CreateUpdateDownloader()
    $downloader.Updates = $selected
    $download = $downloader.Download()
    $ready = New-Object -ComObject Microsoft.Update.UpdateColl
    for ($i = 0; $i -lt $selected.Count; $i++) {
        $update = $selected.Item($i)
        if ($update.IsDownloaded) {
            $null = $ready.Add($update)
        }
    }
    $summary['downloaded_updates'] = [int]$ready.Count
    $summary['failed_updates'] = [int]($selected.Count - $ready.Count)
    $summary['download_result_code'] = [int]$download.ResultCode
    if ($ready.Count -eq 0) {
        $summary['status'] = 'download_failed'
        return $summary
    }

    $installer = $session.CreateUpdateInstaller()
    $installer.Updates = $ready
    $installer.AllowSourcePrompts = $false
    if ($installer.RebootRequiredBeforeInstallation) {
        $summary['reboot_required'] = $true
        $summary['status'] = 'reboot_required_before_install'
        return $summary
    }

    $installation = $installer.Install()
    $summary['install_result_code'] = [int]$installation.ResultCode
    $summary['reboot_required'] = [bool]$installation.RebootRequired
    $results = @()
    for ($i = 0; $i -lt $ready.Count; $i++) {
        $updateResult = $installation.GetUpdateResult($i)
        $code = [int]$updateResult.ResultCode
        if ($code -eq 2) { $summary['installed_updates']++ }
        else { $summary['failed_updates']++ }
        $results += [ordered]@{
            title = $ready.Item($i).Title
            result_code = $code
            hresult = [int]$updateResult.HResult
        }
    }
    $summary['updates'] = $results
    $summary['status'] = if ($summary['failed_updates'] -eq 0 -and
        $summary['install_result_code'] -eq 2) { 'installed' } else { 'partial_failure' }
    return $summary
}

function Invoke-HealthCheck {
    $currentOs = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop |
        Where-Object { $_.DeviceID -eq $env:SystemDrive }
    $eventLog = Get-Service -Name EventLog -ErrorAction Stop
    $recentEvents = @(Get-WinEvent -LogName System -MaxEvents 5 -ErrorAction SilentlyContinue)
    return [ordered]@{
        kind = 'server_health'
        uptime_minutes = [int]((Get-Date) - $currentOs.LastBootUpTime).TotalMinutes
        free_memory_mb = [int]($currentOs.FreePhysicalMemory / 1024)
        system_drive_free_gb = if ($null -ne $disk) { [Math]::Round($disk.FreeSpace / 1GB, 2) } else { $null }
        event_log_service = $eventLog.Status.ToString()
        recent_system_events_read = $recentEvents.Count
    }
}

Assert-UpdatePolicy
Start-UpdateServices
Write-Host ("Windows Update maintenance started: update={0} min, health={1} min, log={2}" -f `
    $UpdateIntervalMinutes, $HealthIntervalMinutes, $logPath)
Write-Host 'Press Ctrl+C to stop. Updates are downloaded and installed; reboot is manual.'

$nextUpdate = Get-Date
$nextHealth = Get-Date
$pendingReboot = $false
while ($true) {
    if (-not $pendingReboot -and (Get-Date) -ge $nextUpdate) {
        try {
            Assert-UpdatePolicy
            Start-UpdateServices
            $maintenance = Invoke-UpdateMaintenance
            Write-ActivityRecord $maintenance
            Write-Host ("{0:o} update status={1} available={2} downloaded={3} installed={4}" -f `
                (Get-Date), $maintenance.status, $maintenance.available_updates, `
                $maintenance.downloaded_updates, $maintenance.installed_updates)
            if ($maintenance.reboot_required) {
                $pendingReboot = $true
                Write-Warning 'A reboot is required. Finish capture, then reboot the server manually.'
            }
        }
        catch {
            Write-Warning ("Windows Update cycle failed: {0}" -f $_.Exception.Message)
            Write-ActivityRecord ([ordered]@{
                kind = 'update_maintenance'
                status = 'failed'
                error = $_.Exception.Message
            })
        }
        $nextUpdate = (Get-Date).AddMinutes($UpdateIntervalMinutes)
    }

    if ((Get-Date) -ge $nextHealth) {
        try {
            $health = Invoke-HealthCheck
            Write-ActivityRecord $health
            Write-Host ("{0:o} server health check succeeded; uptime={1} min" -f `
                (Get-Date), $health.uptime_minutes)
        }
        catch {
            Write-Warning ("Server health check failed: {0}" -f $_.Exception.Message)
            Write-ActivityRecord ([ordered]@{
                kind = 'server_health'
                status = 'failed'
                error = $_.Exception.Message
            })
        }
        $nextHealth = (Get-Date).AddMinutes($HealthIntervalMinutes)
    }

    $wakeAt = if (-not $pendingReboot -and $nextUpdate -lt $nextHealth) {
        $nextUpdate
    } else {
        $nextHealth
    }
    $sleepSeconds = [int][Math]::Max(1, [Math]::Min(60, [Math]::Ceiling(($wakeAt - (Get-Date)).TotalSeconds)))
    Start-Sleep -Seconds $sleepSeconds
}
