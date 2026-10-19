#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
  Read-only Windows Server health checks with small JSONL records for a long
  SentinelCap goodware capture. Does not change services or event logs.
  Runs until Ctrl+C.
#>
[CmdletBinding()]
param(
    [ValidateRange(5, 60)]
    [int]$IntervalMinutes = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 1) {
    throw 'Run this scenario on a Windows Server lab VM.'
}

$runRoot = Join-Path $env:ProgramData 'SentinelCap\server-health-monitor'
$runDirectory = Join-Path $runRoot (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
New-Item -ItemType Directory -Path $runDirectory -ErrorAction Stop | Out-Null
$activityLog = Join-Path $runDirectory 'activity.jsonl'
$cycle = 0
Write-Host "Server health monitor started; interval=$IntervalMinutes min, log=$activityLog"
Write-Host 'Press Ctrl+C to stop.'

while ($true) {
    $cycle++
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $disk = Get-CimInstance Win32_LogicalDisk -ErrorAction Stop |
            Where-Object { $_.DeviceID -eq $env:SystemDrive }
        $services = @('EventLog', 'W32Time', 'LanmanServer') | ForEach-Object {
            $name = $_
            $service = Get-Service -Name $name -ErrorAction SilentlyContinue
            [ordered]@{
                name = $name
                status = if ($null -ne $service) { $service.Status.ToString() } else { 'not_present' }
            }
        }
        $recentSystemEvents = @(Get-WinEvent -LogName System -MaxEvents 5 -ErrorAction Stop)
        $record = [ordered]@{
            timestamp_utc = (Get-Date).ToUniversalTime().ToString('o')
            cycle = $cycle
            status = 'ok'
            host = $env:COMPUTERNAME
            uptime_minutes = [int]((Get-Date) - $os.LastBootUpTime).TotalMinutes
            free_memory_mb = [int]($os.FreePhysicalMemory / 1024)
            system_drive_free_gb = if ($null -ne $disk) { [Math]::Round($disk.FreeSpace / 1GB, 2) } else { $null }
            process_count = @(Get-Process -ErrorAction Stop).Count
            recent_system_events_read = $recentSystemEvents.Count
            services = $services
        }
        $record | ConvertTo-Json -Compress -Depth 4 |
            Add-Content -LiteralPath $activityLog -Encoding UTF8
        Write-Host ("{0:o} health ok; cycle={1}, processes={2}" -f `
            (Get-Date), $cycle, $record.process_count)
    }
    catch {
        $message = $_.Exception.Message
        Write-Warning ("Health cycle {0} failed: {1}" -f $cycle, $message)
        [ordered]@{
            timestamp_utc = (Get-Date).ToUniversalTime().ToString('o')
            cycle = $cycle
            status = 'failed'
            error = $message
        } | ConvertTo-Json -Compress | Add-Content -LiteralPath $activityLog -Encoding UTF8
    }
    Start-Sleep -Seconds ($IntervalMinutes * 60)
}
