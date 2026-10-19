#Requires -RunAsAdministrator
<#
  Scenario: log-archival
  Admin purpose : Compliance log rotation — export event logs to .evtx archives,
                  then clear the live logs to start a fresh retention period.
  Indicators exercised (4.1): event_log_tamper (wevtutil cl / Clear-EventLog).
  Safety        : Clears ONLY 'Application' and 'Windows PowerShell'. NEVER clears
                  'Security' or 'Microsoft-Windows-Sysmon/Operational' (would wipe
                  our own telemetry). Winlogbeat has already shipped forwarded
                  events, so clearing the local Application log is harmless here.
#>
$ErrorActionPreference = 'Continue'
$arch = 'C:\Users\Public\sc-work\logarchive'
New-Item -ItemType Directory -Force $arch | Out-Null

$channels = @('Application', 'Windows PowerShell')
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

foreach ($ch in $channels) {
    $safe = ($ch -replace '[\\/ ]', '_')
    $out  = Join-Path $arch "$safe-$stamp.evtx"
    Write-Host "[log] exporting '$ch' -> $out"
    wevtutil epl "$ch" "$out" 2>&1 | Out-Host
    Write-Host "[log] clearing '$ch'"
    wevtutil cl "$ch" 2>&1 | Out-Host
}

# Clear-EventLog is the PowerShell equivalent an admin might use instead.
Write-Host '[log] Clear-EventLog on Application (PowerShell cmdlet form)...'
Clear-EventLog -LogName Application -ErrorAction SilentlyContinue

Write-Host '[log] archives kept at:' $arch
Get-ChildItem $arch | Select-Object Name, Length | Out-Host
Write-Host '=== DONE ==='
