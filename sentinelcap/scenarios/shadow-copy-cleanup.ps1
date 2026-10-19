#Requires -RunAsAdministrator
<#
  Scenario: shadow-copy-cleanup
  Admin purpose : Reclaim disk space by removing old Volume Shadow Copies /
                  restore points during routine maintenance.
  Indicators exercised (4.1): shadow_copy_deletion (delete shadows, wbadmin
                  delete catalog, Win32_Shadowcopy delete, resize shadowstorage).
  Safety        : Deleting shadow copies is a normal admin action; VM reverts to
                  baseline afterwards. All tools run from System32 and are logged
                  with full command lines on this lab's Sysmon config.
#>
$ErrorActionPreference = 'Continue'

Write-Host '[vss] current shadow storage + copies...'
vssadmin list shadowstorage 2>&1 | Out-Host
vssadmin list shadows 2>&1 | Select-Object -First 10 | Out-Host

Write-Host '[vss] create one restore point so there is something to prune...'
(Get-WmiObject -List Win32_ShadowCopy).Create('C:\', 'ClientAccessible') 2>&1 | Out-Host

Write-Host '[vss] resize shadow storage (maintenance)...'
vssadmin resize shadowstorage /for=C: /on=C: /maxsize=5% 2>&1 | Out-Host

Write-Host '[vss] delete the oldest shadow copy via vssadmin...'
vssadmin delete shadows /for=C: /oldest /quiet 2>&1 | Out-Host

Write-Host '[vss] delete shadow copies via WMI (Win32_Shadowcopy)...'
Get-WmiObject Win32_ShadowCopy | Select-Object -First 1 |
    ForEach-Object { $_.Delete(); Write-Host "  deleted $($_.ID)" }

Write-Host '[vss] wbadmin delete backup catalog (maintenance)...'
wbadmin delete catalog -quiet 2>&1 | Select-Object -First 5 | Out-Host
Write-Host '=== DONE ==='
