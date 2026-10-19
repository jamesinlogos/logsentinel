#Requires -RunAsAdministrator
<#
  Scenario: scheduled-task-setup
  Admin purpose : Schedule a batch of routine maintenance jobs (cleanup, report,
                  health-check) via the Task Scheduler.
  Indicators exercised (4.1): a legitimate persistence-adjacent baseline (task
                  creation) so scheduled-task churn is represented in goodware.
  Safety        : Tasks point at harmless commands and are all deleted at the end.
                  schtasks.exe runs from System32 and is logged with full command
                  lines on this lab's Sysmon config; Register-ScheduledTask is
                  also shown.
#>
$ErrorActionPreference = 'Continue'
$names = @('SC_Cleanup', 'SC_Report', 'SC_HealthCheck', 'SC_Sync', 'SC_Rotate')

Write-Host '[task] creating maintenance tasks via schtasks.exe...'
foreach ($n in $names) {
    schtasks /create /tn $n /tr "cmd.exe /c echo $n ran >> %TEMP%\sc-tasks.log" `
        /sc daily /st 03:00 /ru SYSTEM /f 2>&1 | Out-Host
}

Write-Host '[task] one task via Register-ScheduledTask (PowerShell form)...'
$action  = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c echo psjob'
$trigger = New-ScheduledTaskTrigger -Daily -At 4am
Register-ScheduledTask -TaskName 'SC_PsJob' -Action $action -Trigger $trigger `
    -User 'SYSTEM' -Force -ErrorAction SilentlyContinue | Out-Null

Write-Host '[task] listing the created tasks...'
schtasks /query /tn SC_Cleanup 2>&1 | Out-Host

Write-Host '[task] removing all created tasks (cleanup)...'
foreach ($n in ($names + 'SC_PsJob')) { schtasks /delete /tn $n /f 2>&1 | Out-Null }
Write-Host '=== DONE ==='
