#Requires -RunAsAdministrator
<#
  Scenario: deploy-startup-app
  Admin purpose : Deploy a management agent / helper that must auto-start with
                  Windows, by registering it under the Run key.
  Indicators exercised (4.1): run_key_persistence (write to CurrentVersion\Run /
                  RunOnce). Both the PowerShell Set-ItemProperty writes and the
                  reg.exe write are logged as Event 13 on this lab's Sysmon config
                  (verified: 3 Run/RunOnce writes captured).
  Safety        : Writes benign HKLM/HKCU Run entries pointing at a harmless
                  helper, then removes them. VM reverts anyway.
#>
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\Public\sc-work\startup'
New-Item -ItemType Directory -Force $work | Out-Null

# A harmless "agent" the startup entry will point at.
$agent = Join-Path $work 'CorpAgent.cmd'
'@echo off' | Set-Content $agent
'echo Corp management agent started >> "%TEMP%\corpagent.log"' | Add-Content $agent

Write-Host '[startup] registering Run keys via PowerShell...'
$hklmRun = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$hkcuRun = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
Set-ItemProperty $hklmRun -Name 'CorpAgent'      -Value "`"$agent`"" -Type String
Set-ItemProperty $hkcuRun -Name 'CorpAgentUser'  -Value "`"$agent`"" -Type String

Write-Host '[startup] also a RunOnce entry via reg.exe...'
reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' `
    /v 'CorpAgentOnce' /t REG_SZ /d "`"$agent`"" /f 2>&1 | Out-Host

Write-Host '[startup] verifying...'
Get-ItemProperty $hklmRun | Select-Object CorpAgent | Out-Host

Write-Host '[startup] removing the deployed entries...'
Remove-ItemProperty $hklmRun -Name 'CorpAgent'     -ErrorAction SilentlyContinue
Remove-ItemProperty $hkcuRun -Name 'CorpAgentUser' -ErrorAction SilentlyContinue
reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' /v 'CorpAgentOnce' /f 2>&1 | Out-Null
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
Write-Host '=== DONE ==='
