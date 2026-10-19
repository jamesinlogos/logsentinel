#Requires -RunAsAdministrator
<#
  Scenario: boot-config-maintenance
  Admin purpose : Prepare a server for a controlled reboot / recovery test by
                  adjusting boot configuration, then restore the defaults.
  Indicators exercised (4.1): recovery_disable (bcdedit recoveryenabled no,
                  bootstatuspolicy ignoreallfailures). Benign look-alike of
                  ransomware disabling Windows recovery.
  Safety        : bcdedit.exe is logged via OriginalFileName. Every change is
                  reverted at the end; VM also reverts to baseline.
#>
$ErrorActionPreference = 'Continue'

Write-Host '[boot] current boot configuration...'
bcdedit /enum '{default}' 2>&1 | Select-Object -First 20 | Out-Host

Write-Host '[boot] applying maintenance settings...'
bcdedit /set '{default}' bootstatuspolicy ignoreallfailures 2>&1 | Out-Host
bcdedit /set '{default}' recoveryenabled No 2>&1 | Out-Host
bcdedit /timeout 10 2>&1 | Out-Host

Start-Sleep 2

Write-Host '[boot] restoring defaults...'
bcdedit /set '{default}' bootstatuspolicy displayallfailures 2>&1 | Out-Host
bcdedit /set '{default}' recoveryenabled Yes 2>&1 | Out-Host
bcdedit /timeout 30 2>&1 | Out-Host
Write-Host '=== DONE ==='
