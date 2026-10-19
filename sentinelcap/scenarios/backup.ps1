#Requires -RunAsAdministrator
<#
  Scenario: backup
  Admin purpose : Nightly server backup — snapshot state, copy data to a backup
                  target, list existing restore points.
  Indicators exercised (inference/README.md section 4.1): backup tooling (wbadmin), bulk file copy.
  Safety        : wbadmin targets a scratch folder; no shadow copy is deleted here
                  (see shadow-copy-cleanup for that). Reverted by VM baseline.
#>
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\Public\sc-work\backup'
$src  = Join-Path $work 'data'
$dst  = Join-Path $work 'backup-target'
New-Item -ItemType Directory -Force $src, $dst | Out-Null

Write-Host '[backup] generating source data to back up...'
1..40 | ForEach-Object {
    "Report $_  generated $(Get-Date -Format o)" |
        Set-Content (Join-Path $src ("finance_{0:D3}.csv" -f $_))
}

Write-Host '[backup] listing current shadow copies (read-only)...'
wbadmin get versions 2>&1 | Out-Host
vssadmin list shadows 2>&1 | Select-Object -First 20 | Out-Host

Write-Host '[backup] robocopy mirror to backup target...'
robocopy $src $dst /MIR /NFL /NDL /NJH /NJS 2>&1 | Out-Null

Write-Host '[backup] wbadmin file backup to a separate volume...'
# wbadmin requires a dedicated volume/network share as the target (a subfolder
# of the source volume C: is rejected). Use D:\ if present, else skip.
if (Test-Path 'D:\') {
    wbadmin start backup -backupTarget:D: -include:$src -vssCopy -quiet 2>&1 |
        Select-Object -First 15 | Out-Host
} else {
    Write-Host '  no D: volume, skipping wbadmin image backup (get versions above already ran wbadmin).'
}

Write-Host '[backup] cleanup working data...'
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
Write-Host '=== DONE ==='
