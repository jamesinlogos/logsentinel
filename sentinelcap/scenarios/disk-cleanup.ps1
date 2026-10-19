#Requires -RunAsAdministrator
<#
  Scenario: disk-cleanup
  Admin purpose : Reclaim disk space — delete large batches of temp/cache files
                  and securely wipe free space.
  Indicators exercised (4.1): high-volume file deletion (Event 26) — the benign
                  look-alike of a sample deleting many files; plus cipher /w
                  (free-space wipe). cipher.exe is logged via OriginalFileName.
  Safety        : Deletes only files this script created under a scratch folder,
                  never real system/user data. cipher /w wipes free space of the
                  scratch folder only.
#>
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\Public\sc-work\cleanup'
New-Item -ItemType Directory -Force $work | Out-Null

Write-Host '[cleanup] generating a batch of temp/cache files...'
1..120 | ForEach-Object {
    "temp cache blob $_ $(Get-Random)" |
        Set-Content (Join-Path $work ("cache_{0:D4}.tmp" -f $_))
}
Write-Host "  created $((Get-ChildItem $work -Filter *.tmp).Count) temp files."

Write-Host '[cleanup] deleting the temp files (mass delete)...'
Get-ChildItem $work -Filter *.tmp | Remove-Item -Force
Write-Host '  temp files removed.'

Write-Host '[cleanup] cipher /w: wipe free space of the scratch folder...'
# cipher.exe is logged via OriginalFileName; /w overwrites deallocated space.
cipher /w:$work 2>&1 | Select-Object -First 6 | Out-Host

Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
Write-Host '=== DONE ==='
