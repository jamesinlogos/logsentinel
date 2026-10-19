#Requires -RunAsAdministrator
<#
  Scenario: compress-documents
  Admin purpose : Quarterly archival — read many document folders and produce
                  compressed archives (space saving before cold storage).
  Indicators exercised (4.1): the benign look-alike of encryption — one process
                  reads many files and writes many new files with a fixed
                  extension. Touches new_extension_burst-style behavior with .zip
                  (and .7z if 7-Zip is present in the baseline).
  Safety        : Works only in a scratch folder it creates; removed at the end.
#>
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\Public\sc-work\archive'
$src  = Join-Path $work 'projects'
$out  = Join-Path $work 'archives'
New-Item -ItemType Directory -Force $src, $out | Out-Null

Write-Host '[zip] generating project folders to archive...'
1..12 | ForEach-Object {
    $p = Join-Path $src ("project_{0:D2}" -f $_)
    New-Item -ItemType Directory -Force $p | Out-Null
    1..15 | ForEach-Object { "content $_ $(Get-Random)" |
        Set-Content (Join-Path $p ("doc_{0:D2}.txt" -f $_)) }
}

Write-Host '[zip] Compress-Archive each project -> .zip ...'
Get-ChildItem $src -Directory | ForEach-Object {
    $zip = Join-Path $out ($_.Name + '.zip')
    Compress-Archive -Path (Join-Path $_.FullName '*') -DestinationPath $zip -Force
    Write-Host "  archived $($_.Name) -> $(Split-Path $zip -Leaf)"
}

$sevenZip = 'C:\Program Files\7-Zip\7z.exe'
if (Test-Path $sevenZip) {
    Write-Host '[zip] 7-Zip AES archive of the whole project set...'
    & $sevenZip a -t7z -mhe=on -p"archivepass" (Join-Path $out 'all-projects.7z') "$src\*" 2>&1 |
        Select-Object -Last 5 | Out-Host
} else {
    Write-Host '[zip] 7-Zip not present, skipping AES archive step.'
}

Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
Write-Host '=== DONE ==='
