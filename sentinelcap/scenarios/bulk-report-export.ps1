#Requires -RunAsAdministrator
<#
  Scenario: bulk-report-export
  Admin purpose : Nightly reporting job that exports many records to per-record
                  files with a fixed application-specific extension.
  Indicators exercised (4.1): new_extension_burst (one process creates >= 50 new
                  files with the same uncommon extension). Benign look-alike of
                  ransomware writing many files with a new encrypted extension.
  Safety        : Writes only into a scratch folder; removed at the end.
#>
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\Public\sc-work\reports'
New-Item -ItemType Directory -Force $work | Out-Null

# An application-specific, uncommon extension (not in the common-extension list).
$ext = '.rptx'
$count = 80

Write-Host "[report] exporting $count records to *$ext ..."
1..$count | ForEach-Object {
    $f = Join-Path $work ("record_{0:D4}$ext" -f $_)
    @"
RecordId,$_
Exported,$(Get-Date -Format o)
Amount,$(Get-Random -Minimum 100 -Maximum 99999)
"@ | Set-Content $f
}
Write-Host "[report] wrote $((Get-ChildItem $work -Filter *$ext).Count) files."

Write-Host '[report] rolling the export up into a single manifest...'
Get-ChildItem $work -Filter "*$ext" | Select-Object -First 5 Name | Out-Host

Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
Write-Host '=== DONE ==='
