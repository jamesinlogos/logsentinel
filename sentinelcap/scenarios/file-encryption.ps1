#Requires -RunAsAdministrator
<#
  Scenario: file-encryption
  Admin purpose : Protect a folder of sensitive documents at rest using built-in
                  EFS encryption (cipher /e), the standard Windows way.
  Indicators exercised (4.1): the benign look-alike of ransomware encryption —
                  cipher processing many files. cipher.exe is logged via
                  OriginalFileName. Optionally also 7-Zip AES if present.
  Safety        : Encrypts only files this script creates under a scratch folder,
                  then decrypts and removes them. VM reverts anyway.
#>
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\Public\sc-work\efs'
$docs = Join-Path $work 'sensitive'
New-Item -ItemType Directory -Force $docs | Out-Null

Write-Host '[efs] generating sensitive documents...'
1..60 | ForEach-Object {
    "confidential record $_  $(Get-Random)" |
        Set-Content (Join-Path $docs ("hr_{0:D3}.docx" -f $_))
}

Write-Host '[efs] cipher /e: EFS-encrypt the folder (recursive)...'
cipher /e /s:$docs 2>&1 | Select-Object -First 10 | Out-Host

Write-Host '[efs] verify encryption state...'
cipher $docs 2>&1 | Select-Object -First 6 | Out-Host

$sevenZip = 'C:\Program Files\7-Zip\7z.exe'
if (Test-Path $sevenZip) {
    Write-Host '[efs] also produce an AES-256 7-Zip archive of the folder...'
    & $sevenZip a -t7z -mhe=on -p"labpass" (Join-Path $work 'sensitive.7z') "$docs\*" 2>&1 |
        Select-Object -Last 4 | Out-Host
}

Write-Host '[efs] decrypt + cleanup...'
cipher /d /s:$docs 2>&1 | Select-Object -First 3 | Out-Host
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
Write-Host '=== DONE ==='
