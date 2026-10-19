#Requires -RunAsAdministrator
<#
  Scenario: deploy-config-files
  Admin purpose : Push a standard config / README file into every project folder
                  across multiple shares (policy rollout, template distribution).
  Indicators exercised (4.1): mass_note_drop (one process creates the SAME file
                  name in >= 10 directories, across >= 5 different level-4 branches).
                  This is the benign look-alike of ransom-note dropping.
  Safety        : Only writes a small README.txt into existing decoy folders under
                  user profiles and D:\ shares; removed at the end.
#>
$ErrorActionPreference = 'Continue'

# Spread across several distinct branches so it mirrors mass_note_drop's
# ">= 5 level-4 branches" condition, exactly as a real rollout would.
$roots = @(
    'C:\Users\Administrator', 'C:\Users\Public', 'C:\Users\sysmaint',
    'D:\Backup', 'D:\Shares'
) | Where-Object { Test-Path $_ }

$fileName = 'PROJECT-README.txt'
$content  = @"
Company IT — project folder standard.
Contact helpdesk@corp.local for the retention policy.
Deployed: $(Get-Date -Format o)
"@

$dropped = New-Object System.Collections.Generic.List[string]
foreach ($root in $roots) {
    $dirs = Get-ChildItem -Path $root -Directory -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 8
    foreach ($d in $dirs) {
        $target = Join-Path $d.FullName $fileName
        try { $content | Set-Content $target -ErrorAction Stop; $dropped.Add($target) }
        catch { }
    }
}
Write-Host "[deploy] wrote '$fileName' into $($dropped.Count) folders across $($roots.Count) shares."

Write-Host '[deploy] removing the deployed files...'
foreach ($f in $dropped) { Remove-Item $f -Force -ErrorAction SilentlyContinue }
Write-Host '=== DONE ==='
