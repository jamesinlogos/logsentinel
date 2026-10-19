#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
  Simulate a small periodic backup and hash verification on a Windows Server.
  The source and backup data are generated under this run's ProgramData folder.
  No real server files, volumes or shadow copies are touched. Stop with Ctrl+C.
#>
[CmdletBinding()]
param(
    [ValidateRange(15, 240)]
    [int]$IntervalMinutes = 60,

    [ValidateRange(2, 48)]
    [int]$KeepCopies = 6
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 1) {
    throw 'Run this scenario on a Windows Server lab VM.'
}

$runRoot = Join-Path $env:ProgramData 'SentinelCap\server-backup-verify'
$runDirectory = Join-Path $runRoot (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
$source = Join-Path $runDirectory 'source'
$copies = Join-Path $runDirectory 'copies'
New-Item -ItemType Directory -Path $source, $copies -Force -ErrorAction Stop | Out-Null
$activityLog = Join-Path $runDirectory 'activity.jsonl'

1..5 | ForEach-Object {
    $path = Join-Path $source ('service-data-{0:D2}.txt' -f $_)
    "Initial lab record $_" | Set-Content -LiteralPath $path -Encoding UTF8
}

$cycle = 0
Write-Host "Backup verification started; interval=$IntervalMinutes min, keep=$KeepCopies, log=$activityLog"
Write-Host 'Press Ctrl+C to stop.'

while ($true) {
    $cycle++
    try {
        $changed = Join-Path $source ('service-data-{0:D2}.txt' -f (1 + (($cycle - 1) % 5)))
        "Lab maintenance record $cycle at $((Get-Date).ToUniversalTime().ToString('o'))" |
            Set-Content -LiteralPath $changed -Encoding UTF8 -ErrorAction Stop

        $copyName = 'copy-{0}-{1:D6}' -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'), $cycle
        $destination = Join-Path $copies $copyName
        New-Item -ItemType Directory -Path $destination -ErrorAction Stop | Out-Null
        $files = @(Get-ChildItem -LiteralPath $source -File -Filter 'service-data-*.txt' -ErrorAction Stop)
        if ($files.Count -ne 5) { throw 'Expected five source files for backup verification.' }
        foreach ($file in $files) {
            $target = Join-Path $destination $file.Name
            Copy-Item -LiteralPath $file.FullName -Destination $target -ErrorAction Stop
            $originalHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            $copyHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($originalHash -ne $copyHash) { throw "Backup verification failed for $($file.Name)" }
        }

        $oldCopies = @(Get-ChildItem -LiteralPath $copies -Directory -Filter 'copy-*' |
            Sort-Object Name -Descending | Select-Object -Skip $KeepCopies)
        foreach ($old in $oldCopies) {
            if ($old.Parent.FullName -ne $copies) { throw 'Backup retention path left the run directory.' }
            if ($old.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Refusing to remove a linked backup directory: $($old.FullName)"
            }
            foreach ($file in @(Get-ChildItem -LiteralPath $old.FullName -File -ErrorAction Stop)) {
                if ($file.Name -notlike 'service-data-*.txt') {
                    throw "Unexpected file in backup directory: $($file.FullName)"
                }
                Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
            }
            Remove-Item -LiteralPath $old.FullName -ErrorAction Stop
        }
        [ordered]@{
            timestamp_utc = (Get-Date).ToUniversalTime().ToString('o')
            cycle = $cycle
            status = 'verified'
            files = $files.Count
            copies_removed = $oldCopies.Count
        } | ConvertTo-Json -Compress | Add-Content -LiteralPath $activityLog -Encoding UTF8
        Write-Host ("{0:o} backup verified; files={1}, cycle={2}" -f (Get-Date), $files.Count, $cycle)
    }
    catch {
        $message = $_.Exception.Message
        Write-Warning ("Backup cycle {0} failed: {1}" -f $cycle, $message)
        [ordered]@{
            timestamp_utc = (Get-Date).ToUniversalTime().ToString('o')
            cycle = $cycle
            status = 'failed'
            error = $message
        } | ConvertTo-Json -Compress | Add-Content -LiteralPath $activityLog -Encoding UTF8
    }
    Start-Sleep -Seconds ($IntervalMinutes * 60)
}
