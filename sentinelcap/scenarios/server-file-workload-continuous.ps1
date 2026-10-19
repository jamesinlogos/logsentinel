#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
  Simulate sustained application file processing on a Windows Server lab VM.
  Writes only under this run's ProgramData directory. Runs until Ctrl+C.
  Each input creates a CSV, a working copy and a temporary JSON receipt.
  IntervalSeconds is the pause AFTER a batch, not a guaranteed event rate.
#>
[CmdletBinding(DefaultParameterSetName = 'Seconds')]
param(
    [Parameter(ParameterSetName = 'Seconds')]
    [ValidateRange(0, 3600)]
    [int]$IntervalSeconds = 30,

    # Retained for existing invocations; cannot be combined with IntervalSeconds.
    [Parameter(ParameterSetName = 'Minutes', Mandatory = $true)]
    [ValidateRange(2, 60)]
    [int]$IntervalMinutes,

    [ValidateRange(1, 5000)]
    [int]$FilesPerCycle = 200,

    [ValidateRange(1, 1000)]
    [int]$RowsPerFile = 32,

    [ValidateRange(20, 20000)]
    [int]$MaxArchivedFiles = 2000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 1) {
    throw 'Run this scenario on a Windows Server lab VM.'
}

$pauseSeconds = $IntervalSeconds
if ($PSCmdlet.ParameterSetName -eq 'Minutes') { $pauseSeconds = $IntervalMinutes * 60 }
$runRoot = Join-Path $env:ProgramData 'SentinelCap\server-file-workload'
$runName = '{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'), [guid]::NewGuid().ToString('N')
$runDirectory = Join-Path $runRoot $runName
# The repository's Sysmon FileCreate rules include paths containing \Documents\.
$documents = Join-Path $runDirectory 'Documents'
$inbox = Join-Path $documents 'inbox'
$working = Join-Path $documents 'working'
$archive = Join-Path $documents 'archive'
New-Item -ItemType Directory -Path $inbox, $working, $archive -Force -ErrorAction Stop | Out-Null
$activityLog = Join-Path $runDirectory 'activity.jsonl'
$previousLog = Join-Path $runDirectory 'activity.previous.jsonl'
$archiveQueue = New-Object 'System.Collections.Generic.Queue[string]'
$random = New-Object System.Random
[long]$cycle = 0
Write-Host ("File workload started; files/cycle={0}, rows/file={1}, pause={2}s, archive cap={3}, log={4}" -f `
    $FilesPerCycle, $RowsPerFile, $pauseSeconds, $MaxArchivedFiles, $activityLog)
Write-Host 'Press Ctrl+C to stop.'

while ($true) {
    $cycle++
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $processedFiles = 0
    $processedRows = 0
    $totalUnits = 0
    $filesCreated = 0
    $filesRemoved = 0
    $archivedFilesRemoved = 0
    $status = 'ok'
    $message = $null
    $cleanupFailed = $false
    try {
        for ($fileIndex = 1; $fileIndex -le $FilesPerCycle; $fileIndex++) {
            $stem = 'requests-{0:D10}-{1:D5}' -f $cycle, $fileIndex
            $incoming = Join-Path $inbox "$stem.csv"
            $processing = Join-Path $working "$stem.csv"
            $receipt = Join-Path $working "$stem.json"
            try {
                $createdUtc = [DateTime]::UtcNow.ToString('o')
                $items = for ($rowIndex = 1; $rowIndex -le $RowsPerFile; $rowIndex++) {
                    [pscustomobject]@{
                        request_id = '{0}-{1:D4}' -f $stem, $rowIndex
                        created_utc = $createdUtc
                        units = $random.Next(1, 10)
                    }
                }
                $items | Export-Csv -LiteralPath $incoming -NoTypeInformation -Encoding UTF8
                $filesCreated++
                Copy-Item -LiteralPath $incoming -Destination $processing
                $filesCreated++
                $processed = @(Import-Csv -LiteralPath $processing)
                if ($processed.Count -ne $RowsPerFile) { throw "Unexpected row count in $processing" }

                $fileUnits = 0
                foreach ($row in $processed) { $fileUnits += [int]$row.units }
                [ordered]@{
                    cycle = $cycle
                    file = $stem
                    processed_utc = [DateTime]::UtcNow.ToString('o')
                    rows = $processed.Count
                    units = $fileUnits
                } | ConvertTo-Json -Compress | Set-Content -LiteralPath $receipt -Encoding UTF8
                $filesCreated++

                # FIFO retention avoids scanning/sorting thousands of files every batch.
                # Peek before deleting so a failed deletion remains queued for retry.
                while ($archiveQueue.Count -ge $MaxArchivedFiles) {
                    Remove-Item -LiteralPath $archiveQueue.Peek() -Force
                    [void]$archiveQueue.Dequeue()
                    $archivedFilesRemoved++
                    $filesRemoved++
                }
                $archived = Join-Path $archive "$stem.csv"
                Move-Item -LiteralPath $processing -Destination $archived
                $archiveQueue.Enqueue($archived)
                $processedFiles++
                $processedRows += $processed.Count
                $totalUnits += $fileUnits
            }
            finally {
                # At most one input is in flight; also clean up after a failed file.
                foreach ($temporaryFile in @($incoming, $processing, $receipt)) {
                    try {
                        if (Test-Path -LiteralPath $temporaryFile -PathType Leaf) {
                            Remove-Item -LiteralPath $temporaryFile -Force
                            $filesRemoved++
                        }
                    }
                    catch {
                        $cleanupFailed = $true
                        Write-Warning ("Could not remove {0}: {1}" -f $temporaryFile, $_.Exception.Message)
                    }
                }
                if ($cleanupFailed) { throw 'Temporary file cleanup failed; stopping to avoid accumulating leftovers.' }
            }
        }
        [ordered]@{
            cycle = $cycle
            processed_utc = [DateTime]::UtcNow.ToString('o')
            files = $processedFiles
            rows = $processedRows
            units = $totalUnits
        } | ConvertTo-Json -Compress |
            Set-Content -LiteralPath (Join-Path $runDirectory 'latest-result.json') -Encoding UTF8
    }
    catch {
        $status = 'failed'
        $message = $_.Exception.Message
        Write-Warning ("File workload cycle {0} failed: {1}" -f $cycle, $message)
    }
    $timer.Stop()
    $sleepSeconds = $pauseSeconds
    if ($status -eq 'failed') { $sleepSeconds = [Math]::Max(1, $pauseSeconds) }
    $cycleSeconds = $timer.Elapsed.TotalSeconds + $sleepSeconds
    # These counters describe workload files, not measured Sysmon events.
    $record = [ordered]@{
        timestamp_utc = [DateTime]::UtcNow.ToString('o')
        cycle = $cycle
        status = $status
        processed_files = $processedFiles
        processed_rows = $processedRows
        files_created = $filesCreated
        files_removed = $filesRemoved
        archive_files = $archiveQueue.Count
        archive_files_removed = $archivedFilesRemoved
        work_seconds = [Math]::Round($timer.Elapsed.TotalSeconds, 3)
        pause_seconds = $sleepSeconds
        file_creates_per_second = [Math]::Round($filesCreated / [Math]::Max(0.001, $cycleSeconds), 2)
        error = $message
    }
    # Keep the current log plus one previous segment, each about 16 MiB.
    if ((Test-Path -LiteralPath $activityLog) -and (Get-Item -LiteralPath $activityLog).Length -ge 16MB) {
        if (Test-Path -LiteralPath $previousLog) { Remove-Item -LiteralPath $previousLog -Force }
        Move-Item -LiteralPath $activityLog -Destination $previousLog
    }
    $record | ConvertTo-Json -Compress | Add-Content -LiteralPath $activityLog -Encoding UTF8
    Write-Host ("{0:o} cycle={1} status={2}; files={3}, rows={4}, creates={5}, creates/s~{6}" -f `
        (Get-Date), $cycle, $status, $processedFiles, $processedRows, $filesCreated, $record.file_creates_per_second)
    if ($cleanupFailed) { throw $message }
    if ($sleepSeconds -gt 0) { Start-Sleep -Seconds $sleepSeconds }
}
