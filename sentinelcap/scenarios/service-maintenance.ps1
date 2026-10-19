#Requires -RunAsAdministrator
<#
  Scenario: service-maintenance
  Admin purpose : Stop a batch of non-critical services during a maintenance
                  window (patching / config change), then restart them.
  Indicators exercised (4.1): service_stop_burst (>= 5 process-based stops:
                  net stop / sc stop in the window). NOTE: Stop-Service is a
                  cmdlet and spawns no process, so it does NOT count toward the
                  indicator — this script uses sc.exe / net.exe for the burst.
  Safety        : Only touches a safe allow-list of services. NEVER stops
                  Winlogbeat, Sysmon, or networking. Each service is restarted.
#>
$ErrorActionPreference = 'Continue'

# Safe to bounce on Server 2022; none affect the capture pipeline.
$targets = @('Spooler', 'WSearch', 'wuauserv', 'BITS', 'Themes', 'PcaSvc', 'Schedule')
$present = foreach ($n in $targets) {
    if (Get-Service -Name $n -ErrorAction SilentlyContinue) { $n }
}

# Burst of process-based stops (each is an Event 1) — this is what
# service_stop_burst counts. Use sc.exe and net.exe from System32; they are
# logged with full command lines (verified on this lab's Sysmon config).
Write-Host '[svc] stopping services with sc.exe / net.exe (>=5 for the burst)...'
foreach ($n in $present) {
    if ($n -in @('Spooler', 'BITS', 'wuauserv')) {
        net.exe stop $n /y 2>&1 | Out-Null
        Write-Host "  net stop  $n"
    } else {
        sc.exe stop $n 2>&1 | Out-Null
        Write-Host "  sc stop   $n"
    }
}

Start-Sleep 3

Write-Host '[svc] restarting the services...'
foreach ($n in $present) {
    try { Start-Service -Name $n -ErrorAction Stop; Write-Host "  started  $n" }
    catch { Write-Host "  skip     $n" }
}
Write-Host '=== DONE ==='
