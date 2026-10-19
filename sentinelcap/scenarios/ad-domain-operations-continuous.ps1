#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
  Low-volume AD administration after promoting this lab VM in the same capture.
  All AD and policy writes are confined to a unique SentinelCap OU and GPO. Lab users are
  disabled and have no password. The script removes its objects on exit.
  This is a single DC's activity, not client logons or multi-DC replication.
#>
[CmdletBinding()]
param(
    [ValidateRange(30, 600)]
    [int]$IntervalSeconds = 60,

    [ValidateRange(1, 60)]
    [int]$ReadinessTimeoutMinutes = 20,

    [ValidateNotNullOrEmpty()]
    [string]$ExpectedDomainName = 'ad.logsentinel.test'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Console]::IsInputRedirected) {
    throw 'Run this script in an interactive guest console so Enter can stop it cleanly.'
}

function Test-GuestEnter {
    while ([Console]::KeyAvailable) {
        if ([Console]::ReadKey($true).Key -eq [ConsoleKey]::Enter) {
            return $true
        }
    }
    return $false
}

$computer = Get-CimInstance -ClassName Win32_ComputerSystem
if ($computer.DomainRole -lt 4) {
    throw 'Run this script on a promoted domain controller, after its reboot.'
}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop
$ready = $false
$readyDeadline = (Get-Date).AddMinutes($ReadinessTimeoutMinutes)
while (-not $ready) {
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $dnsRoot = $domain.DNSRoot
        foreach ($serviceName in @('NTDS', 'DNS', 'Netlogon')) {
            $service = Get-Service -Name $serviceName -ErrorAction Stop
            if ($service.Status -ne 'Running') {
                throw "Required DC service $serviceName is not running."
            }
        }
        $srvName = '_ldap._tcp.dc._msdcs.' + $dnsRoot
        $null = Resolve-DnsName -Name $srvName -Type SRV -DnsOnly -ErrorAction Stop
        $sysvol = Join-Path $env:WINDIR ("SYSVOL\sysvol\{0}\Policies" -f $dnsRoot)
        if (-not (Test-Path -LiteralPath $sysvol -PathType Container)) {
            throw "SYSVOL policies directory is missing: $sysvol"
        }
        $ready = $true
    }
    catch {
        if ((Get-Date) -ge $readyDeadline) {
            throw "DC did not become ready within $ReadinessTimeoutMinutes minutes: $($_.Exception.Message)"
        }
        Write-Warning ("Waiting for DC services, DNS and SYSVOL: {0}" -f $_.Exception.Message)
        Start-Sleep -Seconds 30
    }
}
if ($dnsRoot -ne $ExpectedDomainName) {
    throw "Connected to $dnsRoot, expected lab domain $ExpectedDomainName."
}

$runRoot = Join-Path $env:ProgramData 'SentinelCap\ad-domain-operations'
$runDirectory = Join-Path $runRoot (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
New-Item -ItemType Directory -Path $runDirectory -ErrorAction Stop | Out-Null

$runId = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$rootName = "SentinelCap-$runId"
$rootDn = "OU=$rootName,$($domain.DistinguishedName)"
$gpoName = "SentinelCap-Lab-$runId"
$groupSam = "scg$runId"
$rootOu = $null
$gpo = $null
$gpoLinked = $false
$labUsers = New-Object System.Collections.ArrayList
$cleanupErrors = New-Object System.Collections.ArrayList
$runFailure = $null
$failureCount = 0
$consecutiveFailures = 0
$cycle = 0
$createdUserCount = 0
$removedUserCount = 0
$gpoUpdateCount = 0
$temporaryOuCount = 0
$temporaryGroupCreatedCount = 0
$temporaryGroupRemovedCount = 0
$ouUpdateCount = 0
$gpoLinkUpdateCount = 0
$stopRequested = $false
$clock = [Diagnostics.Stopwatch]::StartNew()

Write-Host ("AD operations started: domain={0}, OU={1}, interval={2} sec, log={3}" -f `
    $dnsRoot, $rootDn, $IntervalSeconds, $runDirectory)
Write-Host 'Press Enter in this guest console to stop and remove the lab OU/GPO.'

try {
    $rootOu = New-ADOrganizationalUnit -Name $rootName -Path $domain.DistinguishedName `
        -Description 'Temporary SentinelCap AD activity' -ProtectedFromAccidentalDeletion:$false `
        -PassThru -ErrorAction Stop
    if ($rootOu.DistinguishedName -ne $rootDn) {
        throw 'Created OU does not match the expected lab OU; refusing to continue.'
    }

    $intakeOu = New-ADOrganizationalUnit -Name 'Intake' -Path $rootDn `
        -ProtectedFromAccidentalDeletion:$false -PassThru -ErrorAction Stop
    $activeOu = New-ADOrganizationalUnit -Name 'Active' -Path $rootDn `
        -ProtectedFromAccidentalDeletion:$false -PassThru -ErrorAction Stop
    $groupsOu = New-ADOrganizationalUnit -Name 'Groups' -Path $rootDn `
        -ProtectedFromAccidentalDeletion:$false -PassThru -ErrorAction Stop
    $group = New-ADGroup -Name $groupSam -SamAccountName $groupSam -GroupScope Global `
        -GroupCategory Security -Path $groupsOu.DistinguishedName -PassThru -ErrorAction Stop
    $gpo = New-GPO -Name $gpoName -Comment 'Temporary SentinelCap lab policy' -ErrorAction Stop
    $null = New-GPLink -Guid $gpo.Id -Target $rootDn -LinkEnabled Yes -ErrorAction Stop
    $gpoLinked = $true
    $null = Set-GPPermission -Guid $gpo.Id -TargetName $groupSam -TargetType Group `
        -PermissionLevel GpoRead -Replace -ErrorAction Stop

    do {
        $cycle++
        try {
            $userCount = @(Get-ADUser -Filter * -SearchBase $rootDn -ErrorAction Stop).Count
            $groupCount = @(Get-ADGroup -Filter * -SearchBase $rootDn -ErrorAction Stop).Count
            $computerCount = @(Get-ADComputer -Filter * -ResultSetSize 20 -ErrorAction Stop).Count
            $dc = Get-ADDomainController -Discover -DomainName $dnsRoot -ErrorAction Stop
            $srvRecords = @(Resolve-DnsName -Name $srvName -Type SRV -DnsOnly -ErrorAction Stop)
            $policyCount = @(Get-ChildItem -LiteralPath $sysvol -Directory -ErrorAction Stop).Count

            # One disabled lab user every five cycles; retain at most three.
            if ($cycle % 5 -eq 0) {
                $userSam = "scu$runId$cycle"
                $user = New-ADUser -Name $userSam -SamAccountName $userSam `
                    -Path $intakeOu.DistinguishedName -Enabled:$false -PassThru -ErrorAction Stop
                $createdUserCount++
                Set-ADUser -Identity $user.ObjectGUID -Description "SentinelCap cycle $cycle" `
                    -Department 'Lab operations' -ErrorAction Stop
                Move-ADObject -Identity $user.ObjectGUID -TargetPath $activeOu.DistinguishedName -ErrorAction Stop
                $movedUser = Get-ADUser -Identity $user.ObjectGUID -ErrorAction Stop
                Add-ADGroupMember -Identity $group -Members $movedUser -ErrorAction Stop
                $null = Set-GPPermission -Guid $gpo.Id -TargetName $userSam -TargetType User `
                    -PermissionLevel GpoRead -Replace -ErrorAction Stop
                [void]$labUsers.Add($user.ObjectGUID)

                if ($labUsers.Count -gt 3) {
                    $oldUser = Get-ADUser -Identity $labUsers[0] -ErrorAction Stop
                    $null = Set-GPPermission -Guid $gpo.Id -TargetName $oldUser.SamAccountName `
                        -TargetType User -PermissionLevel None -Replace -ErrorAction Stop
                    Remove-ADGroupMember -Identity $group -Members $oldUser -Confirm:$false -ErrorAction Stop
                    Remove-ADUser -Identity $oldUser -Confirm:$false -ErrorAction Stop
                    $removedUserCount++
                    $labUsers.RemoveAt(0)
                }
            }

            # Review existing lab users and OU metadata between provisioning bursts.
            if ($cycle % 10 -eq 0) {
                Set-ADOrganizationalUnit -Identity $activeOu.ObjectGUID `
                    -Description "Active lab users, reviewed in cycle $cycle" -ErrorAction Stop
                $ouUpdateCount++
                $recentUserId = $labUsers[$labUsers.Count - 1]
                Set-ADUser -Identity $recentUserId -Description "Reviewed in cycle $cycle" `
                    -ErrorAction Stop
                $null = Get-ADGroupMember -Identity $group -ErrorAction Stop
            }

            # The GPO and its permissions belong only to this run's OU/group.
            if ($cycle % 15 -eq 0) {
                $null = Get-ADDefaultDomainPasswordPolicy -Identity $dnsRoot -ErrorAction Stop
                $null = Get-GPInheritance -Target $rootDn -ErrorAction Stop
                $null = Get-GPO -Guid $gpo.Id -ErrorAction Stop
                Set-ADGroup -Identity $group.ObjectGUID -Description "SentinelCap reviewed in cycle $cycle" `
                    -ErrorAction Stop
                $null = Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKCU\Software\Policies\SentinelCap\Lab' -ValueName 'ActivityCycle' `
                    -Type DWord -Value $cycle -ErrorAction Stop
                $gpoUpdateCount++
                $permission = if ($cycle % 30 -eq 0) { 'GpoRead' } else { 'GpoApply' }
                $null = Set-GPPermission -Guid $gpo.Id -TargetName $groupSam -TargetType Group `
                    -PermissionLevel $permission -Replace -ErrorAction Stop
                $null = & (Join-Path $env:WINDIR 'System32\dcdiag.exe') '/test:Advertising' '/q' 2>&1
                if ($LASTEXITCODE -ne 0) { throw "dcdiag Advertising failed (exit $LASTEXITCODE)." }
                $null = Get-WinEvent -LogName 'Directory Service' -MaxEvents 5 -ErrorAction SilentlyContinue
            }

            if ($cycle % 20 -eq 0) {
                $linkState = if ($cycle % 40 -eq 0) { 'Yes' } else { 'No' }
                $null = Set-GPLink -Guid $gpo.Id -Target $rootDn -LinkEnabled $linkState `
                    -ErrorAction Stop
                $gpoLinkUpdateCount++
            }

            # Exercise OU and group lifecycles without touching built-in objects.
            if ($cycle % 30 -eq 0) {
                $temporaryOu = New-ADOrganizationalUnit -Name "Review-$cycle" -Path $rootDn `
                    -ProtectedFromAccidentalDeletion:$false -PassThru -ErrorAction Stop
                $temporaryOuCount++
                Set-ADOrganizationalUnit -Identity $temporaryOu.ObjectGUID `
                    -Description "Reviewed in cycle $cycle" -ErrorAction Stop
                Remove-ADOrganizationalUnit -Identity $temporaryOu.ObjectGUID -Confirm:$false -ErrorAction Stop

                $temporaryGroupSam = "scv$runId$cycle"
                $temporaryGroup = New-ADGroup -Name $temporaryGroupSam -SamAccountName $temporaryGroupSam `
                    -GroupScope Global -GroupCategory Security -Path $groupsOu.DistinguishedName `
                    -PassThru -ErrorAction Stop
                $temporaryGroupCreatedCount++
                Set-ADGroup -Identity $temporaryGroup.ObjectGUID -Description "Review cycle $cycle" `
                    -ErrorAction Stop
                $reviewUserId = $labUsers[$labUsers.Count - 1]
                $reviewUser = Get-ADUser -Identity $reviewUserId -ErrorAction Stop
                Add-ADGroupMember -Identity $temporaryGroup -Members $reviewUser -ErrorAction Stop
                Remove-ADGroupMember -Identity $temporaryGroup -Members $reviewUser `
                    -Confirm:$false -ErrorAction Stop
                Remove-ADGroup -Identity $temporaryGroup.ObjectGUID -Confirm:$false -ErrorAction Stop
                $temporaryGroupRemovedCount++
            }
            if ($cycle % 5 -eq 0) {
                $null = & (Join-Path $env:WINDIR 'System32\nltest.exe') "/dsgetdc:$dnsRoot" 2>&1
                if ($LASTEXITCODE -ne 0) { throw "nltest DC discovery failed (exit $LASTEXITCODE)." }
            }

            if ($cycle % 5 -eq 0 -or $cycle -eq 1) {
                $record = [ordered]@{
                    timestamp_utc = (Get-Date).ToUniversalTime().ToString('o')
                    cycle = $cycle
                    domain = $dnsRoot
                    lab_ou = $rootDn
                    discovered_dc = $dc.HostName
                    lab_users_sampled = $userCount
                    computers_sampled = $computerCount
                    lab_groups_sampled = $groupCount
                    users_created = $createdUserCount
                    users_removed = $removedUserCount
                    gpo_updates = $gpoUpdateCount
                    temporary_ous_created = $temporaryOuCount
                    temporary_groups_created = $temporaryGroupCreatedCount
                    temporary_groups_removed = $temporaryGroupRemovedCount
                    ou_updates = $ouUpdateCount
                    gpo_link_updates = $gpoLinkUpdateCount
                    srv_records = $srvRecords.Count
                    sysvol_policy_directories = $policyCount
                }
                $path = Join-Path $runDirectory ('health-{0:D4}.json' -f $cycle)
                $record | ConvertTo-Json -Compress | Set-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop
                Write-Host ("{0:o} cycle={1} dc={2} lab_users={3} computers={4} lab_groups={5}" -f `
                    (Get-Date), $cycle, $dc.HostName, $userCount, $computerCount, $groupCount)
            }
            $consecutiveFailures = 0
        }
        catch {
            $failureCount++
            $consecutiveFailures++
            Write-Warning ("AD activity failed in cycle {0}: {1}" -f $cycle, $_.Exception.Message)
            if ($consecutiveFailures -ge 5) {
                throw 'Five consecutive AD activity cycles failed; discard this capture.'
            }
        }

        for ($second = 0; $second -lt $IntervalSeconds; $second++) {
            if (Test-GuestEnter) {
                $stopRequested = $true
                break
            }
            Start-Sleep -Seconds 1
        }
    } while (-not $stopRequested)
}
catch {
    $runFailure = $_.Exception.Message
}
finally {
    # GUIDs are captured from objects created above; cleanup never targets a
    # built-in OU, domain root, or an existing GPO selected by display name.
    if ($gpoLinked -and $null -ne $gpo) {
        try { $null = Remove-GPLink -Guid $gpo.Id -Target $rootDn -Confirm:$false -ErrorAction Stop }
        catch { [void]$cleanupErrors.Add("GPO link: $($_.Exception.Message)") }
    }
    if ($null -ne $gpo) {
        try { Remove-GPO -Guid $gpo.Id -Confirm:$false -ErrorAction Stop }
        catch { [void]$cleanupErrors.Add("GPO: $($_.Exception.Message)") }
    }
    if ($null -ne $rootOu -and $rootOu.DistinguishedName -eq $rootDn) {
        try {
            Remove-ADOrganizationalUnit -Identity $rootOu.ObjectGUID -Recursive `
                -Confirm:$false -ErrorAction Stop
        }
        catch { [void]$cleanupErrors.Add("Lab OU: $($_.Exception.Message)") }
    }
    $clock.Stop()
}

if ($runFailure -or $failureCount -gt 0 -or $cleanupErrors.Count -gt 0) {
    $failureSummary = 'AD run failed after {0:n1} minutes; cycle failures={1}; run error={2}; cleanup errors={3}' -f `
        $clock.Elapsed.TotalMinutes, $failureCount, $runFailure, ($cleanupErrors -join ' | ')
    $failureSummary | Set-Content -LiteralPath (Join-Path $runDirectory 'failed.txt') -Encoding UTF8
    throw "$failureSummary. Discard this capture as a normal DC baseline."
}

$summary = 'Completed {0} cycles over {1:n1} minutes; users created={2}, users removed={3}, GPO updates={4}, temporary OUs={5}, groups created={6}, groups removed={7}, OU updates={8}, GPO link updates={9}; lab OU and GPO removed.' -f `
    $cycle, $clock.Elapsed.TotalMinutes, $createdUserCount, $removedUserCount, $gpoUpdateCount, `
    $temporaryOuCount, $temporaryGroupCreatedCount, $temporaryGroupRemovedCount, `
    $ouUpdateCount, $gpoLinkUpdateCount
$summary | Set-Content -LiteralPath (Join-Path $runDirectory 'completed.txt') -Encoding UTF8
Write-Host ("AD operations completed after {0:n1} minutes. Log: {1}" -f `
    $clock.Elapsed.TotalMinutes, $runDirectory)
