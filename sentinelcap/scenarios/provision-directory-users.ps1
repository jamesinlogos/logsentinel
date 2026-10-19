#Requires -RunAsAdministrator
<#
  Scenario: provision-directory-users
  Admin purpose : Onboard a batch of new users — create accounts and groups, make
                  home folders, and set folder permissions (directory provisioning).
  Indicators exercised (4.1): none of the ransomware indicators directly; this is
                  a "busy legitimate admin" baseline (bulk account + ACL + folder
                  churn) so the model does not over-react to high-volume admin work.
  Note          : This provisions LOCAL users/groups only. It does not install
                  AD DS or any optional Windows Server feature.
  Safety        : All created users/groups/folders are removed at the end.
#>
$ErrorActionPreference = 'Continue'
$base = 'C:\Users\Public\sc-work\homes'
New-Item -ItemType Directory -Force $base | Out-Null

$group = 'ProjectTeam2025'
Write-Host "[prov] creating group $group ..."
if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) {
    New-LocalGroup -Name $group -Description 'Provisioned by IT onboarding' | Out-Null
}

$created = @()
1..12 | ForEach-Object {
    $u = 'svc_user_{0:D2}' -f $_
    $pw = ConvertTo-SecureString ('P@ss' + (Get-Random)) -AsPlainText -Force
    try {
        New-LocalUser -Name $u -Password $pw -FullName "Provisioned User $_" `
            -Description 'Onboarding batch 2025' -ErrorAction Stop | Out-Null
        Add-LocalGroupMember -Group $group -Member $u -ErrorAction SilentlyContinue
        # NOTE: do not use $home — it is a read-only PowerShell automatic variable.
        $homeDir = Join-Path $base $u
        New-Item -ItemType Directory -Force $homeDir | Out-Null
        icacls $homeDir /grant "${u}:(OI)(CI)F" 2>&1 | Out-Null
        $created += $u
        Write-Host "  provisioned $u"
    } catch { Write-Host "  skip $u ($($_.Exception.Message))" }
}
Write-Host "[prov] provisioned $($created.Count) users."

Write-Host '[prov] de-provisioning (cleanup)...'
foreach ($u in $created) { Remove-LocalUser -Name $u -ErrorAction SilentlyContinue }
Remove-LocalGroup -Name $group -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $base -ErrorAction SilentlyContinue
Write-Host '=== DONE ==='
