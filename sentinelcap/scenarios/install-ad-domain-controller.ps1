#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
  Promote the bare Windows Server baseline to the first DC of a lab forest.
  Run during the AD capture, then run ad-domain-operations-continuous.ps1 after reboot.
  Promotion reboots Windows. The AD DS cmdlet prompts for and confirms the
  DSRM password; no password is written to the script or disk.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidatePattern('^(?=.{4,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$')]
    [string]$DomainName = 'ad.logsentinel.test',

    [ValidatePattern('^[A-Za-z][A-Za-z0-9-]{0,14}$')]
    [string]$DomainNetBIOSName = 'LOGSENTINEL'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$os = Get-CimInstance -ClassName Win32_OperatingSystem
if ($os.ProductType -eq 1) {
    throw 'Active Directory Domain Services must be installed on Windows Server.'
}

$computer = Get-CimInstance -ClassName Win32_ComputerSystem
if ($computer.DomainRole -ge 4) {
    Import-Module ActiveDirectory -ErrorAction Stop
    $installedDomain = Get-ADDomain -ErrorAction Stop
    if ($installedDomain.DNSRoot -ne $DomainName) {
        throw "This server is already a DC for $($installedDomain.DNSRoot), not $DomainName."
    }
    Write-Host "Already a domain controller for $DomainName. No installation needed."
    return
}
if ($computer.PartOfDomain) {
    throw 'This server is joined to an existing domain. Use a separate lab VM for a new forest.'
}

# A static address is preferred for a DC, but the lab baseline may use DHCP.
# Do not change networking here: doing so can break telemetry during capture.
$staticIpv4 = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
    Where-Object {
        $_.PrefixOrigin -eq 'Manual' -and
        $_.IPAddress -notmatch '^(127\.|169\.254\.)'
    })
if ($staticIpv4.Count -eq 0) {
    Write-Warning 'No static IPv4 address found. AD DS prerequisite checks may warn or fail, and a DHCP lease change can disrupt DC/DNS or telemetry.'
}

Import-Module ServerManager -ErrorAction Stop
$adFeature = Get-WindowsFeature -Name AD-Domain-Services -ErrorAction Stop
$gpmcFeature = Get-WindowsFeature -Name GPMC -ErrorAction Stop
$missingFeatures = @()
if (-not $adFeature.Installed) { $missingFeatures += 'AD-Domain-Services' }
if (-not $gpmcFeature.Installed) { $missingFeatures += 'GPMC' }
if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Install AD DS and Group Policy tools if needed, then promote a new forest')) {
    return
}

if ($missingFeatures.Count -gt 0) {
    $installation = Install-WindowsFeature -Name $missingFeatures -IncludeManagementTools -ErrorAction Stop
    if (-not $installation.Success) {
        throw 'Installing AD DS or Group Policy Management failed.'
    }
    if ($installation.RestartNeeded -eq 'Yes') {
        throw 'Windows requires a reboot after installing server features. Reboot and rerun this script in the same capture.'
    }
}

Import-Module ADDSDeployment -ErrorAction Stop
Write-Host "Promoting $env:COMPUTERNAME as the first DC of $DomainName; Windows will reboot."
Install-ADDSForest -DomainName $DomainName `
    -DomainNetBIOSName $DomainNetBIOSName `
    -InstallDNS `
    -Force `
    -ErrorAction Stop
