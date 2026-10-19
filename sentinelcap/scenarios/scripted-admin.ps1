#Requires -RunAsAdministrator
<#
  Scenario: scripted-admin
  Admin purpose : Day-to-day scripted administration — inventory the machine with
                  wmic, run a VBScript config helper with cscript, register a COM
                  DLL with regsvr32.
  Indicators exercised (4.1): lolbins_execution (wmic, cscript, regsvr32).
  Safety        : Read-only inventory + registering a standard system DLL, then
                  unregistering it. All tools run from System32 and are logged
                  with full command lines on this lab's Sysmon config.
#>
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\Public\sc-work\admin'
New-Item -ItemType Directory -Force $work | Out-Null

Write-Host '[admin] wmic inventory...'
wmic computersystem get Name,Domain,TotalPhysicalMemory /format:list 2>&1 | Out-Host
wmic process where "Name='explorer.exe'" get ProcessId,CommandLine /format:list 2>&1 | Out-Host
wmic logicaldisk get DeviceID,FreeSpace,Size /format:list 2>&1 | Out-Host

Write-Host '[admin] cscript running a config helper .vbs...'
$vbs = Join-Path $work 'inventory.vbs'
@'
Set fso = CreateObject("Scripting.FileSystemObject")
Set f = fso.CreateTextFile("C:\Users\Public\sc-work\admin\inventory.txt", True)
f.WriteLine "Inventory run: " & Now
f.Close
WScript.Echo "inventory written"
'@ | Set-Content $vbs -Encoding ASCII
cscript //nologo $vbs 2>&1 | Out-Host

Write-Host '[admin] regsvr32 register + unregister a standard DLL...'
# Register then immediately unregister a benign, always-present COM DLL.
regsvr32 /s "$env:windir\System32\vbscript.dll" 2>&1 | Out-Host
regsvr32 /s /u "$env:windir\System32\vbscript.dll" 2>&1 | Out-Host

Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
Write-Host '=== DONE ==='
