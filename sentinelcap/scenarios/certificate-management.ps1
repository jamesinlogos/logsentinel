#Requires -RunAsAdministrator
<#
  Scenario: certificate-management
  Admin purpose : Routine PKI admin — create a self-signed cert, export it, and
                  use certutil to inspect / verify / hash certificate files.
  Indicators exercised (4.1): lolbins_execution (certutil).
  Safety        : Only touches a scratch folder and the local machine cert store
                  (a throwaway self-signed cert). certutil runs from System32 and
                  is logged with full command lines on this lab's Sysmon config.
#>
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\Public\sc-work\certs'
New-Item -ItemType Directory -Force $work | Out-Null

Write-Host '[cert] creating a throwaway self-signed certificate...'
$cert = New-SelfSignedCertificate -Subject 'CN=SC Lab Test' `
    -CertStoreLocation 'Cert:\LocalMachine\My' -KeyExportPolicy Exportable
$cerPath = Join-Path $work 'sc-lab.cer'
Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null

Write-Host '[cert] certutil: dump the certificate...'
certutil -dump $cerPath 2>&1 | Select-Object -First 20 | Out-Host

Write-Host '[cert] certutil: hash files in the folder...'
certutil -hashfile $cerPath SHA256 2>&1 | Out-Host

Write-Host '[cert] certutil: verify store + list CAs...'
certutil -store My 2>&1 | Select-Object -First 15 | Out-Host

Write-Host '[cert] cleanup (remove test cert + files)...'
Remove-Item "Cert:\LocalMachine\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
Write-Host '=== DONE ==='
