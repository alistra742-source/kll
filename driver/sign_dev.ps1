# sign_dev.ps1 -- build-side: create the dev certificate, sign the driver, export
# the public .cer to ship.
#
# This is the free path's signing half. The certificate is self-signed, so it is
# trusted only on machines where its public half has been installed (which the
# app does on first run -- see nr/setup.py). It is NOT a substitute for a real
# EV-signed driver; it is what lets a test-signed driver load after the user has
# enabled test signing, which is the onboarding step the app performs.
#
# Run once on the build machine:
#   powershell -ExecutionPolicy Bypass -File sign_dev.ps1
#
# Produces: nightrelay.cer (ship this) and a signed nightrelay.sys.

param(
    [string]$Sys     = "nightrelay.sys",
    [string]$Subject = "CN=NightRelay",
    [string]$Cer     = "nightrelay.cer"
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

if (-not (Test-Path $Sys)) {
    Write-Error "driver not found: $Sys -- run build_driver.bat first"
    exit 1
}

# --- 1. certificate -------------------------------------------------------- #
# Reuse an existing one with the same subject so repeated builds keep a stable
# thumbprint; a new cert every build would force every client to re-trust it.
$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq $Subject -and $_.HasPrivateKey } |
    Select-Object -First 1

if (-not $cert) {
    Write-Host "[1/3] creating certificate $Subject"
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $Subject `
        -FriendlyName "NightRelay Dev" `
        -KeyUsage DigitalSignature `
        -KeyExportPolicy Exportable `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddYears(5)
} else {
    Write-Host "[1/3] reusing certificate $($cert.Thumbprint)"
}

# --- 2. export the public half --------------------------------------------- #
Export-Certificate -Cert $cert -FilePath $Cer -Force | Out-Null
Write-Host "[2/3] exported $Cer (ship this with the app)"

# --- 3. sign the driver ---------------------------------------------------- #
# signtool ships with the Windows SDK. Sign with the cert by name.
$signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
if (-not $signtool) {
    $kit = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    $signtool = Get-ChildItem -Path $kit -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match "x64" } |
        Select-Object -First 1
}
if (-not $signtool) {
    Write-Error "signtool.exe not found -- install the Windows SDK"
    exit 1
}

Write-Host "[3/3] signing $Sys"
& $signtool.FullName sign /v /fd SHA256 /a /n "NightRelay" $Sys
if ($LASTEXITCODE -ne 0) {
    Write-Error "signing failed"
    exit 1
}

Write-Host ""
Write-Host "done."
Write-Host "  ship:     $Sys  +  $Cer"
Write-Host "  app does: install $Cer into Root + TrustedPublisher, enable test signing, prompt restart"
