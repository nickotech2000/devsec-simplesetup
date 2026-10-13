# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    DevKit, Windows: unpacks the .certpacked of this kit into the kit folder and puts the whole PKI (every root and intermediate CA)
    into the LOCAL MACHINE certificate store (Trusted Root Certification Authorities / Intermediate Certification Authorities).
.DESCRIPTION
    Run it once, in PowerShell 7 started as Administrator, from the folder of the kit:    .\Install-PkiTrust.ps1
    It asks for the package password (or: -PackagePassword, or the environment variable PKI_TRANSPORT_PASSWORD).
    Afterwards GenerateLeafCertificate.ps1, GeneratePersonLeafCertificate.ps1 and GenerateOffice365LeafCertificate.ps1 work in this folder.
    It is a wrapper over  PkiTransport.ps1 -Install  (Windows 11 24H2 or newer (Windows Server 2025 / 2022), OpenSSL 4.0.1+): the scan, the checks of every SHA-256
    and the chain proof are those of PkiTransport.ps1.   Full help:  .\Install-PkiTrust.ps1 -Help
#>
param(
    [string]$Package,
    [Alias('Password')][string]$PackagePassword,
    [switch]$TrustOnly,
    [switch]$Reset,
    [switch]$InstallMissing,
    [switch]$SkipOpenSslCheck,
    [string]$OpenSslPath,
    [string]$SevenZipPath,
    [switch]$Help
)
$ErrorActionPreference = 'Stop'
$kit = $PSScriptRoot

if ($Help) {
@'
============================================================
 Install-PkiTrust.ps1 - DevKit installer for Windows
 Version 5.0.0
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : docs\DevKit-MANUAL.txt     Linux twin: Install-PkiTrust.sh

WHAT IT DOES
  1. Finds the .certpacked next to this script (or -Package) and asks for its password.
  2. Scans this machine (Windows 11 24H2+ / Server 2025 / 2022, OpenSSL 4.0.1+, administrator) - PkiTransport.ps1 -Install does it.
  3. Unpacks the CA certificates (folder ca\) AND the pki\ folder with the ISSUING CA keys into THIS folder, checks every SHA-256.
  4. Puts every root in Local Machine \ Trusted Root Certification Authorities and every intermediate in
     Local Machine \ Intermediate Certification Authorities, and proves the chains with OpenSSL.
  5. Gives every intermediate CA a NEW RANDOM serial counter, so certificates you issue never repeat a serial number of the
     master PKI or of another developer.

USAGE   (PowerShell 7, started as Administrator, in the folder of the kit)
  .\Install-PkiTrust.ps1
  .\Install-PkiTrust.ps1 -TrustOnly              only the CA certificates; no issuing keys are unpacked
  .\Install-PkiTrust.ps1 -InstallMissing         install OpenSSL 4 / 7-Zip when they are missing (asks otherwise)
  .\Install-PkiTrust.ps1 -Reset                  unpack pki\ again (your issued certificates in leafcerts\ are kept)

OPTIONS
  -Package <file>   -PackagePassword <text>   (or PKI_TRANSPORT_PASSWORD)   -TrustOnly   -Reset   -InstallMissing
  -SkipOpenSslCheck (not recommended)   -OpenSslPath <exe>   -SevenZipPath <exe>   -Help
EXIT  0 ok   other: see the message (not Windows 11 24H2+ / Server 2025 / 2022, not elevated, wrong password, OpenSSL missing)

WHERE IT RUNS  (5.0.0)
  Windows 11 24H2 or newer (Home, Pro, Pro for Workstations, Education, Pro Education, Enterprise), Windows Server 2025 and Windows Server 2022
  (Essentials, Standard, Datacenter; RTM or newer). On Windows Server 2022 only the CLASSIC track is generated or issued (no Quantum / ML-DSA);
  FIPS and non-FIPS, DV / OV / EV are available. REFUSED with an error (exit 5, nothing is done): Windows 10 and earlier, Windows 11 before 24H2,
  Windows Server before 2022, and the Chinese, Government, IoT / IoT Enterprise, SE and Embedded editions. Linux (pwsh): the distributions of the
  .sh scripts. Settings shared by all scripts (optional): pki_tools.cnf.
'@ | Write-Host
    exit 0
}

# Where may this script run? Windows 11 24H2+ / Server 2025 / Server 2022 (classic only), supported Linux. Error and exit 5 otherwise.
$__pf = Join-Path $PSScriptRoot 'scripts/00a_Platform.ps1'
if (-not (Test-Path -LiteralPath $__pf)) { [Console]::Error.WriteLine('[ERROR] scripts/00a_Platform.ps1 is missing: the operating system cannot be checked. Nothing was done.'); exit 5 }
. $__pf; Assert-PkiPlatform

if (-not $IsWindows) { Write-Host '[ERROR] Install-PkiTrust.ps1 is for Windows. On Ubuntu / Linux use:  sudo ./Install-PkiTrust.sh' -ForegroundColor Red; exit 3 }
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host '[ERROR] Start PowerShell 7 as Administrator (right-click > Run as administrator) and run this script again: the certificates go into the Local Machine store.' -ForegroundColor Red
    exit 5
}
if (-not $Package) {
    $found = @(Get-ChildItem -LiteralPath $kit -Filter '*.certpacked' -File)
    if ($found.Count -eq 0) { Write-Host "[ERROR] No .certpacked in $kit. Give it with -Package <file>." -ForegroundColor Red; exit 1 }
    $Package = $found[0].FullName
}
if (-not (Test-Path -LiteralPath $Package -PathType Leaf)) { Write-Host "[ERROR] Package not found: $Package" -ForegroundColor Red; exit 1 }
$tool = Join-Path $kit 'PkiTransport.ps1'
if (-not (Test-Path -LiteralPath $tool)) { Write-Host "[ERROR] PkiTransport.ps1 is missing in $kit (the kit is incomplete)." -ForegroundColor Red; exit 1 }

$marker = Join-Path (Join-Path $kit 'pki') '.devkit-instance.json'
$already = Test-Path -LiteralPath $marker
$extract = if ($TrustOnly) { 'ca' } elseif ($already -and -not $Reset) { 'ca' } else { 'ca,pki' }
if ($already -and -not $Reset -and -not $TrustOnly) { Write-Host '[INFO] pki\ is already unpacked here (your serial counters and issued certificates stay). The trust is installed again; use -Reset to unpack pki\ anew.' -ForegroundColor Cyan }

# PkiTransport.ps1 is called in this session with a splatted hashtable (a child "pwsh -File" would pass -Extract ca,pki as ONE string).
$splat = @{ Install = $true; Package = $Package; Destination = $kit; Extract = @($extract -split ',') }
if ($PackagePassword) { $splat.PackagePassword = $PackagePassword }
if ($InstallMissing) { $splat.InstallMissing = $true }
if ($SkipOpenSslCheck) { $splat.SkipOpenSslCheck = $true }
if ($OpenSslPath) { $splat.OpenSslPath = $OpenSslPath }
if ($SevenZipPath) { $splat.SevenZipPath = $SevenZipPath }
if ($Reset) { $splat.Force = $true }
$global:LASTEXITCODE = 0
try { & $tool @splat }
catch { Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red; $global:LASTEXITCODE = 1 }
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] PkiTransport.ps1 -Install stopped (exit $LASTEXITCODE). Nothing else was changed. Read the scan above (Windows 11 24H2+ / Server 2025 / 2022, OpenSSL 4.0.1+, password)." -ForegroundColor Red
    exit $LASTEXITCODE
}

# ---- a new random serial counter for every issuing CA of THIS copy
$pkiDir = Join-Path $kit 'pki'
if ((Test-Path -LiteralPath $pkiDir) -and ($Reset -or -not $already) -and -not $TrustOnly) {
    $n = 0
    foreach ($s in Get-ChildItem -LiteralPath $pkiDir -Recurse -File -Filter 'serial') {
        if (-not (Get-ChildItem -LiteralPath $s.DirectoryName -File -Filter '*.key')) { continue }
        $bytes = [byte[]]::new(16); [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        $bytes[0] = [byte](($bytes[0] % 0x70) + 0x10)                 # positive, first nibble 1-7
        [System.IO.File]::WriteAllText($s.FullName, ((($bytes | ForEach-Object { $_.ToString('X2') }) -join '') + "`n"), [System.Text.UTF8Encoding]::new($false))
        $n++
    }
    $inst = [ordered]@{ id = [guid]::NewGuid().ToString(); installedUtc = [DateTime]::UtcNow.ToString('o'); machine = [Environment]::MachineName; user = [Environment]::UserName; serialCountersRandomised = $n }
    [System.IO.File]::WriteAllText($marker, ($inst | ConvertTo-Json), [System.Text.UTF8Encoding]::new($false))
    Write-Host "[OK] $n issuing CA(s) got a new random serial counter (instance $($inst.id))." -ForegroundColor Green
}
Write-Host ''
if ($TrustOnly) { Write-Host '[OK] The PKI is trusted on this machine (CA certificates only).' -ForegroundColor Green }
else { Write-Host '[OK] The PKI is trusted on this machine. Make certificates now:  .\GenerateLeafCertificate.ps1 -OV -DnsName www.example.com   (more: START-HERE.txt)' -ForegroundColor Green }
exit 0
