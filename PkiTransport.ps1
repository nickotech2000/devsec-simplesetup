# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Carries the Agantra Inovatif Enterprise PKI to other machines as a password-protected ".certpacked" file
    (SOURCE: -Pack) and, on a Windows 11 25H2 or newer destination, unpacks it and installs the trust (-Install).

.DESCRIPTION
    A .certpacked file is a zip or 7z archive with a password under another name.
    -Pack     makes it from the pki folder (and, if you say so, the leafcerts folder).
    -Install  DESTINATION, Windows 11 25H2 or newer only: scans the machine (Windows version, OpenSSL 4.0.1+),
              and only when the scan passes unpacks the package and installs the CAs in the Windows stores.
    Unpack only (any machine with PowerShell 7):  Unpack-PkiTransport.ps1.   Linux and macOS:  pki-transport.sh.

    Full help:  .\PkiTransport.ps1 -Help        Manual: PkiTransport-MANUAL.txt

.EXAMPLE
    .\PkiTransport.ps1 -Pack -GeneratePassword
        CA certificates only, zip + AES-256, written to .\transport\agantra-pki-<date>.certpacked
.EXAMPLE
    .\PkiTransport.ps1 -Pack -IncludeLeafCerts -Out D:\share\dev.certpacked -Kit
.EXAMPLE
    .\PkiTransport.ps1 -Install -Package .\dev.certpacked
#>
# No [CmdletBinding()]: it would reserve short aliases of common parameters. -Verbose is declared below.
param(
    # ---- what to do ----
    [switch]$Pack,
    [switch]$Install,
    [switch]$Check,
    [switch]$List,
    [switch]$RemoveTrust,

    # ---- the package ----
    [string]$Package,
    [string]$Out,
    [Alias('Password')][string]$PackagePassword,
    [switch]$GeneratePassword,
    [switch]$AllowWeakPassword,
    [ValidateSet('zip', '7z')][string]$ArchiveFormat = 'zip',
    [ValidateSet('Aes256', 'ZipCrypto')][string]$ZipEncryption = 'Aes256',
    [string]$SevenZipPath,
    [string]$Comment,
    [switch]$NoVerify,

    # ---- what goes in (source) ----
    [switch]$IncludeLeafCerts,
    [string[]]$LeafName,
    [switch]$IncludeCaKeys,
    [switch]$Kit,

    # ---- what comes out (destination) ----
    [string]$Destination,
    [ValidateSet('roots', 'intermediates', 'chains', 'ca', 'leafcerts', 'pki', 'all', 'fullchain')][string[]]$Extract,
    [switch]$InstallLeafPfx,
    [string]$PfxPassword = 'Abc12345!',
    [switch]$Force,
    [switch]$SkipOpenSslCheck,
    [switch]$InstallMissing,

    # ---- environment ----
    [string]$ConfigFile,
    [string]$PkiRoot,
    [string]$OpenSslPath,

    # ---- information, unblock / unlock ----
    [switch]$Unblock,
    [switch]$Help,
    [switch]$Verbose
)

$ErrorActionPreference = 'Stop'
$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Show-PkiTransportHelp {
    @'
============================================================
 PkiTransport.ps1 - carry the PKI to other machines (.certpacked)
 Version 4.9.1-phaseC
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : PkiTransport-MANUAL.txt   Design : PKI-Design-with-FIPS-and-PQC.txt (section 17)
 Needs  : PowerShell 7+. Source: the PKI made by pki_setup.ps1. Destination: see -Install.

WHAT IT DOES
  -Pack      SOURCE.      Makes a password-protected  .certpacked  file from the PKI.
  -Install   DESTINATION. Windows 11 25H2 or newer ONLY. Scans the machine; only if the scan passes it unpacks the
             package and installs the CA certificates in the Windows certificate stores.
  -Check     DESTINATION. The scan only (nothing is changed): READY or NOT READY.
  -List      Shows what is inside a package.
  -RemoveTrust  Removes the CA certificates of a package from the Windows stores (elevated).
  The three scripts of the transport:
      PkiTransport.ps1           pack (source) and install (Windows 11 25H2+)          this script
      Unpack-PkiTransport.ps1    destination, UNPACK ONLY (any machine with PowerShell 7)
      pki-transport.sh           Linux and macOS: unpack and install the trust in the system store

A .certpacked IS an archive: rename it to .zip or .7z and 7-Zip opens it with the password.
  zip + AES-256 (default)  made and read by this script itself: nothing to install on Windows.
  zip + ZipCrypto          legacy, weak: only for packages with NO private keys. Plain "unzip -P" reads it.
  7z  + AES-256            file names hidden too. Needs 7-Zip to make and to read.

PACK  (source)
  .\PkiTransport.ps1 -Pack -GeneratePassword                      CA certificates only
  .\PkiTransport.ps1 -Pack -IncludeLeafCerts                      + the leafcerts folders (with the leaf PRIVATE KEYS)
  .\PkiTransport.ps1 -Pack -IncludeLeafCerts -LeafName www.example.com,api*       only these leaf sets
  .\PkiTransport.ps1 -Pack -IncludeCaKeys                         + the WHOLE pki folder with the CA PRIVATE KEYS
                                                                  (the destination can then ISSUE leaf certificates)
  .\PkiTransport.ps1 -Pack -Out D:\share\dev.certpacked -ArchiveFormat 7z -Kit
  -Out <file>            Where to write. Default .\transport\agantra-pki-<yyyyMMdd-HHmmss>.certpacked. The extension
                         .certpacked is always used (a name ending in .zip or .7z is changed).
  -PackagePassword <t>   (alias -Password). Not given: environment variable PKI_TRANSPORT_PASSWORD, else you are asked.
                         At least 12 printable ASCII characters, 3 of 4 character classes. -AllowWeakPassword relaxes
                         length and classes, never the ASCII rule.
  -GeneratePassword      Makes a 20-character password and shows it ONCE at the end. Write it down.
  -ArchiveFormat zip|7z  Default zip.        -ZipEncryption Aes256|ZipCrypto   Default Aes256 (ZipCrypto is refused
                         when private keys are included).        -SevenZipPath <exe>   7-Zip, for 7z.
  -IncludeLeafCerts      Adds leafcerts\ (next to the scripts). Contains private keys.   -LeafName <wildcards>  only those.
  -IncludeCaKeys         Adds pki\ with the CA private keys. Only for a machine that must issue certificates.
  -Kit                   Also writes <name>-kit\ next to the package: the three transport scripts, the two bootstrap scripts
                         (Install-DevEnvironment.ps1 / .sh), the modules the destination needs and the manuals. The destination then
                         needs nothing else, and -InstallMissing can install 7-Zip and OpenSSL 4 from it.
  -Comment <text>        Stored in the package.       -NoVerify   Do not read the package back after writing it.
  -PkiRoot <path>  -ConfigFile <path>   As in pki_setup.ps1.
  The package always holds: ca\roots (Enterprise, Track and Quadrant roots), ca\intermediates (DV / OV / EV),
  ca\ca-bundle-roots.crt, ca\ca-bundle-all.crt, ca\chains (one fullchain file per intermediate), ca\publish,
  certpack.json, certpack.tsv, SHA256SUMS, README.txt. Every file has its SHA-256 listed.

INSTALL  (destination: Windows 11 25H2 or newer)
  .\PkiTransport.ps1 -Install -Package .\dev.certpacked
  1. SCAN. Windows 11 client, version 25H2 (build 26200) or newer. Windows 11 24H2 and older, Windows 10, 8.1, 7, Windows
     Server and everything else are NOT supported: the script says why and stops (exit code 2).
     OpenSSL 4.0.1 or newer (4.0.1 to 4.0.3 tested). Missing or older: it is INSTALLED when you agree (or give -InstallMissing) with
     Install-DevEnvironment.ps1; otherwise the script stops (exit code 4). -SkipOpenSslCheck continues anyway.
     Elevated PowerShell (administrator).
  2. Only then: the package is decrypted, every file is checked against its SHA-256, and what -Extract selects is
     written to -Destination.
  3. Every ROOT goes to Trusted Root Certification Authorities, every INTERMEDIATE to Intermediate Certification
     Authorities (the rules of pki_setup.ps1); the stores are read back; OpenSSL proves that every CA chains to the roots.
  -Package <file>        The .certpacked.       -PackagePassword / prompt as for -Pack.
  -Destination <folder>  Default .\certpacked-received\<package name>.
  -Extract <list>        roots | intermediates | chains | ca | leafcerts | pki | all (= fullchain). Default ca.
                         -IncludeLeafCerts at the destination adds leafcerts.
  -InstallLeafPfx        Also imports the leaf PFX files into LocalMachine\My (only the leaf). Needs leafcerts in the
                         package. -PfxPassword <text> is the PFX password (default Abc12345!).
  -Force                 Overwrite files that exist and differ.     -SevenZipPath <exe>   7-Zip, for a 7z package.
  -InstallMissing        Install what is missing instead of only reporting it: 7-Zip (7z packages, -ArchiveFormat 7z) and OpenSSL 4.0.1+
                         (FIPS + quantum-safe, proven) with Install-DevEnvironment.ps1, which must sit next to this script (the kit has
                         it). Without the switch you are asked when a person is at the console.
  -OpenSslPath <exe>     Use this openssl.        -SkipOpenSslCheck   Do not stop when OpenSSL 4.0.1+ is missing.
  -NoVerify              Do not run the OpenSSL chain check at the end.

OTHER
  -Check -Package <f>    The scan (and, with -Package, whether the password opens the file). Nothing is installed.
  -List -Package <f>     What is in the package (scope, CAs, leaves, files).
  -RemoveTrust -Package <f>   Remove the CA certificates of the package from the Windows stores (elevated).
  -Unblock               UNBLOCK (Internet mark) and UNLOCK (Read-only) the script folder and -Destination, children
                         and recursive, list the programs that hold files open, and stop. Done at every start too.
  -Verbose               Show detail.         -Help   This text.

EXIT CODES   0 ok   1 error   2 Windows not supported   3 not Windows (use pki-transport.sh)   4 OpenSSL 4.0.1+ missing

LIMITATIONS
  * A package with leaf certificates or CA keys contains PRIVATE KEYS. Send it over a channel you trust, send the
    password by another one, delete the package and the extracted files when you are done.
  * 7-Zip gets the password as an argument (-p<password>) and it is visible in a process list while it runs. The default
    zip engine of this script has no external process.
  * Not tested here on Windows: -Install, -RemoveTrust (the Windows stores, administrator check, Windows scan of a real
    machine). The rest is tested on Linux with OpenSSL 4.0.3 and the real 7-Zip.
'@
}

if ($Help) { Show-PkiTransportHelp; exit 0 }

Write-Host '============================================================'
Write-Host 'Author : Nicko Satria Utama'
Write-Host 'Company: Agantra Inovatif OÜ (NextMantra)'
Write-Host 'Email  : nicko@nextmantra.com'
Write-Host '============================================================'
Write-Host ''

# ------------------------------------------------------------------------------------------------------------
# STANDARD BOOTSTRAP of every main script: UNBLOCK + UNLOCK the whole script folder, children and recursive,
# BEFORE any other script of the folder is loaded (a blocked script cannot be loaded).
#   unblock = remove the Windows "downloaded from the Internet" mark    unlock = remove the Read-only attribute
# ------------------------------------------------------------------------------------------------------------
function Invoke-PkiBootstrapUnlock {
    param([Parameter(Mandatory)][string]$Root)
    $ro = [System.IO.FileAttributes]::ReadOnly
    $unlocked = 0
    foreach ($i in (@(Get-Item -LiteralPath $Root -Force) + @(Get-ChildItem -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue))) {
        try { if (($i.Attributes -band $ro) -ne 0) { $i.Attributes = $i.Attributes -bxor $ro; $unlocked++ } } catch { }
        if ($IsWindows -and -not $i.PSIsContainer) { Unblock-File -LiteralPath $i.FullName -ErrorAction SilentlyContinue }
    }
    return $unlocked
}
$script:BootstrapUnlocked = 0
try { $script:BootstrapUnlocked = [int](Invoke-PkiBootstrapUnlock -Root $script:ScriptRoot) }
catch { Write-Host "[WARN] Automatic unblock / unlock failed: $($_.Exception.Message)" -ForegroundColor Yellow }

$script:PackageOpened = $null
try {
    # ---------------- what is asked ----------------
    $modes = @($Pack, $Install, $Check, $List, $RemoveTrust, $Unblock | Where-Object { $_ })
    if ($modes.Count -eq 0) { throw 'Say what to do: -Pack, -Install, -Check, -List, -RemoveTrust or -Unblock. See .\PkiTransport.ps1 -Help.' }
    if ($modes.Count -gt 1 -and -not ($Check -and ($Install -or $List)) ) { throw 'Use only one of -Pack, -Install, -Check, -List, -RemoveTrust and -Unblock.' }
    if ($IncludeCaKeys -and -not $Pack) { throw '-IncludeCaKeys is a -Pack option.' }
    if ($Pack -and ($Install -or $RemoveTrust)) { throw '-Pack cannot be combined with -Install or -RemoveTrust.' }

    # module set: pack needs the whole library, everything else only the small destination kit
    $PkiModuleSet = if ($Pack) { 'Library' } else { 'Transport' }
    . (Join-Path $script:ScriptRoot 'scripts/PkiModules.ps1')

    # =========================================================================================== -Unblock
    if ($Unblock) {
        Initialize-PkiMinimalContext -PkiRoot (Join-Path $script:ScriptRoot 'pki')
        Write-PkiLog 'UNBLOCK + UNLOCK (children and recursive)'
        Write-PkiLog "Start-up bootstrap of this script: $($script:BootstrapUnlocked) read-only item(s) unlocked in $($script:ScriptRoot) (the Internet mark is removed on Windows)."
        $paths = @($script:ScriptRoot); if ($Destination) { $paths += $Destination }
        [void](Invoke-PkiUnblockUnlock -Path $paths)
        exit 0
    }

    # ---------------- the password (shared by every mode) ----------------
    $getPassword = {
        param([bool]$ForPack)
        $pw = $PackagePassword
        if ([string]::IsNullOrEmpty($pw)) { $pw = $env:PKI_TRANSPORT_PASSWORD }
        $generated = $false
        if ($ForPack -and [string]::IsNullOrEmpty($pw) -and $GeneratePassword) { $pw = New-PkiPackagePassword; $generated = $true }
        if ([string]::IsNullOrEmpty($pw)) { $pw = Read-PkiPackagePassword -Confirm:$ForPack }
        if ($ForPack) {
            $problems = Test-PkiPackagePassword $pw
            if ($AllowWeakPassword) { $problems = @($problems | Where-Object { $_ -like '*ASCII*' -or $_ -like '*empty*' }) }
            if ($problems.Count -gt 0) { throw ("The package password is not accepted: " + ($problems -join '; ') + '. Use -GeneratePassword for a strong one.') }
        }
        return [ordered]@{ Password = $pw; Generated = $generated }
    }

    # =========================================================================================== -Pack
    if ($Pack) {
        Initialize-PkiConfiguration -ScriptRoot $script:ScriptRoot -Bound $PSBoundParameters -VerboseOutput:([bool]$Verbose)
        $c = $script:Pki
        [void](Import-PkiExisting -SkipProviders)
        $leafRoot = Get-PkiLeafRoot
        if ($ZipEncryption -eq 'ZipCrypto' -and ($IncludeLeafCerts -or $IncludeCaKeys)) { throw '-ZipEncryption ZipCrypto is weak and is refused for a package with private keys (-IncludeLeafCerts, -IncludeCaKeys). Use Aes256.' }
        if ($ArchiveFormat -eq '7z' -and -not (Find-PkiSevenZip -Explicit $SevenZipPath)) {
            $doInstall = [bool]$InstallMissing
            if (-not $doInstall) { $doInstall = Confirm-PkiInstall '7-Zip is needed for a 7z package and was not found. Install it now?' }
            if ($doInstall) { [void](Install-PkiSevenZip) }
        }
        if ($ArchiveFormat -eq '7z' -and -not (Find-PkiSevenZip -Explicit $SevenZipPath)) { throw "-ArchiveFormat 7z needs 7-Zip and none was found. Install it (winget install 7zip.7zip) or give -SevenZipPath. The default zip format needs nothing." }
        if ($ArchiveFormat -eq 'zip' -and $ZipEncryption -eq 'ZipCrypto') { Write-PkiLog 'ZipCrypto is the old PKWARE encryption: weak against known-plaintext attacks. It is fine for CA certificates (public), not for anything secret.' 'WARN' }
        if ($IncludeLeafCerts) { Write-PkiLog "The package will contain the LEAF CERTIFICATES of $leafRoot WITH THEIR PRIVATE KEYS." 'WARN' }
        if ($IncludeCaKeys) { Write-PkiLog "The package will contain the WHOLE PKI of $($c.PkiRoot) WITH THE CA PRIVATE KEYS: whoever opens it can issue certificates your clients trust." 'WARN' }

        $pw = & $getPassword $true
        $name = if ($Out) { $Out } else { Join-Path (Join-Path $script:ScriptRoot 'transport') ("agantra-pki-{0}.certpacked" -f (Get-Date -Format 'yyyyMMdd-HHmmss')) }
        $ext = [System.IO.Path]::GetExtension($name)
        if ($ext -in '.zip', '.7z') { Write-PkiLog "The extension $ext is changed to .certpacked (the package is not meant to look like an archive)." 'WARN'; $name = [System.IO.Path]::ChangeExtension($name, '.certpacked') }
        elseif ($ext -ne '.certpacked') { $name = $name + '.certpacked' }
        $name = [System.IO.Path]::GetFullPath($name)

        Write-PkiLog "Packing $($c.PkiRoot) -> $name  ($ArchiveFormat$(if ($ArchiveFormat -eq 'zip') { ', ' + $ZipEncryption }))"
        $res = New-PkiCertPackage -OutFile $name -Password $pw.Password -ArchiveFormat $ArchiveFormat -ZipEncryption $ZipEncryption `
            -IncludeLeafCerts:([bool]$IncludeLeafCerts) -IncludeCaKeys:([bool]$IncludeCaKeys) -LeafName @($LeafName | Where-Object { $_ }) -LeafRoot $leafRoot `
            -Comment ([string]$Comment) -SevenZipPath $SevenZipPath -NoVerify:$NoVerify
        $sha = Get-PkiFileSha256 -Path $res.Path
        Write-Host ''
        Write-Host 'PACKAGE' -ForegroundColor Cyan
        Write-Host ("  File        : {0}" -f $res.Path)
        Write-Host ("  Size        : {0:N0} bytes, {1} files" -f $res.Bytes, $res.Files)
        Write-Host ("  Archive     : {0}, {1}" -f $res.Format, $res.Encryption)
        Write-Host ("  Contains    : CA certificates{0}{1}" -f $(if ($IncludeLeafCerts) { ' + leafcerts (private keys)' } else { '' }), $(if ($IncludeCaKeys) { ' + the whole PKI (CA private keys)' } else { '' }))
        Write-Host ("  CAs         : {0} ({1} roots, {2} intermediates)" -f @($res.Manifest.certificateAuthorities).Count, @($res.Manifest.certificateAuthorities | Where-Object { $_.kind -ne 'intermediate' }).Count, @($res.Manifest.certificateAuthorities | Where-Object { $_.kind -eq 'intermediate' }).Count)
        Write-Host ("  SHA-256     : {0}   (of the .certpacked file: compare it after the transfer)" -f $sha)
        if (-not $NoVerify) { Write-Host '  Read back   : every entry decrypted and authenticated' }
        if ($pw.Generated) {
            Write-Host ''
            Write-Host '  PASSWORD (shown once; send it by another channel than the file):' -ForegroundColor Yellow
            Write-Host "      $($pw.Password)" -ForegroundColor Yellow
        }
        if ($Kit) {
            $kitDir = Join-Path (Split-Path -Parent $res.Path) (([System.IO.Path]::GetFileNameWithoutExtension($res.Path)) + '-kit')
            $kf = Write-PkiTransportKit -Root $script:ScriptRoot -KitDirectory $kitDir
            Write-Host ''
            Write-Host ("  Kit         : {0}   ({1} files: the transport scripts, Install-DevEnvironment.ps1 / .sh, the modules, the manuals)" -f $kitDir, $kf.Count)
        }
        Write-Host ''
        Write-PkiLog 'Next: copy the .certpacked (and the kit) to the destination.  Windows 11 25H2+: .\PkiTransport.ps1 -Install -Package <file>   Linux / macOS: ./pki-transport.sh --package <file>' 'INFO'
        exit 0
    }

    # =========================================================================================== destination modes
    Initialize-PkiMinimalContext -PkiRoot (Join-Path $script:ScriptRoot 'pki') -Password $PfxPassword -VerboseOutput:([bool]$Verbose)
    $script:Pki.ScriptRoot = $script:ScriptRoot

    if (($Install -or $RemoveTrust) -and -not $IsWindows) {
        Write-PkiLog 'PkiTransport.ps1 -Install installs into the Windows stores. On Linux and macOS use ./pki-transport.sh.' 'ERROR'
        exit 3
    }

    # ---------------- the SCAN ----------------
    $scanOk = $true
    $showScan = [bool]($Install -or $Check -or $RemoveTrust)
    if ($showScan) { Write-Host 'SCAN OF THIS MACHINE' -ForegroundColor Cyan }
    $say = { param($n, $st, $t) if ($showScan) { Write-PkiScanLine $n $st $t } }
    $sayRaw = { param($t, $col) if ($showScan) { Write-Host $t -ForegroundColor $col } }
    $sup = Get-PkiWindowsSupport
    if ($sup.Supported) { & $say 'Operating system' 'PASS' "$($sup.Name), build $($sup.Build).$($sup.Ubr)  (required: $($sup.Required))" }
    else { & $say 'Operating system' 'FAIL' "$($sup.Name)$(if ($sup.Build) { ', build ' + $sup.Build })"; & $sayRaw "      $($sup.Reason)" 'Red'; & $sayRaw "      Required: $($sup.Required)." 'Red'; $scanOk = $false }
    & $say 'PowerShell' 'PASS' "$($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
    $ossl = Get-PkiDestinationOpenSsl -ExplicitPath $OpenSslPath
    if ($ossl.Status -ne 'Ok' -and -not $SkipOpenSslCheck -and $Install -and $sup.Supported) {
        $doInstall = [bool]$InstallMissing
        if (-not $doInstall) { $doInstall = Confirm-PkiInstall 'OpenSSL 4.0.1+ is missing. Install it now (Install-DevEnvironment.ps1 -Only OpenSSL)?' }
        if ($doInstall) { [void](Install-PkiOpenSsl); $ossl = Get-PkiDestinationOpenSsl -ExplicitPath $OpenSslPath }
    }
    switch ($ossl.Status) {
        'Ok' {
            $script:PkiDestOpenSslText = $ossl.Best.Text.Split([char]40)[0].Trim()
            & $say 'OpenSSL' 'PASS' "$script:PkiDestOpenSslText  [$($ossl.Best.Exe)]  (required: $($ossl.Required))"
            if ($ossl.Newer) { & $say 'OpenSSL version' 'INFO' "newer than the tested range ($($script:PkiTestedOpenSslMax)); accepted" }
        }
        default {
            $script:PkiDestOpenSslText = ''
            $found = @($ossl.Found | ForEach-Object { $_.Text.Split([char]40)[0].Trim() + '   at ' + $_.Exe })
            & $say 'OpenSSL' $(if ($SkipOpenSslCheck) { 'WARN' } else { 'FAIL' }) "$(if ($ossl.Status -eq 'TooOld') { 'too old' } else { 'not found' })  (required: $($ossl.Required))"
            if (-not $SkipOpenSslCheck) {
                $scanOk = $false
                foreach ($l in ((Get-PkiOpenSslAdvice -Found $found) -split "`r?`n")) { & $sayRaw ('      ' + $l) 'Yellow' }
            }
        }
    }
    if ($IsWindows) { & $say 'Administrator' $(if (Test-IsAdministrator) { 'PASS' } else { 'INFO' }) $(if (Test-IsAdministrator) { 'elevated' } else { 'not elevated (needed for -Install and -RemoveTrust)' }) }
    $sz = Find-PkiSevenZip -Explicit $SevenZipPath
    & $say '7-Zip' 'INFO' $(if ($sz) { $sz } else { 'not found (only needed for a 7z package; zip packages need nothing)' })
    if ($showScan) { Write-Host '' }

    if ($Check -and -not $Package) {
        if ($scanOk) { Write-Host 'READY: this machine can install the package.' -ForegroundColor Green; exit 0 }
        Write-Host 'NOT READY: see above.' -ForegroundColor Red
        if (-not $sup.Supported) { exit 2 } else { exit 4 }
    }
    if (-not $sup.Supported -and ($Install -or $RemoveTrust)) {
        Write-PkiLog "This machine is not supported for installing the trust: $($sup.Reason)" 'ERROR'
        exit 2
    }
    if (-not $scanOk -and $Install) { Write-PkiLog 'The scan did not pass. Nothing was unpacked or installed.' 'ERROR'; exit 4 }
    if ($Install -or $RemoveTrust) { Assert-Administrator }       # before anything is unpacked

    # ---------------- open the package ----------------
    if (-not $Package) { throw '-Package <file> is needed.' }
    $pw = & $getPassword $false
    if ((Get-PkiArchiveType -Path $Package) -eq '7z' -and -not (Find-PkiSevenZip -Explicit $SevenZipPath)) {
        $doInstall = [bool]$InstallMissing
        if (-not $doInstall) { $doInstall = Confirm-PkiInstall 'This is a 7z package and 7-Zip was not found. Install 7-Zip now?' }
        if ($doInstall) { [void](Install-PkiSevenZip) }
    }
    Write-PkiLog "Opening $Package ($(Get-PkiArchiveType -Path $Package))"
    $script:PackageOpened = Open-PkiCertPackage -Path $Package -Password $pw.Password -SevenZipPath $SevenZipPath
    $m = $script:PackageOpened.Manifest
    Write-PkiLog "Package opened: $($script:PackageOpened.Verified) file(s), every SHA-256 matches. Made $($m['createdUtc']) on $($m['source']['machine']), $($m['archive']['encryption'])." 'OK'
    $scope = $m['scope']
    Write-PkiLog "Scope: CA certificates$(if ($scope['leafcerts']) { ' + leaf certificates (private keys)' })$(if ($scope['caPrivateKeys']) { ' + the whole PKI (CA private keys)' })." 'INFO'
    if ($m['comment']) { Write-PkiLog "Comment: $($m['comment'])" 'INFO' }

    if ($Check) {
        if (-not $scanOk) {
            Write-Host 'NOT READY: the password opens the package, but this machine did not pass the scan (see above).' -ForegroundColor Red
            if (-not $sup.Supported) { exit 2 } else { exit 4 }
        }
        Write-Host 'READY: the scan passed and the password opens the package.' -ForegroundColor Green; exit 0
    }

    # =========================================================================================== -List
    if ($List) {
        Write-Host ''
        Write-Host ('{0,-14} {1,-12} {2,-4} {3,-11} {4}' -f 'KIND', 'KEY', 'Q', 'EXPIRES', 'COMMON NAME') -ForegroundColor Cyan
        foreach ($ca in @($m['certificateAuthorities'])) { Write-Host ('{0,-14} {1,-12} {2,-4} {3,-11} {4}' -f $ca['kind'], $ca['keyAlgorithm'], $(if ($ca['quadrant']) { "Q$($ca['quadrant'])" } else { '' }), $ca['notAfter'], $ca['commonName']) }
        $lv = @($m['leaves'])
        if ($lv.Count -gt 0) { Write-Host ''; Write-Host "LEAF CERTIFICATES: $($lv.Count)" -ForegroundColor Cyan; foreach ($l in $lv) { Write-Host ('  {0,-48} {1} Q{2} {3} {4}' -f $l['folder'], $l['level'], $l['quadrant'], $l['keyAlgorithm'], $l['notAfter']) } }
        Write-Host ''
        Write-PkiLog "$(@($m['files']).Count) file(s) in the package; roles: $((@($m['files']) | ForEach-Object { $_['role'] } | Group-Object | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', ')" 'OK'
        exit 0
    }

    # =========================================================================================== -RemoveTrust
    if ($RemoveTrust) { Remove-PkiPackageTrustWindows -Opened $script:PackageOpened; exit 0 }

    # =========================================================================================== -Install
    $sel = if ($Extract) { @($Extract) } else { @('ca') }
    if ($IncludeLeafCerts -and $sel -notcontains 'leafcerts' -and $sel -notcontains 'all' -and $sel -notcontains 'fullchain') { $sel += 'leafcerts' }
    if ($InstallLeafPfx -and $sel -notcontains 'leafcerts' -and $sel -notcontains 'all' -and $sel -notcontains 'fullchain') { $sel += 'leafcerts' }
    if (($sel -contains 'ca') -eq $false -and ($sel -contains 'roots') -eq $false -and ($sel -contains 'all') -eq $false -and ($sel -contains 'fullchain') -eq $false) { $sel += 'ca' }     # trust needs the CAs
    $dest = if ($Destination) { $Destination } else { Join-Path (Join-Path (Get-Location).Path 'certpacked-received') ([System.IO.Path]::GetFileNameWithoutExtension($Package)) }
    $dest = [System.IO.Path]::GetFullPath($dest)
    Write-PkiLog "Unpacking ($($sel -join ', ')) to $dest"
    $written = Export-PkiPackageSelection -Opened $script:PackageOpened -Destination $dest -Select $sel -LeafName @($LeafName | Where-Object { $_ }) -Force:$Force
    Write-PkiLog "$($written.Count) file(s) written." 'OK'

    Assert-Administrator
    Install-PkiPackageWindows -Opened $script:PackageOpened -Destination $dest -InstallLeafPfx:$InstallLeafPfx -PfxPassword $PfxPassword

    if (-not $NoVerify -and $ossl.Status -eq 'Ok') {
        if (-not (Test-PkiPackageChains -Opened $script:PackageOpened -Destination $dest -OpenSslExe $ossl.Best.Exe)) { throw 'The chain check with OpenSSL failed (see above).' }
    }
    Write-Host ''
    Write-PkiLog "Done. The CA certificates are installed (roots: Trusted Root Certification Authorities, intermediates: Intermediate Certification Authorities). Files: $dest" 'OK'
    exit 0
}
catch {
    $failure = $_
    if (Get-Command Write-PkiFatalError -ErrorAction SilentlyContinue) {
        try { Write-PkiFatalError -ErrorRecord $failure }
        catch { Write-Host "[FATAL] $($failure.Exception.Message)" -ForegroundColor Red }
    }
    else { Write-Host "[ERROR] $($failure.Exception.Message)" -ForegroundColor Red }
    exit 1
}
finally {
    if (Get-Command Remove-PkiOpenedPackage -ErrorAction SilentlyContinue) { Remove-PkiOpenedPackage -Opened $script:PackageOpened }
    if (Get-Command Clear-PkiSecretEnvironment -ErrorAction SilentlyContinue) { Clear-PkiSecretEnvironment }
}
