# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    DESTINATION, UNPACK ONLY: opens a .certpacked file made by PkiTransport.ps1 and writes what you select to a
    folder. It installs nothing and changes no certificate store.

.DESCRIPTION
    Works on Windows, Linux and macOS with PowerShell 7. No operating-system restriction (the Windows 11 25H2 rule is
    for installing the trust: PkiTransport.ps1 -Install). Zip packages need no other program; a 7z package needs 7-Zip.

    Full help:  .\Unpack-PkiTransport.ps1 -Help        Manual: PkiTransport-MANUAL.txt

.EXAMPLE
    .\Unpack-PkiTransport.ps1 -Package .\dev.certpacked
        Unpacks the CA certificates (roots, intermediates, chains, bundles) to .\certpacked-received\dev
.EXAMPLE
    .\Unpack-PkiTransport.ps1 -Package .\dev.certpacked -Extract leafcerts -LeafName www.example.com
#>
# No [CmdletBinding()]: -Verbose is declared below.
param(
    [string]$Package,
    [Alias('Password')][string]$PackagePassword,
    [string]$Destination,
    [ValidateSet('roots', 'intermediates', 'chains', 'ca', 'leafcerts', 'pki', 'all', 'fullchain')][string[]]$Extract,
    [string[]]$LeafName,
    [switch]$List,
    [switch]$Force,
    [switch]$InstallMissing,
    [string]$SevenZipPath,
    [switch]$Unblock,
    [switch]$Help,
    [switch]$Verbose
)

$ErrorActionPreference = 'Stop'
$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Show-PkiUnpackHelp {
    @'
============================================================
 Unpack-PkiTransport.ps1 - DESTINATION, UNPACK ONLY
 Version 4.9.3-phaseC
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : PkiTransport-MANUAL.txt   Needs: PowerShell 7+ (Windows, Linux or macOS)

WHAT IT DOES
  Opens a .certpacked (a password-protected zip or 7z made by PkiTransport.ps1), checks the SHA-256 of every file
  against the list inside, and writes what you select to a folder. NOTHING is installed and no certificate store is
  touched. There is no operating-system restriction: install the trust with PkiTransport.ps1 -Install (Windows 11
  25H2+) or pki-transport.sh (Linux, macOS).

USAGE
  .\Unpack-PkiTransport.ps1 -Package .\dev.certpacked                          CA certificates (default)
  .\Unpack-PkiTransport.ps1 -Package .\dev.certpacked -Extract roots           only the roots (+ ca-bundle-roots.crt)
  .\Unpack-PkiTransport.ps1 -Package .\dev.certpacked -Extract intermediates   only the DV / OV / EV CAs
  .\Unpack-PkiTransport.ps1 -Package .\dev.certpacked -Extract ca,leafcerts    CAs and the leaf certificates
  .\Unpack-PkiTransport.ps1 -Package .\dev.certpacked -Extract all             everything in the package (fullchain)
  .\Unpack-PkiTransport.ps1 -Package .\dev.certpacked -Extract leafcerts -LeafName www.example.com,api*
  .\Unpack-PkiTransport.ps1 -Package .\dev.certpacked -List                    what is inside, nothing written

PARAMETERS
  -Package <file>          The .certpacked.
  -PackagePassword <text>  (alias -Password). Not given: environment variable PKI_TRANSPORT_PASSWORD, else you are asked.
  -Destination <folder>    Default .\certpacked-received\<package name>.
  -Extract <list>          roots         ca\roots\*.crt (Enterprise, Track and Quadrant roots), ca-bundle-roots.crt
                           intermediates ca\intermediates\*.crt (DV / OV / EV CAs)
                           chains        ca\chains\*-fullchain.crt (each intermediate + its parents) and the bundles
                           ca            roots + intermediates + chains + bundles + CRLs + public-CA files (default)
                           leafcerts     the leafcerts folders (leaf certificates AND their private keys), if packed
                           pki           the whole PKI folder with the CA private keys, if packed (paths in its
                                         manifest are rewritten to the new place)
                           all           everything the package holds (same as fullchain)
                           certpack.json and README.txt are always written.
  -LeafName <wildcards>    With leafcerts: only these leaf sets (the top-level folder names).
  -List                    Show scope, CAs, leaves and files; write nothing.
  -Force                   Overwrite files that exist and differ (identical files are left alone).
  -SevenZipPath <exe>      7-Zip, for a 7z package (zip packages need nothing).
  -InstallMissing          A 7z package and no 7-Zip: install 7-Zip (Install-DevEnvironment.ps1 -Only 7Zip, or WinGet; Linux / macOS:
                           Install-DevEnvironment.sh --only 7zip) instead of stopping. Without it you are asked when a person is there.
  -Unblock                 UNBLOCK (Internet mark) and UNLOCK (Read-only) the script folder and -Destination, children
                           and recursive, list the programs that hold files open, and stop. Done at every start too.
  -Verbose                 Show detail.      -Help   This text.

WRONG PASSWORD, DAMAGED OR CHANGED FILE
  The script says so and writes nothing. The AES-256 zip authenticates every file: one changed byte is found.

EXIT CODES   0 ok   1 error (including a wrong password)

LIMITATIONS
  * A package with leafcerts or pki contains PRIVATE KEYS: delete the extracted files and the package when done.
  * Tested on Linux with OpenSSL 4.0.3 and the real 7-Zip; not tested here on Windows or macOS.
'@
}

if ($Help) { Show-PkiUnpackHelp; exit 0 }

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
    $PkiModuleSet = 'Transport'
    . (Join-Path $script:ScriptRoot 'scripts/PkiModules.ps1')
    Initialize-PkiMinimalContext -PkiRoot (Join-Path $script:ScriptRoot 'pki') -VerboseOutput:([bool]$Verbose)

    if ($Unblock) {
        Write-PkiLog 'UNBLOCK + UNLOCK (children and recursive)'
        Write-PkiLog "Start-up bootstrap of this script: $($script:BootstrapUnlocked) read-only item(s) unlocked in $($script:ScriptRoot) (the Internet mark is removed on Windows)."
        $paths = @($script:ScriptRoot); if ($Destination) { $paths += $Destination }
        [void](Invoke-PkiUnblockUnlock -Path $paths)
        exit 0
    }

    if (-not $Package) { throw '-Package <file> is needed. See .\Unpack-PkiTransport.ps1 -Help.' }
    $pw = $PackagePassword
    if ([string]::IsNullOrEmpty($pw)) { $pw = $env:PKI_TRANSPORT_PASSWORD }
    if ([string]::IsNullOrEmpty($pw)) { $pw = Read-PkiPackagePassword }

    if ((Get-PkiArchiveType -Path $Package) -eq '7z' -and -not (Find-PkiSevenZip -Explicit $SevenZipPath)) {
        $doInstall = [bool]$InstallMissing
        if (-not $doInstall) { $doInstall = Confirm-PkiInstall 'This is a 7z package and 7-Zip was not found. Install 7-Zip now?' }
        if ($doInstall) { [void](Install-PkiSevenZip) }
    }
    Write-PkiLog "Opening $Package ($(Get-PkiArchiveType -Path $Package))"
    $script:PackageOpened = Open-PkiCertPackage -Path $Package -Password $pw -SevenZipPath $SevenZipPath
    $m = $script:PackageOpened.Manifest
    Write-PkiLog "Package opened: $($script:PackageOpened.Verified) file(s), every SHA-256 matches. Made $($m['createdUtc']) on $($m['source']['machine']), $($m['archive']['encryption'])." 'OK'
    $scope = $m['scope']
    Write-PkiLog "Scope: CA certificates$(if ($scope['leafcerts']) { ' + leaf certificates (private keys)' })$(if ($scope['caPrivateKeys']) { ' + the whole PKI (CA private keys)' })." 'INFO'
    if ($m['comment']) { Write-PkiLog "Comment: $($m['comment'])" 'INFO' }

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

    $sel = if ($Extract) { @($Extract) } else { @('ca') }
    $dest = if ($Destination) { $Destination } else { Join-Path (Join-Path (Get-Location).Path 'certpacked-received') ([System.IO.Path]::GetFileNameWithoutExtension($Package)) }
    $dest = [System.IO.Path]::GetFullPath($dest)
    Write-PkiLog "Unpacking ($($sel -join ', ')) to $dest"
    $written = Export-PkiPackageSelection -Opened $script:PackageOpened -Destination $dest -Select $sel -LeafName @($LeafName | Where-Object { $_ }) -Force:$Force

    Write-Host ''
    Write-Host 'UNPACKED' -ForegroundColor Cyan
    Write-Host ("  Folder : {0}" -f $dest)
    foreach ($g in ($written | ForEach-Object { ($_ -split '/')[0] + $(if (($_ -split '/').Count -gt 2) { '/' + ($_ -split '/')[1] } else { '' }) } | Group-Object | Sort-Object Name)) { Write-Host ("  {0,-26} {1} file(s)" -f $g.Name, $g.Count) }
    Write-Host ''
    Write-PkiLog "$($written.Count) file(s) written. Nothing was installed." 'OK'
    if ($written -match '^(ca|ca/)' ) { Write-PkiLog 'To trust the PKI: Windows 11 25H2+  .\PkiTransport.ps1 -Install -Package <file>   Linux / macOS  ./linux/pki-transport.sh --package <file>' 'INFO' }
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
