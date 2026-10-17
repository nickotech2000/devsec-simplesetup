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

    Full help:  .\Unpack-PkiTransport.ps1 -Help        Manual: docs\PkiTransport-MANUAL.txt

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
====================================================================================================
 Unpack-PkiTransport.ps1  -  unpack a .certpacked on any computer
 Version 6.4.7
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
====================================================================================================
 On a terminal: SPACE = next page, ENTER = next line, Q = quit.
 Manual : docs\PkiTransport-MANUAL.txt (section 8)        Needs: PowerShell 7+

WHAT IT DOES
  Opens a .certpacked (a password-protected zip or 7z made by PkiTransport.ps1), checks the SHA-256
  of every file, and writes what you select to a folder.
  NOTHING is installed and no certificate store is touched. To install the trust use
  PkiTransport.ps1 -Install (Windows) or pki-transport.sh (Linux).
  A wrong password, a damaged or a changed file: it says so and writes nothing.

QUICK START
  .\Unpack-PkiTransport.ps1 -Package .\dev.certpacked                    CA certificates (default)
  .\Unpack-PkiTransport.ps1 -Package .\dev.certpacked -List
  What is inside; nothing is written

COMMON COMMANDS
  .\Unpack-PkiTransport.ps1 -Package .\dev.certpacked -Extract roots           Only the roots
  .\Unpack-PkiTransport.ps1 -Package .\dev.certpacked -Extract intermediates
  Only the DV / OV / EV CAs
  .\Unpack-PkiTransport.ps1 -Package .\dev.certpacked -Extract ca,leafcerts
  CAs and leaf certificates
  .\Unpack-PkiTransport.ps1 -Package .\dev.certpacked -Extract all
  Everything in the package
  .\Unpack-PkiTransport.ps1 -Package .\dev.certpacked -Extract leafcerts -LeafName
    www.example.com,api*

OPTIONS
  -Package <file>          The .certpacked.
  -PackagePassword <text>  (alias -Password). Not given: the variable PKI_TRANSPORT_PASSWORD, else a
                           prompt.
  -Destination <folder>    Default .\certpacked-received\<package name>.
  -Extract <list>          What to write:
                           roots          ca\roots\*.crt and ca-bundle-roots.crt
                           intermediates  ca\intermediates\*.crt (DV / OV / EV CAs)
                           chains         ca\chains\*-fullchain.crt and the bundles
                           ca
                           roots + intermediates + chains + bundles + CRLs + public-CA
                                          files (default)
                           leafcerts      the leafcerts folders (certificates AND private keys), if
                                          packed
                           pki
                           the whole PKI with the CA private keys, if packed. Paths in
                                          its manifest are rewritten to the new place.
                           all            everything the package holds (same as fullchain)
                           certpack.json and README.txt are always written.
  -LeafName <wildcards>    With leafcerts: only these leaf sets (top-level folder names).
  -List                    Show scope, CAs, leaves and files. Write nothing.
  -Force                   Overwrite files that exist and differ. Identical files are left alone.
  -SevenZipPath <exe>      7-Zip, for a 7z package (zip packages need nothing).
  -InstallMissing          A 7z package and no 7-Zip: install 7-Zip instead of stopping.
  -Unblock                 Unblock and unlock the script folder and -Destination, then stop.
  -Verbose                 Show detail.        -Help   This text.

LIMITS
  * A package with leafcerts or pki holds PRIVATE KEYS. Delete the extracted files and the package
    when you are done.
  * Tested on Linux with OpenSSL 4.0.3 and real 7-Zip. Not tested on Windows.

WHERE IT RUNS
  Windows 11 24H2 or newer, Windows Server 2025 and 2022, Linux with pwsh.
  Refused (exit 5): Windows 10, older Windows 11, macOS and special editions.

EXIT CODES
  0 done      1 error (also a wrong password)      5 this system is refused
'@
}

function Out-PagedHelp {
    # Shows help one screen at a time on a terminal (Space = next page, Enter = next line, q = quit).
    # When the output is redirected (a file, a pipe, a pipeline) it prints everything.
    param([Parameter(ValueFromPipeline = $true)][AllowEmptyString()][AllowNull()][string[]]$InputObject)
    begin { $all = [System.Collections.Generic.List[string]]::new() }
    process { foreach ($x in $InputObject) { foreach ($l in ([string]$x -split "\r?\n")) { [void]$all.Add($l) } } }
    end {
        $page = 0; $width = 120
        try { if (-not ([Console]::IsOutputRedirected -or [Console]::IsInputRedirected)) { $page = [Console]::WindowHeight - 2; $width = [Console]::WindowWidth } } catch { $page = 0 }
        if ($page -lt 8) { foreach ($l in $all) { Write-Host $l }; return }
        $rows = 0
        foreach ($l in $all) {
            Write-Host $l
            $rows += [Math]::Max(1, [Math]::Ceiling($l.Length / [Math]::Max(20, $width)))
            if ($rows -ge $page) {
                Write-Host ' -- more --  Space = next page   Enter = next line   q = quit ' -NoNewline -ForegroundColor Yellow
                $k = [Console]::ReadKey($true)
                Write-Host ("`r" + (' ' * 64) + "`r") -NoNewline
                if ($k.KeyChar -eq 'q' -or $k.KeyChar -eq 'Q' -or $k.Key -eq 'Escape') { return }
                $rows = if ($k.Key -eq 'Enter') { $page - 1 } else { 0 }
            }
        }
    }
}
function Invoke-PagedHelp {
    param([scriptblock]$Block)
    & $Block 6>&1 | ForEach-Object { if ($_ -is [System.Management.Automation.InformationRecord]) { [string]$_.MessageData } else { [string]$_ } } | Out-PagedHelp
}

if ($Help) { Invoke-PagedHelp { Show-PkiUnpackHelp }; exit 0 }

# Where may this script run? Windows 11 24H2+ / Server 2025 / Server 2022 (classic only), supported Linux. Error and exit 5 otherwise.
$__pf = Join-Path $PSScriptRoot 'scripts/00a_Platform.ps1'
if (-not (Test-Path -LiteralPath $__pf)) { [Console]::Error.WriteLine('[ERROR] scripts/00a_Platform.ps1 is missing: the operating system cannot be checked. Nothing was done.'); exit 5 }
. $__pf; Assert-PkiPlatform

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
    Write-PkiLog "Scope: CA certificates$(if ($scope['leafcerts']) { ' + leaf certificates (private keys)' })$(if ($scope['caPrivateKeys']) { if ($scope.Contains('issuingKeysOnly') -and $scope['issuingKeysOnly']) { ' + the PKI folder with the keys of the ISSUING (intermediate) CAs only (no root key)' } else { ' + the whole PKI (CA private keys)' } })." 'INFO'
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
