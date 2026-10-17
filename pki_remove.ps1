# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Lists the PKIs in .\pki\ (releases R1, R2 ... and the NoCR variant) and removes one release, or all of them:
    their Windows trust (Local Machine Root / Intermediate / Personal) and, when you say so, their files.
    Full help: .\pki_remove.ps1 -Help     Manual: docs\pki_setup-MANUAL.txt
.EXAMPLE
    .\pki_remove.ps1 -List
.EXAMPLE
    .\pki_remove.ps1 -Release 2 -NoCaRevocationInfo
.EXAMPLE
    .\pki_remove.ps1 -All -Yes
#>
param(
    # which company's PKI (default: agantra; names = the *_pki.cnf files next to the scripts; list: .\pki_setup.ps1 -ListPki)
    [Alias('Pki')][ArgumentCompleter({ param($c, $p, $w) $s = (Get-Command $c -ErrorAction SilentlyContinue).Source; $d = if ($s) { Split-Path -Parent $s } else { $PWD.Path }; Get-ChildItem -LiteralPath $d -Filter '*_pki.cnf' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name -replace '_pki\.cnf$', '' } | Where-Object { $_ -like "$w*" } })][string]$PkiProfile,
    [switch]$List,
    [ValidateRange(1, 99)][int]$Release,
    [switch]$NoCaRevocationInfo,
    [switch]$DeleteFiles,
    [switch]$All,
    [switch]$AllPki,
    [switch]$KeepFiles,
    [switch]$Yes,
    [switch]$Help,
    [switch]$Verbose,
    [string]$ConfigFile
)

$ErrorActionPreference = 'Stop'
$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Show-RemoveHelp {
    @'
============================================================
 pki_remove.ps1 - list and remove releases of the PKI
 Version 6.4.3
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : docs\pki_setup-MANUAL.txt   Design : docs\PKI-Design-with-FIPS-and-PQC.txt (section 21)

WHAT IT DOES
  Every PKI lives in its own folder inside .\pki\ :   pki\pki-<name>-01  pki\pki-<name>-02 ...
  and, made with  pki_setup.ps1 -NoCaRevocationInfo, pki\pki-<name>-nocr-01  pki\pki-<name>-nocr-02
  ...   (a PKI of an older version sits directly in pki\ and counts as release 1).
  This script lists them and removes the trust of one of them (or of all of them) from this Windows
  machine.

USAGE
  .\pki_remove.ps1 -List                                           every PKI (all companies) with `
        its releases   (-Pki <name>: only that company)
  .\pki_remove.ps1 [-Pki <name>] -Release <n> [-NoCaRevocationInfo] [-DeleteFiles] [-Yes]     ONE `
        release of one PKI (default: agantra)
  .\pki_remove.ps1 -Pki <name> -All [-KeepFiles] [-Yes]            EVERY release and variant of `
        ONE PKI; the other PKIs stay
  .\pki_remove.ps1 -AllPki [-KeepFiles] [-Yes]                     EVERY PKI of EVERY company (the `
        same as pki_setup.ps1 -RemoveAllTrust)

PARAMETERS
  -List                  Show every PKI found: release, variant, folder, number of CAs, expiry, and
                         (Windows) whether its roots are installed in the Local Machine store.
                         Changes nothing. Needs no administrator.
  -Release <n>           Remove the trust of release R<n> of the NORMAL family: its CA certificates
                         (matched by thumbprint and by name) and its leaf certificates from
                         LocalMachine Root, Intermediate (CA) and Personal (My). The files stay.
  -NoCaRevocationInfo    Together with -Release: the NoCR family (pki\pki-<name>-nocr-<NN>) instead
                         of the normal one. The two families are separate: removing R2 never touches
                         NoCR R2, and the other way round.
  -DeleteFiles           Together with -Release: also delete the folder of that release
                         (pki\pki-<name>-<NN> or pki\pki-<name>-nocr-<NN>), with its keys. Leaf
                         certificates in .\leafcerts are never touched (they do not chain to a new
                         PKI: delete them yourself).
  -Pki <name>            Which company's PKI (5.0.0; default agantra). See pki_setup.ps1 -ListPki.
  -AllPki                Remove EVERYTHING of EVERY company: the trust of every PKI, release and
                         variant in the Local Machine stores (Root, Intermediate, Personal) and the
                         folder pki with all of them. Cannot be combined with -Pki.
  -All                   With -Pki <name>: every release and variant of that ONE PKI (trust + its
                         folders). Without -Pki (old form) = -AllPki. Remove EVERYTHING: the trust
                         of EVERY release and EVERY variant (every certificate that carries 'Agantra
                         Inovatif' or 'NextMantra'), and delete the folder pki with all of them. The
                         same as pki_setup.ps1 -RemoveAllTrust. Cannot be combined with -Release.
  -KeepFiles             Together with -All: remove the trust only, keep the folder pki.
  -Yes                   Do not ask. Without it, -All and -DeleteFiles ask you to type  yes.
  -ConfigFile <path>     agantra_pki.cnf (default next to the script).     -Verbose   -Help   this text.

  Several releases and no -Release is not a problem for -List; for removing, the release number is
  always required (nothing is guessed).
  Removing the trust needs an ELEVATED PowerShell (administrator) on Windows. On Linux / macOS the
  trust is not touched (nothing is installed by these scripts there); -DeleteFiles and -All still
  delete the folders. Linux trust: pki-transport.sh --remove-trust.

EXAMPLES
  .\pki_remove.ps1 -List
  .\pki_remove.ps1 -Release 2                          trust of R2 (normal family) removed, files `
        stay
  .\pki_remove.ps1 -Release 2 -NoCaRevocationInfo      trust of NoCR R2 removed
  .\pki_remove.ps1 -Release 1 -DeleteFiles -Yes        R1: trust removed, folder pki\pki-<name>-01 `
        deleted
  .\pki_remove.ps1 -All                                everything (asks first)
  .\pki_remove.ps1 -All -KeepFiles -Yes                the trust of all releases out of the `
        stores, the files stay

THE SAME FROM pki_setup.ps1
  .\pki_setup.ps1 -RemoveTrust -Release 2 [-NoCaRevocationInfo]       = pki_remove.ps1 -Release 2
  .\pki_setup.ps1 -RemoveAllTrust                                     = pki_remove.ps1 -All
EXIT CODES   0 ok   1 error (the message says why)
============================================================

WHICH PKI  (-Pki, 5.0.0)
  -Pki <name>   the company whose PKI is used: the file <name>_pki.cnf next to the scripts. Default:
                agantra (or DefaultPki of pki_tools.cnf). The names: .\pki_setup.ps1 -ListPki
                (press Tab after -Pki to see them). Make a new company: .\New-PkiConfig.ps1. The PKI
                folders are .\pki\pki-default-NN (agantra) and .\pki\pki-<name>-NN (NoCR:
                pki-<name>-nocr-NN).

WHERE IT RUNS  (5.0.0)
  Windows 11 24H2 or newer (Home, Pro, Pro for Workstations, Education, Pro Education, Enterprise),
  Windows Server 2025 and Windows Server 2022 (Essentials, Standard, Datacenter; RTM or newer). On
  Windows Server 2022 only the CLASSIC track is generated or issued (no Quantum / ML-DSA);
  FIPS and non-FIPS, DV / OV / EV are available. REFUSED with an error (exit 5, nothing is done):
  Windows 10 and earlier, Windows 11 before 24H2,
  Windows Server before 2022, and the Chinese, Government, IoT / IoT Enterprise, SE and Embedded
  editions. Linux (pwsh): the distributions of the
  .sh scripts. Settings shared by all scripts (optional): pki_tools.cnf.
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

if ($Help) { Invoke-PagedHelp { Show-RemoveHelp }; exit 0 }

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

function Confirm-PkiRemoval {
    param([string]$Question)
    if ($Yes) { return $true }
    if (-not [Environment]::UserInteractive -or [Console]::IsInputRedirected) { throw 'This needs your confirmation but there is no terminal. Add -Yes.' }
    $a = Read-Host "$Question  Type yes to continue"
    return ($a.Trim().ToLowerInvariant() -eq 'yes')
}

try {
    $PkiModuleSet = 'Library'
    . (Join-Path $script:ScriptRoot 'scripts/PkiModules.ps1')

    if ($AllPki) { if ($PkiProfile) { throw '-AllPki removes the PKIs of ALL companies: do not combine it with -Pki. For one company: -Pki <name> -All.' }; $All = [System.Management.Automation.SwitchParameter]::new($true); $allCompanies = $true }
    elseif ($All -and -not $PkiProfile) { $allCompanies = $true } else { $allCompanies = $false }
    if ($All -and ($PSBoundParameters.ContainsKey('Release') -or $NoCaRevocationInfo -or $DeleteFiles)) { throw '-All removes every release and variant: do not combine it with -Release, -NoCaRevocationInfo or -DeleteFiles.' }
    if ($KeepFiles -and -not $All) { throw '-KeepFiles belongs to -All. For one release the files stay unless you add -DeleteFiles.' }
    if (-not $List -and -not $All -and -not $PSBoundParameters.ContainsKey('Release')) {
        Write-Host '[INFO] Say what to remove: [-Pki <name>] -Release <n> [-NoCaRevocationInfo], -Pki <name> -All, or -AllPki. Here is what exists:' -ForegroundColor Cyan
        $List = $true
    }

    # the folder pki is the container; PkiRoot is set per release below
    $bound = @{}
    foreach ($k in $PSBoundParameters.Keys) { $bound[$k] = $PSBoundParameters[$k] }
    $mode = if ($PSBoundParameters.ContainsKey('Release') -and -not $List) { 'Strict' } else { 'Generate' }
    Initialize-PkiConfiguration -ScriptRoot $script:ScriptRoot -Bound $bound -VerboseOutput:([bool]$Verbose) -RootMode $mode
    $c = $script:Pki
    # -List shows every PKI (or only -Pki <name>); removing one release works on the PKI named by -Pki (default: the default PKI)
    $pkis = @(Get-PkiInstalledPkis -ScriptRoot $script:ScriptRoot -Profile $(if ($PkiProfile -or -not $List) { $c.Profile } else { '' }))

    # ------------------------------------------------------------------ -List
    if ($List) {
        Write-Host ''
        Write-Host 'PKIs in .\pki\' -ForegroundColor Cyan
        if ($pkis.Count -eq 0) { Write-Host '  (none)'; exit 0 }
        Write-Host ('  {0,-10} {1,-9} {2,-9} {3,-22} {4,4}  {5,-12} {6,-10} {7}' -f 'PKI', 'RELEASE', 'VARIANT', 'FOLDER', 'CAs', 'EXPIRES', 'TRUSTED', 'ROOT COMMON NAME') -ForegroundColor Cyan
        $rootStore = $null
        if ($IsWindows) { try { $rootStore = @(Read-PkiStoreContents).Root } catch { } }
        foreach ($p in $pkis) {
            $nCa = 0; $exp = ''; $cn = ''; $trusted = 'n/a'
            $mp = Join-Path $p.Path 'pki-manifest.json'
            if (Test-Path -LiteralPath $mp) {
                try {
                    $m = Get-Content -LiteralPath $mp -Raw | ConvertFrom-Json -AsHashtable
                    $cas = @($m['certificateAuthorities']); $nCa = $cas.Count
                    $root = $cas | Where-Object { $_['id'] -eq 'root' } | Select-Object -First 1
                    if ($root) {
                        $cn = [string]$root['commonName']; $exp = ([string]$root['notAfter']).Substring(0, [Math]::Min(10, ([string]$root['notAfter']).Length))
                        if ($IsWindows -and $null -ne $rootStore) { $trusted = if (@($rootStore | Where-Object { $_.Sha1 -ieq [string]$root['sha1'] }).Count -gt 0) { 'yes' } else { 'no' } }
                    }
                }
                catch { }
            }
            Write-Host ('  {0,-10} {1,-9} {2,-9} {3,-22} {4,4}  {5,-12} {6,-10} {7}' -f $p.Profile, $p.Label, $p.Variant, $p.Name, $nCa, $exp, $trusted, $cn)
        }
        Write-Host ''
        Write-Host "  Remove one release:  .\pki_remove.ps1 [-Pki <name>] -Release <n> [-NoCaRevocationInfo] [-DeleteFiles]      One PKI:  .\pki_remove.ps1 -Pki <name> -All      Everything:  .\pki_remove.ps1 -AllPki"
        exit 0
    }

    # ------------------------------------------------------------------ -All / -AllPki
    if ($All) {
        if ($allCompanies) {
            if (-not (Confirm-PkiRemoval "This removes the trust of EVERY release and variant of EVERY PKI (all companies) from this machine$(if (-not $KeepFiles) { ' AND DELETES the folder pki with all their keys' }).")) { Write-PkiLog 'Cancelled. Nothing was changed.' 'WARN'; exit 0 }
            if ($IsWindows) {
                Assert-Administrator
                Invoke-PkiStep -Name 'Remove the trust of every PKI, release and variant' -Action { Remove-AllTrust }
            }
            else { Write-PkiLog 'Not Windows: no certificate store to clean here.' 'INFO' }
            if (-not $KeepFiles) { Invoke-PkiStep -Name 'Delete the folder pki with every PKI' -Action { Remove-PkiOutput -Path $c.PkiContainer -Whole } }
        }
        else {
            $mine = @(Get-PkiInstalledPkis -ScriptRoot $script:ScriptRoot -Profile $c.Profile)
            if (-not (Confirm-PkiRemoval "This removes the trust of EVERY release and variant of the PKI '$($c.Profile)' from this machine$(if (-not $KeepFiles) { " AND DELETES its $($mine.Count) folder(s) with the keys" }). Other PKIs stay.")) { Write-PkiLog 'Cancelled. Nothing was changed.' 'WARN'; exit 0 }
            if ($IsWindows) {
                Assert-Administrator
                Invoke-PkiStep -Name "Remove the trust of the PKI '$($c.Profile)'" -Action { Remove-PkiProfileTrust -Profile $c.Profile }
            }
            else { Write-PkiLog 'Not Windows: no certificate store to clean here.' 'INFO' }
            if (-not $KeepFiles) { foreach ($m1 in $mine) { $m1p = $m1.Path; Invoke-PkiStep -Name "Delete $m1p" -Action { Remove-PkiOutput -Path $m1p } } }
        }
        Write-PkiLog 'Done.' 'OK'
        exit 0
    }

    # ------------------------------------------------------------------ -Release n
    $nocr = [bool]$NoCaRevocationInfo
    $label = "$($c.Profile) $(if ($nocr) { 'NoCR ' })R$Release"
    $hit = $pkis | Where-Object { $_.Release -eq $Release -and $_.NoCr -eq $nocr -and $_.Profile -eq $c.Profile } | Select-Object -First 1
    if ($null -eq $hit) {
        Write-PkiLog "No PKI folder for $label exists here (deleted earlier?)." 'WARN'
        if ($IsWindows) { Write-PkiLog 'The trust is still removed by NAME, in case the certificates are installed.' 'INFO' }
    }
    if ($DeleteFiles -and $null -ne $hit) {
        if (-not (Confirm-PkiRemoval "This removes the trust of $label AND DELETES $($hit.Path) with its keys.")) { Write-PkiLog 'Cancelled. Nothing was changed.' 'WARN'; exit 0 }
    }
    if ($IsWindows) {
        Assert-Administrator
        if ($null -ne $hit) {
            # work on exactly that PKI: its manifest gives the thumbprints and the release / variant
            $c.PkiRoot = $hit.Path; $c.Release = $hit.Release; $c.NoCaRevocationInfo = $hit.NoCr
            $m = Import-PkiExisting -SkipProviders
            Invoke-PkiStep -Name "Remove the trust of $label" -Action { Remove-CurrentTrust }
        }
        else {
            Invoke-PkiStep -Name "Remove the trust of $label by name" -Action {
                $n = Remove-PkiTrustByRelease -Release $Release -NoCr $nocr
                Write-PkiLog "Removed $n CA certificate(s) of $label." 'OK'
            }
        }
    }
    else { Write-PkiLog 'Not Windows: no certificate store to clean here.' 'INFO' }
    if ($DeleteFiles -and $null -ne $hit) {
        Invoke-PkiStep -Name "Delete $($hit.Path)" -Action { Remove-PkiOutput -Path $hit.Path }
    }
    Write-PkiLog 'Done.' 'OK'
    exit 0
}
catch {
    $failure = $_
    if (-not $Verbose -and $failure.Exception.GetType().Name -eq 'RuntimeException') { Write-Host "[ERROR] $($failure.Exception.Message)" -ForegroundColor Red; exit 1 }
    if (Get-Command Write-PkiFatalError -ErrorAction SilentlyContinue) {
        try { Write-PkiFatalError -ErrorRecord $failure } catch { Write-Host "[FATAL] $($failure.Exception.Message)" -ForegroundColor Red }
    }
    else { Write-Host "[ERROR] $($failure.Exception.Message)" -ForegroundColor Red }
    exit 1
}
finally {
    if (Get-Command Clear-PkiSecretEnvironment -ErrorAction SilentlyContinue) { Clear-PkiSecretEnvironment }
}
