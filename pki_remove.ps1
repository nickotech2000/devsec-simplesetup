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
    [switch]$List,
    [ValidateRange(1, 99)][int]$Release,
    [switch]$NoCaRevocationInfo,
    [switch]$DeleteFiles,
    [switch]$All,
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
 Version 4.9.5-phaseC
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : docs\pki_setup-MANUAL.txt   Design : docs\PKI-Design-with-FIPS-and-PQC.txt (section 21)

WHAT IT DOES
  Every PKI lives in its own folder inside .\pki\ :   pki\R1  pki\R2 ...   and, made with  pki_setup.ps1 -NoCaRevocationInfo,
  pki\NoCR-R1  pki\NoCR-R2 ...   (a PKI of an older version sits directly in pki\ and counts as release 1).
  This script lists them and removes the trust of one of them (or of all of them) from this Windows machine.

USAGE
  .\pki_remove.ps1 -List
  .\pki_remove.ps1 -Release <n> [-NoCaRevocationInfo] [-DeleteFiles] [-Yes]
  .\pki_remove.ps1 -All [-KeepFiles] [-Yes]

PARAMETERS
  -List                  Show every PKI found: release, variant, folder, number of CAs, expiry, and (Windows) whether its roots are
                         installed in the Local Machine store. Changes nothing. Needs no administrator.
  -Release <n>           Remove the trust of release R<n> of the NORMAL family: its CA certificates (matched by thumbprint and by
                         name) and its leaf certificates from LocalMachine Root, Intermediate (CA) and Personal (My). The files stay.
  -NoCaRevocationInfo    Together with -Release: the NoCR family (pki\NoCR-R<n>) instead of the normal one. The two families are
                         separate: removing R2 never touches NoCR R2, and the other way round.
  -DeleteFiles           Together with -Release: also delete the folder of that release (pki\R<n> or pki\NoCR-R<n>), with its keys.
                         Leaf certificates in .\leafcerts are never touched (they do not chain to a new PKI: delete them yourself).
  -All                   Remove EVERYTHING: the trust of EVERY release and EVERY variant (every certificate that carries
                         'Agantra Inovatif' or 'NextMantra'), and delete the folder pki with all of them. The same as
                         pki_setup.ps1 -RemoveAllTrust. Cannot be combined with -Release.
  -KeepFiles             Together with -All: remove the trust only, keep the folder pki.
  -Yes                   Do not ask. Without it, -All and -DeleteFiles ask you to type  yes.
  -ConfigFile <path>     agantra_pki.cnf (default next to the script).     -Verbose   -Help   this text.

  Several releases and no -Release is not a problem for -List; for removing, the release number is always required (nothing is guessed).
  Removing the trust needs an ELEVATED PowerShell (administrator) on Windows. On Linux / macOS the trust is not touched (nothing is
  installed by these scripts there); -DeleteFiles and -All still delete the folders. Linux trust: pki-transport.sh --remove-trust.

EXAMPLES
  .\pki_remove.ps1 -List
  .\pki_remove.ps1 -Release 2                          trust of R2 (normal family) removed, files stay
  .\pki_remove.ps1 -Release 2 -NoCaRevocationInfo      trust of NoCR R2 removed
  .\pki_remove.ps1 -Release 1 -DeleteFiles -Yes        R1: trust removed, folder pki\R1 deleted
  .\pki_remove.ps1 -All                                everything (asks first)
  .\pki_remove.ps1 -All -KeepFiles -Yes                the trust of all releases out of the stores, the files stay

THE SAME FROM pki_setup.ps1
  .\pki_setup.ps1 -RemoveTrust -Release 2 [-NoCaRevocationInfo]       = pki_remove.ps1 -Release 2
  .\pki_setup.ps1 -RemoveAllTrust                                     = pki_remove.ps1 -All
EXIT CODES   0 ok   1 error (the message says why)
============================================================
'@
}

if ($Help) { Show-RemoveHelp; exit 0 }

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

    if ($All -and ($PSBoundParameters.ContainsKey('Release') -or $NoCaRevocationInfo -or $DeleteFiles)) { throw '-All removes every release and variant: do not combine it with -Release, -NoCaRevocationInfo or -DeleteFiles.' }
    if ($KeepFiles -and -not $All) { throw '-KeepFiles belongs to -All. For one release the files stay unless you add -DeleteFiles.' }
    if (-not $List -and -not $All -and -not $PSBoundParameters.ContainsKey('Release')) {
        Write-Host '[INFO] Say what to remove: -Release <n> [-NoCaRevocationInfo], or -All. Here is what exists:' -ForegroundColor Cyan
        $List = $true
    }

    # the folder pki is the container; PkiRoot is set per release below
    $bound = @{}
    foreach ($k in $PSBoundParameters.Keys) { $bound[$k] = $PSBoundParameters[$k] }
    $mode = if ($PSBoundParameters.ContainsKey('Release') -and -not $List) { 'Strict' } else { 'Generate' }
    Initialize-PkiConfiguration -ScriptRoot $script:ScriptRoot -Bound $bound -VerboseOutput:([bool]$Verbose) -RootMode $mode
    $c = $script:Pki
    $pkis = @(Get-PkiInstalledPkis -ScriptRoot $script:ScriptRoot)

    # ------------------------------------------------------------------ -List
    if ($List) {
        Write-Host ''
        Write-Host 'PKIs in .\pki\' -ForegroundColor Cyan
        if ($pkis.Count -eq 0) { Write-Host '  (none)'; exit 0 }
        Write-Host ('  {0,-9} {1,-9} {2,-22} {3,4}  {4,-12} {5,-10} {6}' -f 'RELEASE', 'VARIANT', 'FOLDER', 'CAs', 'EXPIRES', 'TRUSTED', 'ROOT COMMON NAME') -ForegroundColor Cyan
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
            Write-Host ('  {0,-9} {1,-9} {2,-22} {3,4}  {4,-12} {5,-10} {6}' -f $p.Label, $p.Variant, $p.Name, $nCa, $exp, $trusted, $cn)
        }
        Write-Host ''
        Write-Host "  Remove one:  .\pki_remove.ps1 -Release <n> [-NoCaRevocationInfo] [-DeleteFiles]      Remove all:  .\pki_remove.ps1 -All"
        exit 0
    }

    # ------------------------------------------------------------------ -All
    if ($All) {
        if (-not (Confirm-PkiRemoval "This removes the trust of EVERY release and variant of the PKI from this machine$(if (-not $KeepFiles) { ' AND DELETES the folder pki with all their keys' }).")) { Write-PkiLog 'Cancelled. Nothing was changed.' 'WARN'; exit 0 }
        if ($IsWindows) {
            Assert-Administrator
            Invoke-PkiStep -Name 'Remove the trust of every release and variant' -Action { Remove-AllTrust }
        }
        else { Write-PkiLog 'Not Windows: no certificate store to clean here.' 'INFO' }
        if (-not $KeepFiles) { Invoke-PkiStep -Name 'Delete the folder pki with every release and variant' -Action { Remove-PkiOutput -Path $c.PkiContainer -Whole } }
        Write-PkiLog 'Done.' 'OK'
        exit 0
    }

    # ------------------------------------------------------------------ -Release n
    $nocr = [bool]$NoCaRevocationInfo
    $label = "$(if ($nocr) { 'NoCR ' })R$Release"
    $hit = $pkis | Where-Object { $_.Release -eq $Release -and $_.NoCr -eq $nocr } | Select-Object -First 1
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
