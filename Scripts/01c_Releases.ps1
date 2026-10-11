# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 01c_Releases.ps1  -  RELEASES (R2, R3 ...) and the NoCR variant of the PKI
#
# EVERY PKI LIVES INSIDE THE FOLDER  pki  next to the scripts. Several PKIs can exist side by side, one subfolder each:
#
#     pki\R1           release 1, CA certificates WITH revocation information
#     pki\R2           release 2
#     pki\NoCR-R1      release 1 of the NoCR variant: CA certificates WITHOUT revocation information (-NoCaRevocationInfo)
#     pki\NoCR-R2      release 2 of that variant
#
# (A PKI made by an older version sits directly in pki\ (pki\root, pki\classical ...): it counts as release 1 of the normal
#  family, or as the release / variant written in its pki-manifest.json, and keeps working. -PkiRoot pki\R2 points at one PKI.)
#
# Release 1 has no suffix in any name. From release 2 every CA common name ends in " R2", " R3" ...
# The NoCR variant adds " (NoCR)":   Agantra Inovatif Enterprise Root CA G1 (NoCR) R2
# (leaf certificates are not renamed).
#
# The two variants are two separate families of roots. Inside a family every release has its own Enterprise
# Root, Track Roots, Quadrant Roots and intermediates.
#
# WHICH PKI DOES A SCRIPT USE?  (generators, SignCsr, SignExternalCa, PkiRevocation, PkiTransport ...)
#   -PkiRoot <folder>   that folder, nothing else.
#   -Release N          release N of the family; when it does not exist (deleted) the LATEST release is used and a
#                       warning says so: a release that is gone is never an error for signing.
#   (nothing)           the latest release.
#   -NoCaRevocationInfo the NoCR family. Without it the normal family; when only a NoCR family exists, that one.
#
# Provides : Get-PkiContainer, Get-PkiFolderName, Get-PkiFolderInfo, Get-PkiInstalledPkis, Resolve-PkiRootChoice
# Requires : 00_Common (Write-PkiLog)
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PkiContainer {
    # <script folder>\pki : the folder that holds every PKI
    param([Parameter(Mandatory)][string]$ScriptRoot)
    return (Join-Path $ScriptRoot 'pki')
}

function Get-PkiFolderName {
    # R1 | R2 | NoCR-R1 | NoCR-R2   (the subfolder of pki\)
    param([bool]$NoCr, [int]$Release = 1)
    if ($Release -lt 1) { $Release = 1 }
    return ($(if ($NoCr) { 'NoCR-' } else { '' }) + "R$Release")
}

function Get-PkiFolderInfo {
    # Release and variant of ONE PKI folder: from its pki-manifest.json, else from the folder name (NoCR-R2; a flat old pki\ = R1). $null when it holds no PKI.
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $null }
    $name = Split-Path -Leaf ($Path.TrimEnd('\', '/'))
    $nocr = $false; $rel = 1
    if ($name -match '^(?i)(?<nocr>NoCR-)?R(?<rel>\d+)$') { $nocr = ($Matches['nocr'] -ne ''); $rel = [int]$Matches['rel'] }
    $mp = Join-Path $Path 'pki-manifest.json'
    $has = (Test-Path -LiteralPath $mp) -or (Test-Path -LiteralPath (Join-Path (Join-Path $Path 'root') 'root.crt'))
    if (-not $has) { return $null }
    if (Test-Path -LiteralPath $mp) {
        try {
            $m = Get-Content -LiteralPath $mp -Raw | ConvertFrom-Json -AsHashtable
            if ($m.ContainsKey('release') -and [int]$m['release'] -gt 0) { $rel = [int]$m['release'] }
            if ($m.ContainsKey('noCaRevocationInfo')) { $nocr = [bool]$m['noCaRevocationInfo'] }
        }
        catch { }
    }
    return [pscustomobject]@{
        Path = $Path; Name = $name; Release = $rel; NoCr = $nocr
        Variant = $(if ($nocr) { 'NoCR' } else { 'normal' })
        Label = $(if ($nocr) { "NoCR R$rel" } else { "R$rel" })
    }
}

function Get-PkiInstalledPkis {
    <#
    .SYNOPSIS
        The PKIs found in <script folder>\pki: the subfolders R1, R2, NoCR-R1 ... that hold a PKI, and an old flat PKI in pki\ itself.
    .OUTPUTS
        objects with Path, Name, Release, NoCr, Variant ('normal' | 'NoCR'), Label ('R1', 'NoCR R2' ...), sorted by variant then release.
    #>
    param([Parameter(Mandatory)][string]$ScriptRoot)
    $list = [System.Collections.Generic.List[object]]::new()
    $container = Get-PkiContainer -ScriptRoot $ScriptRoot
    if (-not (Test-Path -LiteralPath $container -PathType Container)) { return @() }
    $flat = Get-PkiFolderInfo -Path $container
    if ($null -ne $flat) { $flat.Name = 'pki (old layout)'; [void]$list.Add($flat) }
    foreach ($d in Get-ChildItem -LiteralPath $container -Directory -Force -ErrorAction SilentlyContinue) {
        if ($d.Name -notmatch '^(?i)(NoCR-)?R\d+$') { continue }
        $i = Get-PkiFolderInfo -Path $d.FullName
        if ($null -ne $i) { [void]$list.Add($i) }
    }
    return @($list | Sort-Object @{ Expression = { $_.NoCr } }, Release)
}

function Resolve-PkiRootChoice {
    <#
    .SYNOPSIS
        Decides which PKI folder a script works on.
    .PARAMETER Mode
        Use       a script that signs / issues / packs: the requested release, else the LATEST (a missing release falls
                  back to the latest with a warning).
        Exact     administration (-Verify, -ReinstallTrust ...): the requested release exactly (an error later when it does not exist);
                  none requested = the latest.
        Strict    like Exact, but several releases and no -Release is an error (-RemoveTrust, pki_remove).
        Generate  pki_setup builds a new PKI: the folder of (variant, release); -NewRelease = latest + 1.
    .OUTPUTS
        @{ Path; Name; Release; NoCr; Exists; Fallback }
    #>
    param(
        [Parameter(Mandatory)][string]$ScriptRoot,
        [bool]$NoCr = $false,
        [bool]$NoCrExplicit = $false,
        [int]$Release = 0,
        [bool]$NewRelease = $false,
        [ValidateSet('Use', 'Exact', 'Strict', 'Generate')][string]$Mode = 'Use'
    )
    $all = @(Get-PkiInstalledPkis -ScriptRoot $ScriptRoot)

    if ($Mode -eq 'Generate') {
        $rel = if ($Release -gt 0) { $Release } else { 1 }
        if ($NewRelease) {
            $fam = @($all | Where-Object { $_.NoCr -eq $NoCr })
            $rel = if ($fam.Count -gt 0) { ([int](($fam | Measure-Object -Property Release -Maximum).Maximum)) + 1 } else { 1 }
        }
        $old = $all | Where-Object { $_.Name -eq 'pki (old layout)' -and $_.NoCr -eq $NoCr -and $_.Release -eq $rel } | Select-Object -First 1
        if ($null -ne $old -and -not $NewRelease) { return [pscustomobject]@{ Path = $old.Path; Name = $old.Name; Release = $rel; NoCr = $NoCr; Exists = $true; Fallback = $false } }
        $p = Join-Path (Get-PkiContainer -ScriptRoot $ScriptRoot) (Get-PkiFolderName -NoCr $NoCr -Release $rel)
        return [pscustomobject]@{ Path = $p; Name = (Split-Path -Leaf $p); Release = $rel; NoCr = $NoCr; Exists = (Test-Path -LiteralPath $p); Fallback = $false }
    }

    # the family
    $useNoCr = $NoCr
    if (-not $NoCrExplicit) {
        $hasNormal = @($all | Where-Object { -not $_.NoCr }).Count -gt 0
        $hasNoCr = @($all | Where-Object { $_.NoCr }).Count -gt 0
        if (-not $hasNormal -and $hasNoCr) { $useNoCr = $true; Write-PkiLog 'Only a NoCR PKI exists here: using it.' 'INFO' }
        else { $useNoCr = $false }
    }
    $fam = @($all | Where-Object { $_.NoCr -eq $useNoCr })
    $famName = if ($useNoCr) { 'NoCR' } else { 'normal' }

    if ($fam.Count -eq 0) {
        $rel = if ($Release -gt 0) { $Release } else { 1 }
        $p = Join-Path (Get-PkiContainer -ScriptRoot $ScriptRoot) (Get-PkiFolderName -NoCr $useNoCr -Release $rel)
        return [pscustomobject]@{ Path = $p; Name = (Split-Path -Leaf $p); Release = $rel; NoCr = $useNoCr; Exists = $false; Fallback = $false }
    }
    $latest = $fam | Sort-Object Release -Descending | Select-Object -First 1
    if ($Release -le 0) {
        if ($Mode -eq 'Strict' -and $fam.Count -gt 1) {
            throw ("Several releases of the $famName PKI exist ($(($fam | ForEach-Object { 'R' + $_.Release }) -join ', ')): say which one with -Release <n>.`n" +
                   "Nothing is removed without that. List them: .\pki_remove.ps1 -List")
        }
        return [pscustomobject]@{ Path = $latest.Path; Name = $latest.Name; Release = $latest.Release; NoCr = $latest.NoCr; Exists = $true; Fallback = $false }
    }
    $hit = $fam | Where-Object { $_.Release -eq $Release } | Select-Object -First 1
    if ($null -ne $hit) { return [pscustomobject]@{ Path = $hit.Path; Name = $hit.Name; Release = $hit.Release; NoCr = $hit.NoCr; Exists = $true; Fallback = $false } }
    if ($Mode -eq 'Use') {
        Write-PkiLog "Release R$Release of the $famName PKI does not exist here (deleted?). Using the latest release, R$($latest.Release) ($($latest.Name))." 'WARN'
        return [pscustomobject]@{ Path = $latest.Path; Name = $latest.Name; Release = $latest.Release; NoCr = $latest.NoCr; Exists = $true; Fallback = $true }
    }
    $p = Join-Path (Get-PkiContainer -ScriptRoot $ScriptRoot) (Get-PkiFolderName -NoCr $useNoCr -Release $Release)
    return [pscustomobject]@{ Path = $p; Name = (Split-Path -Leaf $p); Release = $Release; NoCr = $useNoCr; Exists = $false; Fallback = $false }
}
