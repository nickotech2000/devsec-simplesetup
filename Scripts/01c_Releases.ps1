# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 01c_Releases.ps1  -  RELEASES (R2, R3 ...) and the NoCR variant of the PKI
#
# EVERY PKI LIVES INSIDE THE FOLDER  pki  next to the scripts (name: pki_tools.cnf [ general ] PkiFolder). Several PKIs can exist side by side,
# one subfolder each. Since 5.0.0 the folder name carries the PROFILE (company):
#
#     pki\pki-default-01        release 1 of the default profile (agantra), CA certificates WITH revocation information
#     pki\pki-default-02        release 2
#     pki\pki-default-nocr-01   release 1 of the NoCR variant: CA certificates WITHOUT revocation information (-NoCaRevocationInfo)
#     pki\pki-raksaka-01        release 1 of the profile "raksaka" (raksaka_pki.cnf, made by New-PkiConfig.ps1)
#     pki\pki-raksaka-nocr-01   ...
#
# (PKIs made before 5.0.0 - pki\R1, pki\R2, pki\NoCR-R1 or directly in pki\ (pki\root, pki\classical ...) - belong to the default profile
#  and keep working: release / variant from the folder name or from pki-manifest.json. -PkiRoot <folder> points at one PKI.)
#
# Release 1 has no suffix in any name. From release 2 every CA common name ends in " R2", " R3" ...
# The NoCR variant adds " (NoCR)":   Agantra Root CA G1 (NoCR) R2
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
# Provides : Get-PkiContainer, Get-PkiFolderName, Test-PkiFolderName, Get-PkiFolderInfo, Get-PkiInstalledPkis, Resolve-PkiRootChoice
# Requires : 00_Common (Write-PkiLog), 00b_Profiles
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PkiContainer {
    # <script folder>\pki : the folder that holds every PKI
    param([Parameter(Mandatory)][string]$ScriptRoot)
    return (Join-Path $ScriptRoot (Get-PkiToolSetting -Section 'general' -Key 'PkiFolder' -Default 'pki'))
}

# the names of the release folders: pki-<token>-NN | pki-<token>-nocr-NN   (5.0.0)   and the old R1 | NoCR-R1
$script:PkiFolderNameRegex = '^(?i)(?:pki-(?<tok>[a-z][a-z0-9]*)-(?<nocr>nocr-)?(?<rel>\d{2,})|(?<onocr>NoCR-)?R(?<orel>\d+))$'
function Test-PkiFolderName {
    param([Parameter(Mandatory)][string]$Name)
    return ($Name -match $script:PkiFolderNameRegex)
}

function Get-PkiFolderName {
    # pki-default-01 | pki-default-nocr-02 | pki-raksaka-01 ...   (the subfolder of pki\)
    param([bool]$NoCr, [int]$Release = 1, [string]$Profile = 'agantra')
    if ($Release -lt 1) { $Release = 1 }
    return ('pki-{0}-{1}{2:00}' -f (Get-PkiFolderToken -Profile $Profile), $(if ($NoCr) { 'nocr-' } else { '' }), $Release)
}

function Get-PkiFolderInfo {
    # Release and variant of ONE PKI folder: from its pki-manifest.json, else from the folder name (NoCR-R2; a flat old pki\ = R1). $null when it holds no PKI.
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $null }
    $name = Split-Path -Leaf ($Path.TrimEnd('\', '/'))
    $nocr = $false; $rel = 1; $profile = 'agantra'
    if ($name -match $script:PkiFolderNameRegex) {
        if ($Matches['tok']) { $profile = Get-PkiProfileFromToken -Token $Matches['tok']; $nocr = ($Matches['nocr'] -ne ''); $rel = [int]$Matches['rel'] }
        else { $nocr = ($Matches['onocr'] -ne ''); $rel = [int]$Matches['orel'] }
    }
    $mp = Join-Path $Path 'pki-manifest.json'
    $has = (Test-Path -LiteralPath $mp) -or (Test-Path -LiteralPath (Join-Path (Join-Path $Path 'root') 'root.crt'))
    if (-not $has) { return $null }
    if (Test-Path -LiteralPath $mp) {
        try {
            $m = Get-Content -LiteralPath $mp -Raw | ConvertFrom-Json -AsHashtable
            if ($m.ContainsKey('release') -and [int]$m['release'] -gt 0) { $rel = [int]$m['release'] }
            if ($m.ContainsKey('noCaRevocationInfo')) { $nocr = [bool]$m['noCaRevocationInfo'] }
            if ($m.ContainsKey('profile') -and -not [string]::IsNullOrWhiteSpace([string]$m['profile'])) { $profile = ([string]$m['profile']).ToLowerInvariant() }
        }
        catch { }
    }
    return [pscustomobject]@{
        Path = $Path; Name = $name; Release = $rel; NoCr = $nocr; Profile = $profile
        Variant = $(if ($nocr) { 'NoCR' } else { 'normal' })
        Label = $(if ($nocr) { "NoCR R$rel" } else { "R$rel" })
    }
}

function Get-PkiInstalledPkis {
    <#
    .SYNOPSIS
        The PKIs found in <script folder>\pki: the subfolders pki-default-01, pki-raksaka-01, pki-default-nocr-01 ... (and the old R1, NoCR-R1 ...) that
        hold a PKI, and an old flat PKI in pki\ itself. -Profile <short> = only that company's PKIs (default: all profiles).
    .OUTPUTS
        objects with Path, Name, Release, NoCr, Profile, Variant ('normal' | 'NoCR'), Label ('R1', 'NoCR R2' ...), sorted by profile, variant, release.
    #>
    param([Parameter(Mandatory)][string]$ScriptRoot, [string]$Profile)
    $list = [System.Collections.Generic.List[object]]::new()
    $container = Get-PkiContainer -ScriptRoot $ScriptRoot
    if (-not (Test-Path -LiteralPath $container -PathType Container)) { return @() }
    $flat = Get-PkiFolderInfo -Path $container
    if ($null -ne $flat) { $flat.Name = 'pki (old layout)'; [void]$list.Add($flat) }
    foreach ($d in Get-ChildItem -LiteralPath $container -Directory -Force -ErrorAction SilentlyContinue) {
        if (-not (Test-PkiFolderName -Name $d.Name)) { continue }
        $i = Get-PkiFolderInfo -Path $d.FullName
        if ($null -ne $i) { [void]$list.Add($i) }
    }
    $res = @($list | Sort-Object Profile, @{ Expression = { $_.NoCr } }, Release)
    if (-not [string]::IsNullOrWhiteSpace($Profile)) { $res = @($res | Where-Object { $_.Profile -eq $Profile.ToLowerInvariant() }) }
    return $res
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
        [bool]$AutoNew = $false,           # Generate: no release asked and none of -Clean ...: take the next free number when this variant already exists
        [bool]$CheckStore = $false,        # Generate: the Windows certificate stores count as "existing" too
        [string]$Profile = 'agantra',      # the company profile (5.0.0): only its PKIs are looked at, new folders are named pki-<profile>-NN
        [ValidateSet('Use', 'Exact', 'Strict', 'Generate')][string]$Mode = 'Use'
    )
    $Profile = $Profile.ToLowerInvariant()
    $all = @(Get-PkiInstalledPkis -ScriptRoot $ScriptRoot -Profile $Profile)

    if ($Mode -eq 'Generate') {
        # Which release numbers are taken: the folders pki\R<n> / pki\NoCR-R<n> AND (on Windows) the CA certificates in LocalMachine Root / CA.
        $folderRels = @($all | Where-Object { $_.NoCr -eq $NoCr } | ForEach-Object { [int]$_.Release })
        $storeRels = @()
        if ($CheckStore) {
            try { $storeRels = @(Get-PkiStoreReleases -Profile $Profile | Where-Object { $_.NoCr -eq $NoCr } | ForEach-Object { [int]$_.Release }) } catch { $storeRels = @() }
        }
        $known = @($folderRels + $storeRels | Sort-Object -Unique)
        $rel = if ($Release -gt 0) { $Release } else { 1 }
        $auto = $false
        if ($NewRelease -or ($AutoNew -and $Release -le 0 -and $known.Count -gt 0)) {
            $rel = if ($known.Count -gt 0) { ([int](($known | Measure-Object -Maximum).Maximum)) + 1 } else { 1 }
            $auto = (-not $NewRelease)
        }
        $old = $all | Where-Object { $_.Name -eq 'pki (old layout)' -and $_.NoCr -eq $NoCr -and $_.Release -eq $rel } | Select-Object -First 1
        if ($null -ne $old -and -not $NewRelease) { return [pscustomobject]@{ Path = $old.Path; Name = $old.Name; Release = $rel; NoCr = $NoCr; Exists = $true; FolderExists = $true; StoreExists = ($storeRels -contains $rel); AutoNew = $auto; Fallback = $false } }
        $p = Join-Path (Get-PkiContainer -ScriptRoot $ScriptRoot) (Get-PkiFolderName -NoCr $NoCr -Release $rel -Profile $Profile)
        $fe = (Test-Path -LiteralPath $p)
        return [pscustomobject]@{ Path = $p; Name = (Split-Path -Leaf $p); Release = $rel; NoCr = $NoCr; Exists = $fe; FolderExists = $fe; StoreExists = ($storeRels -contains $rel); AutoNew = $auto; Fallback = $false }
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
        $p = Join-Path (Get-PkiContainer -ScriptRoot $ScriptRoot) (Get-PkiFolderName -NoCr $useNoCr -Release $rel -Profile $Profile)
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
    $p = Join-Path (Get-PkiContainer -ScriptRoot $ScriptRoot) (Get-PkiFolderName -NoCr $useNoCr -Release $Release -Profile $Profile)
    return [pscustomobject]@{ Path = $p; Name = (Split-Path -Leaf $p); Release = $Release; NoCr = $useNoCr; Exists = $false; Fallback = $false }
}

function Show-PkiList {
    <#
    .SYNOPSIS
        -ListPki: the PKIs (companies) that can be used with  -Pki <name>  and the PKI folders (releases) that were built for each.
        The name in the first column is the value for -Pki on pki_setup, the leaf / transport / sign scripts and pki_remove.
    #>
    param([Parameter(Mandatory)][string]$ScriptRoot)
    $profiles = @(Get-PkiProfileList -ScriptRoot $ScriptRoot)
    $built = @(Get-PkiInstalledPkis -ScriptRoot $ScriptRoot)
    Write-Host ''
    Write-Host 'PKIs (use the name with  -Pki <name>)' -ForegroundColor Cyan
    if ($profiles.Count -eq 0) { Write-Host '  (no <name>_pki.cnf found next to the scripts)' }
    foreach ($p in $profiles) {
        $mine = @($built | Where-Object { $_.Profile -eq $p.Name })
        Write-Host ('  {0,-14} {1}{2}' -f $p.Name, $p.Organization, $(if ($p.IsDefault) { '   (default)' } else { '' })) -ForegroundColor White
        Write-Host ('  {0,-14} configuration: {1}   folder word: {2}' -f '', (Split-Path -Leaf $p.ConfigPath), $p.Token)
        if ($mine.Count -eq 0) { Write-Host ('  {0,-14} not built yet:  .\pki_setup.ps1 -Pki {1} -InstallTrust' -f '', $p.Name) }
        foreach ($b in $mine) { Write-Host ('  {0,-14} {1,-22} {2}' -f '', $b.Name, $b.Label) }
    }
    $orphans = @($built | Where-Object { $profiles.Name -notcontains $_.Profile })
    foreach ($b in $orphans) { Write-Host ('  [WARN] folder {0} belongs to the PKI "{1}" but {1}_pki.cnf is missing.' -f $b.Name, $b.Profile) -ForegroundColor Yellow }
    Write-Host ''
    Write-Host 'New company: .\New-PkiConfig.ps1      Folders: .\pki\pki-default-01 (agantra), .\pki\pki-<name>-01 ...' -ForegroundColor DarkGray
}
