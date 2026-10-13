# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 00b_Profiles.ps1  -  PKI PROFILES (one per company) and the TOOLS CONFIGURATION FILE  (5.0.0)
#
# A PROFILE is one company's PKI definition: the file  <short>_pki.cnf  next to the scripts.
#     agantra_pki.cnf     the default profile ("agantra"): Agantra Inovatif OU
#     raksaka_pki.cnf     made by  New-PkiConfig.ps1  for "Raksaka Teknologi Indonesia"   (short name = first word, lower case)
# Every script that works on a PKI takes   -Pki <short>   (default: DefaultPki of pki_tools.cnf, "agantra"; tab-completion lists the profiles).
# Same hierarchy, same algorithms, same policies as agantra: only the company data (names, subject, URLs ...) differ.
#
# FOLDERS (inside .\pki\):
#     pki-default-01   pki-default-02  ...     release 1, 2 ... of the default (agantra) profile
#     pki-default-nocr-01 ...                  the NoCR variant of the default profile
#     pki-raksaka-01   pki-raksaka-nocr-01 ... the same for the profile "raksaka"
#   (PKIs made before 5.0.0 - pki\R1, pki\NoCR-R1, or directly in pki\ - belong to the default profile and keep working.)
#
# THE TOOLS CONFIGURATION FILE   pki_tools.cnf   (optional; the owner's file for all the scripts - it is NOT a company profile)
#   Missing file or missing key = the default that was hard-coded before. Sections / keys used:
#     [ general ]    DefaultPki = agantra     PkiFolder = pki     TransportFolder = transport
#     [ openssl ]    Path =                    FipsModuleConfig =
#     [ transport ]  ZipEncryption = Aes256    ArchiveFormat = zip
#     [ trustkit ]   SelfExtract = false       Targets = Windows,Ubuntu,Redhat,SUSE
#
# Provides : Get-PkiToolSetting, Get-PkiDefaultProfileName, Get-PkiProfileList, Resolve-PkiProfile, Get-PkiFolderToken, Get-PkiAllIdentityMarkers
# This file reads the INI files itself, so scripts that do not load the other modules can use it (dot-source it).
# ============================================================
Set-StrictMode -Version Latest

$script:PkiProjectRoot = Split-Path -Parent $PSScriptRoot
$script:PkiToolsCache = $null

function Read-PkiMiniIni {
    # -> hashtable  section(lower) -> ordered hashtable key(lower) -> value.   Comments: # and ;   Sections: [ name ]   Keys: key = value (value may be empty).
    param([Parameter(Mandatory)][string]$Path)
    $ini = @{}
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $ini }
    $sec = ''
    foreach ($raw in [System.IO.File]::ReadAllLines($Path)) {
        $l = $raw.Trim()
        if ($l -eq '' -or $l.StartsWith('#') -or $l.StartsWith(';')) { continue }
        if ($l -match '^\[\s*([^\]]+?)\s*\]$') { $sec = $Matches[1].ToLowerInvariant(); if (-not $ini.ContainsKey($sec)) { $ini[$sec] = [ordered]@{} }; continue }
        $i = $l.IndexOf('=')
        if ($i -lt 1 -or $sec -eq '') { continue }
        $ini[$sec][$l.Substring(0, $i).Trim().ToLowerInvariant()] = $l.Substring($i + 1).Trim()
    }
    return $ini
}

function Get-PkiToolsConfigPath { return (Join-Path $script:PkiProjectRoot 'pki_tools.cnf') }

function Get-PkiToolSetting {
    # The value of  [ section ] key  in pki_tools.cnf, else the default given by the caller (= what was hard-coded before).
    param([Parameter(Mandatory)][string]$Section, [Parameter(Mandatory)][string]$Key, [string]$Default = '')
    if ($null -eq $script:PkiToolsCache) { $script:PkiToolsCache = Read-PkiMiniIni -Path (Get-PkiToolsConfigPath) }
    $s = $Section.ToLowerInvariant(); $k = $Key.ToLowerInvariant()
    if ($script:PkiToolsCache.ContainsKey($s) -and $script:PkiToolsCache[$s].Contains($k)) {
        $v = [string]$script:PkiToolsCache[$s][$k]
        if ($v -ne '') { return $v }
    }
    return $Default
}

function Get-PkiDefaultProfileName { return ((Get-PkiToolSetting -Section 'general' -Key 'DefaultPki' -Default 'agantra').Trim().ToLowerInvariant()) }

function Get-PkiFileStem {
    # the word in file names of packages: agantra-pki | raksaka-pki ...  (-Name empty = the default profile)
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { $Name = Get-PkiDefaultProfileName }
    return ($Name.Trim().ToLowerInvariant() + '-pki')
}

function Get-PkiTransportFolder {
    # <script folder>	ransport (pki_tools.cnf [ general ] TransportFolder; a full path is allowed)
    param([string]$Root = $script:PkiProjectRoot)
    $f = Get-PkiToolSetting -Section 'general' -Key 'TransportFolder' -Default 'transport'
    if ([System.IO.Path]::IsPathRooted($f)) { return $f }
    return (Join-Path $Root $f)
}

function Get-PkiFolderToken {
    # the word in the folder name: "default" for the agantra profile, else the profile name
    param([Parameter(Mandatory)][string]$Profile)
    if ($Profile -eq 'agantra') { return 'default' }
    return $Profile
}

function Get-PkiProfileFromToken {
    param([Parameter(Mandatory)][string]$Token)
    if ($Token -eq 'default') { return 'agantra' }
    return $Token.ToLowerInvariant()
}

function Get-PkiProfileList {
    <#
    .SYNOPSIS
        The PKI profiles found next to the scripts: every  <short>_pki.cnf.
    .OUTPUTS
        objects: Name (short, lower case), ConfigPath, Organization, Prefix, Token (folder word), IsDefault
    #>
    param([string]$ScriptRoot = $script:PkiProjectRoot)
    $out = [System.Collections.Generic.List[object]]::new()
    $def = Get-PkiDefaultProfileName
    foreach ($f in (Get-ChildItem -LiteralPath $ScriptRoot -Filter '*_pki.cnf' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $name = $f.Name.Substring(0, $f.Name.Length - '_pki.cnf'.Length).ToLowerInvariant()
        if ($name -notmatch '^[a-z][a-z0-9]*$') { continue }
        $ini = Read-PkiMiniIni -Path $f.FullName
        $org = ''; if ($ini.ContainsKey('pki_settings') -and $ini['pki_settings'].Contains('organization')) { $org = [string]$ini['pki_settings']['organization'] }
        $prefix = ''; if ($ini.ContainsKey('ca_names') -and $ini['ca_names'].Contains('prefix')) { $prefix = [string]$ini['ca_names']['prefix'] }
        if ($prefix -eq '') { $prefix = ((($org -split '\s+')[0])) }
        [void]$out.Add([pscustomobject]@{ Name = $name; ConfigPath = $f.FullName; Organization = $org; Prefix = $prefix; Token = (Get-PkiFolderToken -Profile $name); IsDefault = ($name -eq $def) })
    }
    return @($out)
}

function Resolve-PkiProfile {
    # -Name empty = the default profile. An unknown name stops with the list of the known ones.
    param([string]$ScriptRoot = $script:PkiProjectRoot, [string]$Name)
    $all = @(Get-PkiProfileList -ScriptRoot $ScriptRoot)
    if ([string]::IsNullOrWhiteSpace($Name)) { $Name = Get-PkiDefaultProfileName }
    $Name = $Name.Trim().ToLowerInvariant()
    $hit = $all | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($null -eq $hit) {
        $known = if ($all.Count -gt 0) { ($all | ForEach-Object { $_.Name }) -join ', ' } else { '(none)' }
        throw "PKI profile '$Name' not found: there is no ${Name}_pki.cnf next to the scripts. Known PKIs: $known.   Make a new one with .\New-PkiConfig.ps1 ; list them with .\pki_setup.ps1 -ListPki"
    }
    return $hit
}

function Get-PkiAllIdentityMarkers {
    # Words that identify the certificates of ALL profiles (organization, prefix, domain of the CRL host): for -RemoveAllTrust.
    param([string]$ScriptRoot = $script:PkiProjectRoot)
    $m = [System.Collections.Generic.List[string]]::new()
    foreach ($w in 'Agantra Inovatif', 'NextMantra') { [void]$m.Add($w) }
    foreach ($p in @(Get-PkiProfileList -ScriptRoot $ScriptRoot)) {
        foreach ($w in @($p.Organization, "$($p.Prefix) Root CA")) { if (-not [string]::IsNullOrWhiteSpace($w) -and ($m -notcontains $w)) { [void]$m.Add($w.Trim()) } }
    }
    return @($m)
}
