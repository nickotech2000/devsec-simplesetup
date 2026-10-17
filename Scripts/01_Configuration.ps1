# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 01_Configuration.ps1
#
# Reads agantra_pki.cnf, merges command-line overrides, validates
# every setting and builds the CA catalog (the PKI hierarchy).
#
# PKI hierarchy (selected quadrants only):
#
#   Enterprise Root  (root)                           RSA 8192 / SHA-512     1000 y
#   |- Classic Track Root (classic-root)              RSA 8192 / SHA-512      500 y
#   |   |- Q1 Root  Non-FIPS  RSA 4096 / SHA-384                              400 y -> q1-dv, q1-ov, q1-ev  250 y  RSA 4096
#   |   `- Q2 Root  FIPS      ECDSA P-384 / SHA-384                           400 y -> q2-dv, q2-ov, q2-ev  250 y  ECDSA P-384
#   `- Quantum Track Root (quantum-root)              ML-DSA-87               500 y
#       |- Quantum Q1 Root (quadrant 3, non-FIPS)  ML-DSA-87                                       400 y -> q3-dv, q3-ov, q3-ev  250 y  ML-DSA-87
#       `- Quantum Q2 Root (quadrant 4, FIPS)      ML-DSA-87                                       400 y -> q4-dv, q4-ov, q4-ev  250 y  ML-DSA-87
#
# The whole Quantum track (roots, intermediates, leaves; FIPS and non-FIPS) uses the post-quantum
# signature ML-DSA. Only the Enterprise Root, which anchors both tracks, is RSA 8192 / SHA-512.
# ML-DSA certificates are stored and validated by Windows 11 24H2+ / Server 2025 (CryptoAPI) and by
# OpenSSL 3.5+; Windows TLS (Schannel) and the browsers do not accept them for HTTPS yet.
#
# Command-line value > agantra_pki.cnf value > built-in default.
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:PkiGeneratorVersion = '6.6.18'

# ROOT KEY POLICY (enforced, not configurable)
#   Every root-level CA (Enterprise Root, Track Roots, Quadrant Roots) is RSA 8192 with
#   SHA-512. Where the algorithm is not RSA, the strongest key and the largest digest the
#   algorithm offers are used:
#     RSA     8192 bit              SHA-512   (8192 is also the largest size BoringSSL / Chrome accepts)
#     ECDSA   P-521 (secp521r1)     SHA-512   (largest NIST curve; Classic FIPS quadrant)
#     ML-DSA  ML-DSA-87             none      (NIST level 5, the highest; a pure signature that hashes
#                                              internally with SHAKE256; Quantum track, FIPS and non-FIPS)
$script:PkiRootRsaBits = 8192
$script:PkiRootCurve   = 'P-521'
$script:PkiRootPqc     = 'mldsa87'
$script:PkiRootDigest  = 'sha512'
# QUADRANT ROOTS (Classic Q1 / Q2) have their own policy (4.9.4): equal strength (about 150-190 bits) with another algorithm, SHA-384.
#     Q1 (non-FIPS)  RSA 4096 / SHA-384          Q2 (FIPS)  ECDSA P-384 / SHA-384          (Quantum Q3 / Q4: ML-DSA-87, unchanged)
# The defaults are written here; agantra_pki.cnf [ pki_settings ] QuadrantRsaBits (4096 | 8192) and QuadrantCurve (P-384 | P-521) can raise them
# (-QuadrantRsaBits / -QuadrantCurve). The Enterprise Root and the Track Roots stay RSA 8192 / SHA-512.
$script:PkiQuadRsaBits = 4096
$script:PkiQuadCurve   = 'P-384'
$script:PkiQuadDigest  = 'sha384'

# Certificate policy OIDs. Defaults are the CA/Browser Forum OIDs; agantra_pki.cnf
# [ policy_oids ] (and -EvPolicyOid) can replace them. The EV OID is mandatory.
# All issuance policies (Windows: "All issuance policies", OpenSSL: "X509v3 Any Policy"): the policy of the Enterprise Root and the Track Roots.
$script:PkiAnyPolicyOid = '2.5.29.32.0'
$script:PkiPolicyOid = @{
    EV = '2.23.140.1.1'
    OV = '2.23.140.1.2.2'
    DV = '2.23.140.1.2.1'
}


# ------------------------------------------------------------
# Windows generation. Windows 11 = build 22000 or higher. Windows 10 has no hybrid
# ML-KEM key exchange in Schannel, so on Windows 10 the Quantum quadrants (3, 4) are not
# built by default (clients there fall back to classical TLS anyway).
# ------------------------------------------------------------
function Get-PkiWindowsBuild {
    if (-not $IsWindows) { return $null }
    return [int][System.Environment]::OSVersion.Version.Build
}

# ------------------------------------------------------------
# ASCII-safe text for OpenSSL subjects (Agantra Inovatif OÜ -> OU)
# ------------------------------------------------------------
function ConvertTo-PkiAscii {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    # Case-sensitive map (a plain hashtable would treat U and u as the same key).
    $map = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
    $pairs = @('Ü=U','ü=u','Ö=O','ö=o','Ä=A','ä=a','Õ=O','õ=o','Š=S','š=s','Ž=Z','ž=z',
               'É=E','é=e','è=e','à=a','ç=c','ñ=n','ß=ss','Å=A','å=a','Ø=O','ø=o','Æ=AE','æ=ae')
    foreach ($pair in $pairs) { $kv = $pair.Split('=', 2); $map[$kv[0]] = $kv[1] }
    $sb = [System.Text.StringBuilder]::new()
    foreach ($ch in $Text.ToCharArray()) {
        $s = [string]$ch
        if ([int]$ch -lt 128) { [void]$sb.Append($s) }
        elseif ($map.ContainsKey($s)) { [void]$sb.Append($map[$s]) }
    }
    return $sb.ToString()
}

# ------------------------------------------------------------
# Minimal OpenSSL-style INI reader.
# Returns: hashtable  section -> List[pscustomobject]{Key;Value}
# Section names and keys are case-insensitive.
# ------------------------------------------------------------
function Read-PkiIni {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Configuration file not found: $Path"
    }
    $ini = @{}
    $section = ''
    $ini[$section] = [System.Collections.Generic.List[object]]::new()
    foreach ($raw in [System.IO.File]::ReadAllLines($Path)) {
        $line = $raw.Trim()
        if ($line.Length -eq 0) { continue }
        if ($line.StartsWith('#') -or $line.StartsWith(';')) { continue }
        if ($line -match '^\[\s*(?<n>[^\]]+?)\s*\]$') {
            $section = $Matches['n']
            if (-not $ini.ContainsKey($section)) {
                $ini[$section] = [System.Collections.Generic.List[object]]::new()
            }
            continue
        }
        $eq = $line.IndexOf('=')
        if ($eq -lt 1) { continue }
        $key = $line.Substring(0, $eq).Trim()
        $val = $line.Substring($eq + 1).Trim()
        $val = ($val -replace '\s+#.*$', '').Trim()
        if ($val.Length -ge 2 -and $val.StartsWith('"') -and $val.EndsWith('"')) {
            $val = $val.Substring(1, $val.Length - 2)
        }
        [void]$ini[$section].Add([pscustomobject]@{ Key = $key; Value = $val })
    }
    return $ini
}

function Get-PkiIniEntries {
    param([hashtable]$Ini, [string]$Section)
    if ($Ini.ContainsKey($Section)) { return @($Ini[$Section]) }
    return @()
}

function Get-PkiIniValue {
    param([hashtable]$Ini, [string]$Section, [string]$Key, [string]$Default = '')
    $found = $null
    foreach ($e in (Get-PkiIniEntries -Ini $Ini -Section $Section)) {
        if ($e.Key -ieq $Key) { $found = $e.Value }
    }
    if ($null -eq $found -or $found -eq '') { return $Default }
    return $found
}

function Get-PkiIniList {
    # Values of keys such as URI.1, URI.2 ... in section order.
    param([hashtable]$Ini, [string]$Section)
    return @(Get-PkiIniEntries -Ini $Ini -Section $Section |
        Where-Object { $_.Value -ne '' } | ForEach-Object { $_.Value })
}

# ------------------------------------------------------------
# Custom policies: "label = OID [| CPS URL]"
# ------------------------------------------------------------
function ConvertTo-PkiPolicy {
    param([Parameter(Mandatory)][string]$Text, [string]$Label = 'custom')
    $parts = $Text -split '\|', 2
    $oid = $parts[0].Trim()
    $cps = ''
    if ($parts.Count -gt 1) { $cps = $parts[1].Trim() }
    if ($oid -notmatch '^[0-2](\.(0|[1-9]\d*))+$') {
        throw "Custom policy '$Label' has an invalid OID: '$oid'"
    }
    return [ordered]@{ Label = $Label; Oid = $oid; Cps = $cps }
}

function Get-PkiPqcDisplayName {
    param([string]$Algorithm)
    if ($Algorithm -match '^(?i)ml-?dsa-?(\d+)$') { return "ML-DSA-$($Matches[1])" }
    return $Algorithm.ToUpperInvariant()
}

# ------------------------------------------------------------
# CA catalog
# ------------------------------------------------------------
function New-PkiCatalog {
    $cfg = $script:Pki
    $list = [System.Collections.Generic.List[hashtable]]::new()
    $addCa = {
        param([hashtable]$d)
        $d['Actual'] = $null
        $d['Done'] = $false
        [void]$list.Add($d)
    }
    $nm = $cfg.Naming
    $gE = $nm.GenEnterprise; $gC = $nm.GenClassic; $gQ = $nm.GenQuantum
    $rsaRoot = @{ Family = 'rsa';   Bits = $script:PkiRootRsaBits; Curve = $null;                 PqcAlg = $null }
    $ecRoot  = @{ Family = 'ecdsa'; Bits = 0;                      Curve = $script:PkiRootCurve;  PqcAlg = $null }
    $q1Root  = @{ Family = 'rsa';   Bits = $cfg.QuadrantRsaBits;   Curve = $null;                 PqcAlg = $null }
    $q2Root  = @{ Family = 'ecdsa'; Bits = 0;                      Curve = $cfg.QuadrantCurve;    PqcAlg = $null }
    $pqRoot  = @{ Family = 'pqc';   Bits = 0;                      Curve = $null;                 PqcAlg = $script:PkiRootPqc }

    & $addCa @{
        Id = 'root'; Kind = 'root'; Parent = $null
        RelDir = 'root'; Track = 'Enterprise'; Quadrant = 0; Fips = $false
        Family = $rsaRoot.Family; Bits = $cfg.EnterpriseRootKeyBits; Curve = $null; PqcAlg = $null; FallbackBits = $script:PkiRootRsaBits
        Years = $cfg.RootYears; PathLen = 3; Validation = $null; Gen = $gE; Ou = $cfg.OuRoot
    }

    $wantClassic = ($cfg.Quadrants -contains 1) -or ($cfg.Quadrants -contains 2)
    $wantQuantum = ($cfg.Quadrants -contains 3) -or ($cfg.Quadrants -contains 4)

    if ($wantClassic) {
        & $addCa @{
            Id = 'classic-root'; Kind = 'track'; Parent = 'root'
            RelDir = 'classical\root'; Track = 'Classic'; Quadrant = 0; Fips = $false
            Family = $rsaRoot.Family; Bits = $rsaRoot.Bits; Curve = $null; PqcAlg = $null; FallbackBits = $script:PkiRootRsaBits
            Years = $cfg.TrackYears; PathLen = 2; Validation = $null; Gen = $gC; Ou = $cfg.OuTrack
        }
    }
    if ($wantQuantum) {
        & $addCa @{
            Id = 'quantum-root'; Kind = 'track'; Parent = 'root'
            RelDir = 'quantum\root'; Track = 'Quantum'; Quadrant = 0; Fips = $false
            Family = $pqRoot.Family; Bits = 0; Curve = $null; PqcAlg = $pqRoot.PqcAlg; FallbackBits = $script:PkiRootRsaBits
            Years = $cfg.TrackYears; PathLen = 2; Validation = $null; Gen = $gQ; Ou = $cfg.OuTrack
        }
    }

    # Quadrants 1 / 3 are non-FIPS, 2 / 4 are FIPS (named Q1 / Q2 in both tracks). Quantum quadrants (3, 4) are ML-DSA at every level.
    # Root level = enforced root policy. Intermediate level = configurable (below the roots).
    $quadDefs = @(
        @{ N = 1; Track = 'Classic'; Dir = 'classical'; Parent = 'classic-root'; Fips = $false; Gen = $gC
           Root = $q1Root; Int = @{ Family = 'rsa';   Bits = $cfg.IntermediateRsaBits; Curve = $null; PqcAlg = $null } }
        @{ N = 2; Track = 'Classic'; Dir = 'classical'; Parent = 'classic-root'; Fips = $true;  Gen = $gC
           Root = $q2Root;  Int = @{ Family = 'ecdsa'; Bits = 0; Curve = $cfg.IntermediateCurve; PqcAlg = $null } }
        @{ N = 3; Track = 'Quantum'; Dir = 'quantum';   Parent = 'quantum-root'; Fips = $false; Gen = $gQ
           Root = $pqRoot;  Int = @{ Family = 'pqc';   Bits = 0; Curve = $null; PqcAlg = $cfg.PqcAlgorithm } }
        @{ N = 4; Track = 'Quantum'; Dir = 'quantum';   Parent = 'quantum-root'; Fips = $true;  Gen = $gQ
           Root = $pqRoot;  Int = @{ Family = 'pqc';   Bits = 0; Curve = $null; PqcAlg = $cfg.PqcAlgorithm } }
    )
    foreach ($q in $quadDefs) {
        if ($cfg.Quadrants -notcontains $q.N) { continue }
        $qid = "q$($q.N)"
        $g = $q.Gen.ToLowerInvariant()
        & $addCa @{
            Id = "$qid-root"; Kind = 'quadrant'; Parent = $q.Parent
            RelDir = "$($q.Dir)\$qid\root"; Track = $q.Track; Quadrant = $q.N; Fips = $q.Fips
            Family = $q.Root.Family; Bits = $q.Root.Bits; Curve = $q.Root.Curve; PqcAlg = $q.Root.PqcAlg; FallbackBits = $script:PkiRootRsaBits
            Years = $cfg.QuadrantYears; PathLen = 1; Validation = $null; Gen = $q.Gen; Ou = $cfg.OuQuadrant
        }
        foreach ($v in @('DV', 'OV', 'EV')) {
            $vl = $v.ToLowerInvariant()
            & $addCa @{
                Id = "$qid-$vl"; Kind = 'intermediate'; Parent = "$qid-root"
                RelDir = "$($q.Dir)\$qid\$vl"; Track = $q.Track; Quadrant = $q.N; Fips = $q.Fips
                Family = $q.Int.Family; Bits = $q.Int.Bits; Curve = $q.Int.Curve; PqcAlg = $q.Int.PqcAlg; FallbackBits = $cfg.FallbackRsaBits
                Years = $cfg.IntYears; PathLen = $cfg.IntermediatePathLen; Validation = $v; Gen = $q.Gen; Ou = $cfg.OuIntermediate
            }
        }
    }
    foreach ($d in $list) { $d['Slug'] = Get-PkiCaSlug -Ca $d }
    return $list
}

# ------------------------------------------------------------
# Extra policies: the PEN policies derived from your IANA Private Enterprise Number.
#   arc    = 1.3.6.1.4.1.<PEN>.<PenPolicyArc>          general company policy
#   level  = <arc>.1 (EV)  <arc>.2 (OV)  <arc>.3 (DV)  level policy
# Nothing is added while IanaPen is blank.
# ------------------------------------------------------------
function Get-PkiCpsUrl {
    # CPS pointer of a policy: EV -> CpsUrlEv (ev-cps.pdf), every other level -> CpsUrl (https://nextmantra.com/security/certs)
    param([Parameter(Mandatory)][ValidateSet('EV', 'OV', 'DV', 'All')][string]$Level)
    if ($Level -eq 'EV') { return [string]$script:Pki.CpsUrlEv }
    return [string]$script:Pki.CpsUrl
}

function Get-PkiHighAssurancePolicy {
    # The High Assurance policy of OV certificates ($null when switched off or no OID can be derived).
    $v = [string]$script:PkiHighAssuranceOid
    if ($v -eq 'none') { return $null }
    if ($v -eq '') {
        $pen = [string]$script:Pki.IanaPen
        if ([string]::IsNullOrWhiteSpace($pen)) { return $null }
        $v = "1.3.6.1.4.1.$pen.$($script:Pki.PenArc).5"
    }
    return [ordered]@{ Label = 'HighAssurance'; Oid = $v; Cps = (Get-PkiCpsUrl -Level 'OV') }
}

function Get-PkiPenPolicies {
    param([Parameter(Mandatory)][ValidateSet('EV', 'OV', 'DV', 'All')][string]$Level)
    $list = [System.Collections.Generic.List[object]]::new()
    $pen = [string]$script:Pki.IanaPen
    if ([string]::IsNullOrWhiteSpace($pen)) { return $list }
    $arc = "1.3.6.1.4.1.$pen.$($script:Pki.PenArc)"
    [void]$list.Add([ordered]@{ Label = 'PEN'; Oid = $arc; Cps = (Get-PkiCpsUrl -Level $Level) })
    $n = @{ EV = 1; OV = 2; DV = 3 }
    foreach ($l in 'EV', 'OV', 'DV') {
        if ($Level -eq 'All' -or $Level -eq $l) { [void]$list.Add([ordered]@{ Label = "PEN-$l"; Oid = "$arc.$($n[$l])"; Cps = (Get-PkiCpsUrl -Level $l) }) }
    }
    return $list
}

function Get-PkiExtraPolicies {
    # custom policies of the cnf + PEN policies, without duplicates
    param([Parameter(Mandatory)][ValidateSet('EV', 'OV', 'DV', 'All')][string]$Level)
    $list = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $ha = @(); if ($Level -in 'OV', 'All') { $h = Get-PkiHighAssurancePolicy; if ($null -ne $h) { $ha = @($h) } }
    foreach ($p in (@($script:Pki.CustomPolicies) + @(Get-PkiPenPolicies -Level $Level) + $ha)) {
        if ($seen.Add($p.Oid)) { [void]$list.Add($p) }
    }
    return $list
}

function Get-PkiTimestampSettings {
    # Quadrant (default 1 = Classic non-FIPS), policy OID (-TimestampPolicyOid > [ timestamp ] PolicyOid > <PEN arc>.4), validity days.
    $c = $script:Pki
    $oid = [string]$c.TimestampPolicyOid
    $derived = $false
    if ([string]::IsNullOrWhiteSpace($oid) -and -not [string]::IsNullOrWhiteSpace([string]$c.IanaPen)) { $oid = "1.3.6.1.4.1.$($c.IanaPen).$($c.PenArc).4"; $derived = $true }
    return [ordered]@{ Quadrant = [int]$c.TimestampQuadrant; PolicyOid = $oid; Derived = $derived; Days = [int]$c.TimestampDays }
}

function Get-PkiLeafDays {
    # EV: LeafDays (397). OV: OvLeafYears (3 years). DV: DvLeafYears (5 years).
    param([Parameter(Mandatory)][ValidateSet('EV', 'OV', 'DV')][string]$Level)
    switch ($Level) {
        'EV' { return [int]$script:Pki.LeafDays }
        'OV' { return (Get-PkiValidityDays -Years ([int]$script:Pki.OvLeafYears)) }
        'DV' { return (Get-PkiValidityDays -Years ([int]$script:Pki.DvLeafYears)) }
    }
}

function Get-PkiCa {
    param([Parameter(Mandatory)][string]$Id)
    foreach ($c in $script:Pki.Catalog) { if ($c.Id -eq $Id) { return $c } }
    throw "CA '$Id' is not in the catalog."
}

# ------------------------------------------------------------
# Initialize-PkiConfiguration
# ------------------------------------------------------------
function Initialize-PkiConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptRoot,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Bound,
        [switch]$VerboseOutput,
        # which PKI folder (pki\R1, pki\R2, pki\NoCR-R1 ...): Use (default; signing, issuing, packing: the requested release, else the latest),
        # Exact / Strict (administration), Generate (pki_setup builds a new one). See scripts\01c_Releases.ps1.
        [ValidateSet('Use', 'Exact', 'Strict', 'Generate')][string]$RootMode = 'Use'
    )

    # PSBoundParametersDictionary has ContainsKey only; use a plain hashtable.
    $copy = @{}
    foreach ($k in $Bound.Keys) { $copy[$k] = $Bound[$k] }
    $Bound = $copy

    # ---- which company (profile)? -Pki <short> (default: pki_tools.cnf DefaultPki = agantra) -> <short>_pki.cnf; -ConfigFile <path> names the file directly ----
    $reqPki = if ($Bound.Contains('PkiProfile') -and -not [string]::IsNullOrWhiteSpace([string]$Bound['PkiProfile'])) { [string]$Bound['PkiProfile'] } else { '' }
    $configPath = ''
    if ($Bound.Contains('ConfigFile') -and -not [string]::IsNullOrWhiteSpace([string]$Bound['ConfigFile'])) {
        $configPath = [string]$Bound['ConfigFile']
        if (-not [System.IO.Path]::IsPathRooted($configPath)) { $configPath = Join-Path (Get-Location).Path $configPath }
        $leafCnf = [System.IO.Path]::GetFileName($configPath).ToLowerInvariant()
        $profileName = if ($reqPki) { $reqPki.ToLowerInvariant() } elseif ($leafCnf -match '^(?<n>[a-z][a-z0-9]*)_pki\.cnf$') { $Matches['n'] } else { Get-PkiDefaultProfileName }
    }
    else {
        $prof = Resolve-PkiProfile -ScriptRoot $ScriptRoot -Name $reqPki
        $configPath = $prof.ConfigPath; $profileName = $prof.Name
    }
    $ini = Read-PkiIni -Path $configPath
    if ($profileName -ne 'agantra' -and [string]::IsNullOrWhiteSpace((Get-PkiIniValue -Ini $ini -Section 'pki_settings' -Key 'Organization' -Default ''))) {
        throw "The configuration of the PKI '$profileName' ($configPath) has no Organization in [ pki_settings ]: make it with .\New-PkiConfig.ps1."
    }

    # policy OIDs: command line > [ policy_oids ] > CA/B Forum default
    $script:PkiPolicyOid.EV = Get-PkiIniValue -Ini $ini -Section 'policy_oids' -Key 'EV' -Default '2.23.140.1.1'
    $script:PkiPolicyOid.OV = Get-PkiIniValue -Ini $ini -Section 'policy_oids' -Key 'OV' -Default '2.23.140.1.2.2'
    $script:PkiPolicyOid.DV = Get-PkiIniValue -Ini $ini -Section 'policy_oids' -Key 'DV' -Default '2.23.140.1.2.1'
    if ($Bound.Contains('EvPolicyOid')) { $script:PkiPolicyOid.EV = ([string]$Bound['EvPolicyOid']).Trim() }
    # High Assurance policy of every OV certificate: '' = <PEN>.<arc>.5 when a PEN is set, an OID = that OID, 'none' = off
    $script:PkiHighAssuranceOid = (Get-PkiIniValue -Ini $ini -Section 'policy_oids' -Key 'HighAssurance' -Default '').Trim()

    # command line > cnf > default
    $opt = {
        param([string]$Name, [string]$IniKey, $Default)
        if ($Bound.Contains($Name)) { return $Bound[$Name] }
        $v = Get-PkiIniValue -Ini $ini -Section 'pki_settings' -Key $IniKey -Default ''
        if ($v -ne '') { return $v }
        return $Default
    }
    $flag = { param([string]$Name) return ($Bound.Contains($Name) -and [bool]$Bound[$Name]) }

    # ---- which PKI: -PkiRoot, else release / variant (pki\R1, pki\R2, pki\NoCR-R1 ...) ----
    $reqRelease = if ($Bound.Contains('Release') -and [int]$Bound['Release'] -gt 0) { [int]$Bound['Release'] } else { 0 }
    $reqNoCr = ($Bound.Contains('NoCaRevocationInfo') -and [bool]$Bound['NoCaRevocationInfo'])
    # A leaf without CRL / OCSP (-NoRevocationInfo on the leaf scripts and SignCsr) is signed by the NoCR family: CA certificates without revocation URLs, latest release (or -Release).
    $impliedNoCr = (-not $reqNoCr -and $RootMode -eq 'Use' -and $Bound.Contains('NoRevocationInfo') -and [bool]$Bound['NoRevocationInfo'] -and -not ($Bound.Contains('PkiRoot') -and -not [string]::IsNullOrWhiteSpace([string]$Bound['PkiRoot'])))
    if ($impliedNoCr) { $reqNoCr = $true }
    $newRelease = ($Bound.Contains('NewRelease') -and [bool]$Bound['NewRelease'])
    $noCr = $reqNoCr; $release = if ($reqRelease -gt 0) { $reqRelease } else { 1 }
    if ($Bound.Contains('PkiRoot') -and -not [string]::IsNullOrWhiteSpace([string]$Bound['PkiRoot'])) {
        $pkiRoot = [string]$Bound['PkiRoot']
        if (-not [System.IO.Path]::IsPathRooted($pkiRoot)) { $pkiRoot = Join-Path (Get-Location).Path $pkiRoot }
        $fi = Get-PkiFolderInfo -Path $pkiRoot
        if ($null -ne $fi -and $RootMode -ne 'Generate') { $noCr = $fi.NoCr; $release = $fi.Release }
        if ($null -ne $fi -and $RootMode -ne 'Generate' -and $reqPki -eq '' -and $fi.Profile -ne $profileName -and ($Bound.Contains('ConfigFile') -eq $false)) {
            # -PkiRoot points at another company's PKI: use that company's configuration
            try { $prof2 = Resolve-PkiProfile -ScriptRoot $ScriptRoot -Name $fi.Profile; $configPath = $prof2.ConfigPath; $profileName = $prof2.Name; $ini = Read-PkiIni -Path $configPath } catch { }
        }
    }
    else {
        # A plain build (also with -InstallTrust): no release asked = the next free release; -Release <n> that exists (folder or Windows store) = stop.
        $otherAction = @('Clean', 'Check', 'Unblock', 'ShowNames', 'EnterpriseRootCsr', 'ImportEnterpriseRoot', 'RemoveAllTrust', 'RemoveTrust', 'Verify', 'ReinstallTrust', 'CrossSignCsr', 'ImportCrossCert') | Where-Object { & $flag $_ }
        $plainBuild = ($RootMode -eq 'Generate' -and @($otherAction).Count -eq 0)
        $choice = Resolve-PkiRootChoice -ScriptRoot $ScriptRoot -NoCr $reqNoCr -NoCrExplicit $reqNoCr -Release $reqRelease -NewRelease $newRelease -Mode $RootMode -Profile $profileName `
            -AutoNew $plainBuild -CheckStore ($plainBuild -and $IsWindows)
        $pkiRoot = $choice.Path; $noCr = [bool]$choice.NoCr; $release = [int]$choice.Release
        if ($impliedNoCr) {
            if (-not $choice.Exists) { throw "-NoRevocationInfo signs with the NoCR PKI (CA certificates without CRL / OCSP URLs), and none exists here.`nBuild it first:  .\pki_setup.ps1 -NoCaRevocationInfo -InstallTrust     (or leave out -NoRevocationInfo to sign with the normal PKI)" }
            Write-PkiLog "-NoRevocationInfo: signing with the NoCR PKI, release R$($choice.Release) ($($choice.Name)), not the normal PKI." 'INFO'
        }
        if ($plainBuild -and $reqRelease -gt 0 -and -not $newRelease -and ([bool]$choice.FolderExists -or [bool]$choice.StoreExists)) {
            $where = @(); if ($choice.FolderExists) { $where += "the folder $($choice.Path)" }; if ($choice.StoreExists) { $where += 'the Windows certificate store (LocalMachine Root / CA)' }
            throw ("$(if ($noCr) { 'NoCR ' })R$release already exists: $($where -join ' and ').`nNothing was created. Use another number, leave out -Release (the next free release is taken), or replace it:  -Clean -Release $release   Remove it:  .\pki_remove.ps1 -Release $release$(if ($noCr) { ' -NoCaRevocationInfo' })")
        }
        if ($choice.PSObject.Properties['AutoNew'] -and $choice.AutoNew) { Write-PkiLog "A PKI of this variant already exists: building the next release, R$release (like -NewRelease). Replace one instead: -Clean -Release <n>." 'INFO' }
    }

    # Windows Server 2022 (5.0.0): the CLASSIC track only (quadrants 1 and 2). Windows 11 24H2+ / Server 2025 / Linux: all four.
    $plat = if ($null -ne (Get-Variable -Name PkiPlatform -Scope Global -ErrorAction SilentlyContinue)) { $global:PkiPlatform } else { Get-PkiPlatformInfo }
    $classicOnly = [bool]$plat.ClassicOnly
    $quadrants = if ($classicOnly) { @(1, 2) } else { @(1, 2, 3, 4) }
    if ($Bound.Contains('ClassicPKI') -and [bool]$Bound['ClassicPKI']) {
        if ($Bound.Contains('Quadrant')) { throw '-ClassicPKI builds Enterprise Root, Classic Track Root, Q1 Root and the DV / OV / EV intermediates only. It cannot be combined with -Quadrant.' }
        $quadrants = @(1)
    }
    elseif ($Bound.Contains('Quadrant')) { $quadrants = @($Bound['Quadrant'] | ForEach-Object { [int]$_ } | Sort-Object -Unique) }
    if ($classicOnly -and (@($quadrants | Where-Object { $_ -ge 3 }).Count -gt 0)) {
        throw "This computer ($($plat.Name)) is Windows Server 2022: only the CLASSIC track can be generated (Quadrant 1 and 2). The Quantum track (Quadrant 3 and 4, ML-DSA) needs Windows 11 24H2 or newer / Windows Server 2025."
    }

    $country = ([string](& $opt 'Country' 'Country' 'EE')).ToUpperInvariant()
    $jur = ([string](& $opt 'JurisdictionCountry' 'JurisdictionCountry' 'EE')).ToUpperInvariant()

    $leafSizes = @(2048)
    if ($Bound.Contains('LeafSizes')) { $leafSizes = @($Bound['LeafSizes'] | ForEach-Object { [int]$_ }) }

    $script:Pki = [ordered]@{
        ScriptRoot = $ScriptRoot
        Profile    = $profileName
        ProfileToken = (Get-PkiFolderToken -Profile $profileName)
        ClassicOnly = $classicOnly
        ConfigPath = $configPath
        Ini        = $ini
        PkiRoot    = $pkiRoot
        Release    = $release
        NoCaRevocationInfo = $noCr
        PkiContainer = (Get-PkiContainer -ScriptRoot $ScriptRoot)
        PublishDir = Join-Path $pkiRoot 'publish'
        LeafDir    = Join-Path $pkiRoot 'leaf'
        VerboseOutput = [bool]$VerboseOutput
        Bound = $Bound

        # algorithms
        IntermediateRsaBits = [int](& $opt 'IntermediateRsaBits' 'IntermediateRsaBits' 4096)
        IntermediatePathLen = [int](& $opt 'IntermediatePathLen' 'IntermediatePathLen' 0)
        QuadrantRsaBits     = [int](& $opt 'QuadrantRsaBits' 'QuadrantRsaBits' $script:PkiQuadRsaBits)
        QuadrantCurve       = [string](& $opt 'QuadrantCurve' 'QuadrantCurve' $script:PkiQuadCurve)
        PqcAlgorithm        = [string](& $opt 'PqcAlgorithm' 'PqcAlgorithm' 'mldsa87')
        PqcLeafAlgorithm    = [string](& $opt 'PqcLeafAlgorithm' 'PqcLeafAlgorithm' 'mldsa65')
        FallbackRsaBits     = [int](& $opt 'FallbackRsaBits' 'FallbackRsaBits' 8192)
        PqcFallback         = (& $flag 'PqcFallback')
        IntermediateCurve   = [string](& $opt 'IntermediateCurve' 'IntermediateCurve' 'P-384')
        RsaPss          = (& $flag 'RsaPss')

        # validity
        RootYears     = [int](& $opt 'RootYears' 'RootYears' 1000)
        TrackYears    = [int](& $opt 'TrackYears' 'TrackYears' 500)
        QuadrantYears = [int](& $opt 'QuadrantYears' 'QuadrantYears' 400)
        IntYears      = [int](& $opt 'IntYears' 'IntYears' 250)
        LeafDays      = [int](& $opt 'LeafDays' 'LeafDays' 397)
        OvLeafYears   = [int](& $opt 'OvLeafYears' 'OvLeafYears' 3)
        DvLeafYears   = [int](& $opt 'DvLeafYears' 'DvLeafYears' 5)
        IanaPen       = ([string]$(if ($Bound.Contains('IanaPen')) { $Bound['IanaPen'] } else { Get-PkiIniValue -Ini $ini -Section 'iana_pen' -Key 'PEN' -Default '' })).Trim()
        PenArc        = ([string](Get-PkiIniValue -Ini $ini -Section 'iana_pen' -Key 'PenPolicyArc' -Default '1')).Trim()
        # time stamping (RFC 3161): classic non-FIPS by default (Quadrant 1), the parameters allow another quadrant later
        TimestampQuadrant  = [int]$(if ($Bound.Contains('TimestampQuadrant')) { $Bound['TimestampQuadrant'] } else { Get-PkiIniValue -Ini $ini -Section 'timestamp' -Key 'Quadrant' -Default '1' })
        TimestampPolicyOid = ([string]$(if ($Bound.Contains('TimestampPolicyOid')) { $Bound['TimestampPolicyOid'] } else { Get-PkiIniValue -Ini $ini -Section 'timestamp' -Key 'PolicyOid' -Default '' })).Trim()
        TimestampDays      = [int]$(if ($Bound.Contains('TimestampDays')) { $Bound['TimestampDays'] } else { Get-PkiIniValue -Ini $ini -Section 'timestamp' -Key 'Days' -Default '1825' })
        # revocation: CRL validity and the OCSP responder certificates
        CrlDays            = [int]$(if ($Bound.Contains('CrlDays')) { $Bound['CrlDays'] } else { Get-PkiIniValue -Ini $ini -Section 'revocation' -Key 'CrlDays' -Default '365' })
        OcspDays           = [int]$(if ($Bound.Contains('OcspDays')) { $Bound['OcspDays'] } else { Get-PkiIniValue -Ini $ini -Section 'revocation' -Key 'OcspDays' -Default '365' })
        OcspKeyBits        = [int](Get-PkiIniValue -Ini $ini -Section 'revocation' -Key 'OcspKeyBits' -Default '2048')
        LeafSizes     = $leafSizes

        # layer names
        OuRoot         = ConvertTo-PkiAscii ([string](& $opt 'OuRoot' 'OU_Root' 'Root-Certs'))
        OuTrack        = ConvertTo-PkiAscii ([string](& $opt 'OuTrack' 'OU_Track' 'Track-Roots'))
        OuQuadrant     = ConvertTo-PkiAscii ([string](& $opt 'OuQuadrant' 'OU_Quadrant' 'Quadrant-Roots'))
        OuIntermediate = ConvertTo-PkiAscii ([string](& $opt 'OuIntermediate' 'OU_Intermediate' 'Intermediate-CA'))

        # CA subject
        Subject = [ordered]@{
            Organization = ConvertTo-PkiAscii ([string](& $opt 'Organization' 'Organization' 'Agantra Inovatif OU'))
            Country      = $country
            State        = ConvertTo-PkiAscii ([string](& $opt 'State' 'State' 'Tallinn'))
            Locality     = ConvertTo-PkiAscii ([string](& $opt 'Locality' 'Locality' 'Tallinn'))
            PostalCode   = ConvertTo-PkiAscii ([string](& $opt 'PostalCode' 'PostalCode' '15199'))
            Street       = ConvertTo-PkiAscii ([string](& $opt 'Street' 'Street' ''))
            Serial       = ConvertTo-PkiAscii ([string](& $opt 'Serial' 'CaSerialNumber' 'EEARIREG.17344131'))
            BusinessCategory    = ConvertTo-PkiAscii ([string](& $opt 'BusinessCategory' 'BusinessCategory' 'Private Organization'))
            JurisdictionCountry = $jur
            JurisdictionState   = ConvertTo-PkiAscii ([string](& $opt 'JurisdictionState' 'JurisdictionState' 'Tallinn'))
            JurisdictionLocality = ConvertTo-PkiAscii ([string](& $opt 'JurisdictionLocality' 'JurisdictionLocality' ''))
            ContactName  = ConvertTo-PkiAscii ([string](& $opt 'ContactName' 'CaContactName' 'Nicko Satria Utama'))
            ContactEmail = [string](& $opt 'ContactEmail' 'CaContactEmail' 'nicko@nextmantra.com')
            ContactPhone = [string](& $opt 'ContactPhone' 'CaContactPhone' '(+372)53194019')
        }
        Domain = [string]$(if ($Bound.Contains('Domain')) { $Bound['Domain'] } else { '' })
        CpsUrl = [string](& $opt 'CpsUrl' 'CpsUrl' 'https://nextmantra.com/security/certs')
        CpsUrlEv = [string](& $opt 'CpsUrlEv' 'CpsUrlEv' 'https://nextmantra.com/security/certs/ev-cps.pdf')

        # tooling
        OpenSslPath      = [string]$(if ($Bound.Contains('OpenSslPath')) { $Bound['OpenSslPath'] } else { Get-PkiToolSetting -Section 'openssl' -Key 'Path' -Default '' })
        FipsModuleConfig = [string]$(if ($Bound.Contains('FipsModuleConfig')) { $Bound['FipsModuleConfig'] } else { Get-PkiToolSetting -Section 'openssl' -Key 'FipsModuleConfig' -Default '' })
        OpenSslExe = $null
        OpenSslVersion = $null
        Quadrants = $quadrants
        WindowsBuild = $(if ($IsWindows) { Get-PkiWindowsBuild } else { $null })
        Windows10 = $false
        QuadrantWasChosen = $Bound.Contains('Quadrant')

        # actions
        Password      = [string]$(if ($Bound.Contains('Password')) { $Bound['Password'] } else { 'Abc12345!' })
        LegacyPfx     = (& $flag 'LegacyPfx')
        InstallTrust  = (& $flag 'InstallTrust')
        Clean         = (& $flag 'Clean')
        RemoveTrust   = (& $flag 'RemoveTrust')
        RemoveAllTrust = (& $flag 'RemoveAllTrust')
        SkipLeaf      = (& $flag 'SkipLeaf')
        SkipRevocation = (& $flag 'SkipRevocation')
        UnblockOnly   = (& $flag 'Unblock')
        ShowNamesOnly = (& $flag 'ShowNames')
        ReinstallTrust = (& $flag 'ReinstallTrust')
        ClassicPki    = (& $flag 'ClassicPKI')

        # Enterprise Root signed by a public CA (see docs\PUBLIC-CA-ENTERPRISE-ROOT.txt)
        ExternalCa           = [string]$(if ($Bound.Contains('ExternalCa')) { $Bound['ExternalCa'] } else { '' })
        EnterpriseRootCsr    = (& $flag 'EnterpriseRootCsr')
        ImportEnterpriseRoot = [string]$(if ($Bound.Contains('ImportEnterpriseRoot')) { $Bound['ImportEnterpriseRoot'] } else { '' })
        ExternalChain        = [string]$(if ($Bound.Contains('ExternalChain')) { $Bound['ExternalChain'] } else { '' })
        EnterpriseRootKeyBits = [int]$(if ($Bound.Contains('EnterpriseRootKeyBits')) { $Bound['EnterpriseRootKeyBits'] } else { 8192 })
        CrossSignCsr         = (& $flag 'CrossSignCsr')
        ImportCrossCert      = [string]$(if ($Bound.Contains('ImportCrossCert')) { $Bound['ImportCrossCert'] } else { '' })
        ExternalRoot         = $null
        CheckOnly     = (& $flag 'Check')
        VerifyOnly    = (& $flag 'Verify')

        # lists from the cnf
        CrlUrls    = @(Get-PkiIniList -Ini $ini -Section 'crl_urls')
        OcspUrls   = @(Get-PkiIniList -Ini $ini -Section 'ocsp_urls')
        CaIssuerUrls = @(Get-PkiIniList -Ini $ini -Section 'ca_issuer_urls')
        CustomPolicies = @()

        # runtime state
        Catalog = $null
        Built = [ordered]@{}
        Leaves = [System.Collections.Generic.List[object]]::new()
        PqcFallbacks = [System.Collections.Generic.List[object]]::new()
        FipsConfigResolved = $null
    }

    $policies = [System.Collections.Generic.List[object]]::new()
    foreach ($e in (Get-PkiIniEntries -Ini $ini -Section 'custom_policies')) {
        if ($e.Value -ne '') { [void]$policies.Add((ConvertTo-PkiPolicy -Text $e.Value -Label $e.Key)) }
    }
    $script:Pki.CustomPolicies = @($policies)

    Test-PkiConfiguration
    $script:Pki.Naming = Get-PkiNamingConfig
    $script:Pki.Catalog = New-PkiCatalog
    Test-PkiNaming
    Start-PkiTelemetry -OutputDirectory $script:Pki.PkiRoot
    Set-PkiSecretEnvironment -Password $script:Pki.Password
}

function Test-PkiConfiguration {
    $c = $script:Pki
    $errors = [System.Collections.Generic.List[string]]::new()

    # Root-level keys are fixed by policy ($script:PkiRootRsaBits / $script:PkiRootCurve), so only the levels below the roots are checked here (roots: RSA 8192 / ECDSA P-521 / ML-DSA-87).
    if ($c.IntermediatePathLen -notin 0, 1) { [void]$errors.Add("IntermediatePathLen must be 0 or 1 (got $($c.IntermediatePathLen)).") }
    if ($c.QuadrantRsaBits -notin 4096, 8192) { [void]$errors.Add("QuadrantRsaBits must be 4096 or 8192 (got $($c.QuadrantRsaBits)).") }
    if ($c.QuadrantCurve -notin 'P-384', 'P-521') { [void]$errors.Add("QuadrantCurve must be P-384 or P-521 (got $($c.QuadrantCurve)).") }
    if ($c.IntermediateRsaBits -notin 4096, 8192) { [void]$errors.Add("IntermediateRsaBits must be 4096 or 8192 (got $($c.IntermediateRsaBits)).") }
    if ($c.PqcAlgorithm -notmatch '^(?i)ml-?dsa-?(44|65|87)$') { [void]$errors.Add("PqcAlgorithm must be mldsa44, mldsa65 or mldsa87 (got $($c.PqcAlgorithm)).") }
    if ($c.PqcLeafAlgorithm -notmatch '^(?i)ml-?dsa-?(44|65|87)$') { [void]$errors.Add("PqcLeafAlgorithm must be mldsa44, mldsa65 or mldsa87 (got $($c.PqcLeafAlgorithm)).") }
    if ($c.FallbackRsaBits -notin 4096, 8192) { [void]$errors.Add("FallbackRsaBits must be 4096 or 8192 (got $($c.FallbackRsaBits)).") }
    if ($c.IntermediateCurve -notin 'P-256', 'P-384', 'P-521') { [void]$errors.Add("IntermediateCurve must be P-256, P-384 or P-521 (got $($c.IntermediateCurve)).") }

    if (-not ($c.RootYears -gt $c.TrackYears -and $c.TrackYears -gt $c.QuadrantYears -and $c.QuadrantYears -gt $c.IntYears -and $c.IntYears -ge 1)) {
        [void]$errors.Add("Validity must shrink at every level: RootYears ($($c.RootYears)) > TrackYears ($($c.TrackYears)) > QuadrantYears ($($c.QuadrantYears)) > IntYears ($($c.IntYears)) >= 1.")
    }
    if ($c.RootYears -gt 1000) { [void]$errors.Add('RootYears may not exceed 1000.') }
    if ($c.LeafDays -lt 1 -or $c.LeafDays -gt 397) { [void]$errors.Add("EV leaf validity (LeafDays) must be 1..397 days (got $($c.LeafDays)).") }
    if ($c.OvLeafYears -lt 1 -or $c.OvLeafYears -gt 100) { [void]$errors.Add("OvLeafYears must be 1..100 (got $($c.OvLeafYears)).") }
    if ($c.DvLeafYears -lt 1 -or $c.DvLeafYears -gt 100) { [void]$errors.Add("DvLeafYears must be 1..100 (got $($c.DvLeafYears)).") }
    foreach ($lvl in 'EV', 'OV', 'DV') {
        $oid = [string]$script:PkiPolicyOid[$lvl]
        if ([string]::IsNullOrWhiteSpace($oid)) { [void]$errors.Add("The $lvl policy OID is required (agantra_pki.cnf [ policy_oids ] $lvl, or -EvPolicyOid for EV).") }
        elseif ($oid -notmatch '^[0-2](\.(0|[1-9]\d*))+$') { [void]$errors.Add("The $lvl policy OID '$oid' is not a valid OID.") }
    }
    if ($script:PkiPolicyOid.EV -eq $script:PkiPolicyOid.OV -or $script:PkiPolicyOid.EV -eq $script:PkiPolicyOid.DV -or $script:PkiPolicyOid.OV -eq $script:PkiPolicyOid.DV) { [void]$errors.Add('The EV, OV and DV policy OIDs must be different from each other.') }
    if (-not [string]::IsNullOrWhiteSpace($c.IanaPen) -and $c.IanaPen -notmatch '^[1-9]\d{0,9}$') { [void]$errors.Add("IanaPen must be your IANA Private Enterprise Number (a positive integer), got '$($c.IanaPen)'.") }
    if ($c.PenArc -notmatch '^\d+$') { [void]$errors.Add("PenPolicyArc must be a number (got '$($c.PenArc)').") }
    if ($c.TimestampQuadrant -notin 1, 2, 3, 4) { [void]$errors.Add("TimestampQuadrant must be 1, 2, 3 or 4 (got '$($c.TimestampQuadrant)').") }
    if (-not [string]::IsNullOrWhiteSpace($c.TimestampPolicyOid) -and $c.TimestampPolicyOid -notmatch '^[0-2](\.(0|[1-9]\d*))+$') { [void]$errors.Add("TimestampPolicyOid '$($c.TimestampPolicyOid)' is not a valid OID.") }
    if ($c.TimestampDays -lt 1 -or $c.TimestampDays -gt 36500) { [void]$errors.Add("TimestampDays must be 1..36500 (got $($c.TimestampDays)).") }
    if ($c.CrlDays -lt 1 -or $c.CrlDays -gt 3650) { [void]$errors.Add("CrlDays must be 1..3650 (got $($c.CrlDays)).") }
    if ($c.OcspDays -lt 1 -or $c.OcspDays -gt 3650) { [void]$errors.Add("OcspDays must be 1..3650 (got $($c.OcspDays)).") }
    foreach ($s in $c.LeafSizes) {
        if ($s -lt 2048) { [void]$errors.Add("RSA leaf key size $s is rejected: minimum is 2048.") }
    }
    foreach ($q in $c.Quadrants) { if ($q -notin 1, 2, 3, 4) { [void]$errors.Add("Quadrant must be 1, 2, 3 or 4 (got $q).") } }
    if ($c.Quadrants.Count -eq 0) { [void]$errors.Add('At least one quadrant is required.') }
    if ($c.Subject.Country -notmatch '^[A-Z]{2}$') { [void]$errors.Add("Country must be an ISO 3166 alpha-2 code (got '$($c.Subject.Country)').") }
    if ($c.Password.Length -lt 8) { [void]$errors.Add('Password must have at least 8 characters (FIPS PBKDF2 minimum).') }

    # ---- Enterprise Root signed by a public CA ----
    $ext = @($c.EnterpriseRootCsr, [bool]$c.ImportEnterpriseRoot, $c.CrossSignCsr, [bool]$c.ImportCrossCert) | Where-Object { $_ }
    if (@($ext).Count -gt 1) { [void]$errors.Add('Use only one of -EnterpriseRootCsr, -ImportEnterpriseRoot, -CrossSignCsr and -ImportCrossCert at a time.') }
    if ($c.EnterpriseRootKeyBits -notin 4096, 8192) { [void]$errors.Add("EnterpriseRootKeyBits must be 4096 or 8192 (got $($c.EnterpriseRootKeyBits)).") }
    if ($c.EnterpriseRootKeyBits -eq 4096 -and -not ($c.EnterpriseRootCsr -or $c.ImportEnterpriseRoot)) {
        [void]$errors.Add('-EnterpriseRootKeyBits 4096 is only allowed with -EnterpriseRootCsr / -ImportEnterpriseRoot (public CAs rarely accept RSA 8192). A self-signed Enterprise Root is always RSA 8192.')
    }
    if ($c.ExternalChain -ne '' -and -not ($c.ImportEnterpriseRoot -or $c.ImportCrossCert)) { [void]$errors.Add('-ExternalChain is used together with -ImportEnterpriseRoot or -ImportCrossCert.') }
    foreach ($pth in @($c.ImportEnterpriseRoot, $c.ImportCrossCert, $c.ExternalChain)) {
        if ($pth -ne '' -and -not (Test-Path -LiteralPath $pth -PathType Leaf)) { [void]$errors.Add("File not found: $pth") }
    }

    if ($errors.Count -gt 0) {
        throw ("Invalid configuration:`n  - " + ($errors -join "`n  - "))
    }
}
