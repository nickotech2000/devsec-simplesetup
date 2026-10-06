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
#   |   |- Q1 Root  Non-FIPS  RSA 8192 / SHA-512                              400 y -> q1-dv, q1-ov, q1-ev  250 y  RSA 4096
#   |   `- Q2 Root  FIPS      ECDSA P-521 / SHA-512                           400 y -> q2-dv, q2-ov, q2-ev  250 y  ECDSA P-384
#   `- Quantum Track Root (quantum-root)              ML-DSA-87               500 y
#       |- Q3 Root  Non-FIPS  ML-DSA-87                                       400 y -> q3-dv, q3-ov, q3-ev  250 y  ML-DSA-87
#       `- Q4 Root  FIPS      ML-DSA-87                                       400 y -> q4-dv, q4-ov, q4-ev  250 y  ML-DSA-87
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

$script:PkiGeneratorVersion = '4.9.0-phaseC'

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

# Certificate policy OIDs. Defaults are the CA/Browser Forum OIDs; agantra_pki.cnf
# [ policy_oids ] (and -EvPolicyOid) can replace them. The EV OID is mandatory.
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

    # Q1 / Q3 are non-FIPS, Q2 / Q4 are FIPS. Quantum quadrants (3, 4) are ML-DSA at every level.
    # Root level = enforced root policy. Intermediate level = configurable (below the roots).
    $quadDefs = @(
        @{ N = 1; Track = 'Classic'; Dir = 'classical'; Parent = 'classic-root'; Fips = $false; Gen = $gC
           Root = $rsaRoot; Int = @{ Family = 'rsa';   Bits = $cfg.IntermediateRsaBits; Curve = $null; PqcAlg = $null } }
        @{ N = 2; Track = 'Classic'; Dir = 'classical'; Parent = 'classic-root'; Fips = $true;  Gen = $gC
           Root = $ecRoot;  Int = @{ Family = 'ecdsa'; Bits = 0; Curve = $cfg.IntermediateCurve; PqcAlg = $null } }
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
                Years = $cfg.IntYears; PathLen = 0; Validation = $v; Gen = $q.Gen; Ou = $cfg.OuIntermediate
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
function Get-PkiPenPolicies {
    param([Parameter(Mandatory)][ValidateSet('EV', 'OV', 'DV', 'All')][string]$Level)
    $list = [System.Collections.Generic.List[object]]::new()
    $pen = [string]$script:Pki.IanaPen
    if ([string]::IsNullOrWhiteSpace($pen)) { return $list }
    $arc = "1.3.6.1.4.1.$pen.$($script:Pki.PenArc)"
    [void]$list.Add([ordered]@{ Label = 'PEN'; Oid = $arc; Cps = '' })
    $n = @{ EV = 1; OV = 2; DV = 3 }
    foreach ($l in 'EV', 'OV', 'DV') {
        if ($Level -eq 'All' -or $Level -eq $l) { [void]$list.Add([ordered]@{ Label = "PEN-$l"; Oid = "$arc.$($n[$l])"; Cps = '' }) }
    }
    return $list
}

function Get-PkiExtraPolicies {
    # custom policies of the cnf + PEN policies, without duplicates
    param([Parameter(Mandatory)][ValidateSet('EV', 'OV', 'DV', 'All')][string]$Level)
    $list = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($p in (@($script:Pki.CustomPolicies) + @(Get-PkiPenPolicies -Level $Level))) {
        if ($seen.Add($p.Oid)) { [void]$list.Add($p) }
    }
    return $list
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
        [switch]$VerboseOutput
    )

    # PSBoundParametersDictionary has ContainsKey only; use a plain hashtable.
    $copy = @{}
    foreach ($k in $Bound.Keys) { $copy[$k] = $Bound[$k] }
    $Bound = $copy

    $configPath = Join-Path $ScriptRoot 'agantra_pki.cnf'
    if ($Bound.Contains('ConfigFile') -and -not [string]::IsNullOrWhiteSpace([string]$Bound['ConfigFile'])) {
        $configPath = [string]$Bound['ConfigFile']
        if (-not [System.IO.Path]::IsPathRooted($configPath)) { $configPath = Join-Path (Get-Location).Path $configPath }
    }
    $ini = Read-PkiIni -Path $configPath

    # policy OIDs: command line > [ policy_oids ] > CA/B Forum default
    $script:PkiPolicyOid.EV = Get-PkiIniValue -Ini $ini -Section 'policy_oids' -Key 'EV' -Default '2.23.140.1.1'
    $script:PkiPolicyOid.OV = Get-PkiIniValue -Ini $ini -Section 'policy_oids' -Key 'OV' -Default '2.23.140.1.2.2'
    $script:PkiPolicyOid.DV = Get-PkiIniValue -Ini $ini -Section 'policy_oids' -Key 'DV' -Default '2.23.140.1.2.1'
    if ($Bound.Contains('EvPolicyOid')) { $script:PkiPolicyOid.EV = ([string]$Bound['EvPolicyOid']).Trim() }

    # command line > cnf > default
    $opt = {
        param([string]$Name, [string]$IniKey, $Default)
        if ($Bound.Contains($Name)) { return $Bound[$Name] }
        $v = Get-PkiIniValue -Ini $ini -Section 'pki_settings' -Key $IniKey -Default ''
        if ($v -ne '') { return $v }
        return $Default
    }
    $flag = { param([string]$Name) return ($Bound.Contains($Name) -and [bool]$Bound[$Name]) }

    $pkiRoot = Join-Path $ScriptRoot 'pki'
    if ($Bound.Contains('PkiRoot') -and -not [string]::IsNullOrWhiteSpace([string]$Bound['PkiRoot'])) {
        $pkiRoot = [string]$Bound['PkiRoot']
        if (-not [System.IO.Path]::IsPathRooted($pkiRoot)) { $pkiRoot = Join-Path (Get-Location).Path $pkiRoot }
    }

    $winBuild = Get-PkiWindowsBuild
    $isWin10 = ($null -ne $winBuild -and $winBuild -lt 22000)
    $quadrants = if ($isWin10) { @(1, 2) } else { @(1, 2, 3, 4) }
    if ($Bound.Contains('ClassicPKI') -and [bool]$Bound['ClassicPKI']) {
        if ($Bound.Contains('Quadrant')) { throw '-ClassicPKI builds Enterprise Root, Classic Track Root, Q1 Root and the DV / OV / EV intermediates only. It cannot be combined with -Quadrant.' }
        $quadrants = @(1)
    }
    elseif ($Bound.Contains('Quadrant')) { $quadrants = @($Bound['Quadrant'] | ForEach-Object { [int]$_ } | Sort-Object -Unique) }

    $country = ([string](& $opt 'Country' 'Country' 'EE')).ToUpperInvariant()
    $jur = ([string](& $opt 'JurisdictionCountry' 'JurisdictionCountry' 'EE')).ToUpperInvariant()

    $leafSizes = @(2048)
    if ($Bound.Contains('LeafSizes')) { $leafSizes = @($Bound['LeafSizes'] | ForEach-Object { [int]$_ }) }

    $script:Pki = [ordered]@{
        ScriptRoot = $ScriptRoot
        ConfigPath = $configPath
        Ini        = $ini
        PkiRoot    = $pkiRoot
        PublishDir = Join-Path $pkiRoot 'publish'
        LeafDir    = Join-Path $pkiRoot 'leaf'
        VerboseOutput = [bool]$VerboseOutput
        Bound = $Bound

        # algorithms
        IntermediateRsaBits = [int](& $opt 'IntermediateRsaBits' 'IntermediateRsaBits' 4096)
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
        CpsUrl = [string](& $opt 'CpsUrl' 'CpsUrl' 'https://cps.nextmantra.com/ev_cps.pdf')

        # tooling
        OpenSslPath      = [string]$(if ($Bound.Contains('OpenSslPath')) { $Bound['OpenSslPath'] } else { '' })
        FipsModuleConfig = [string]$(if ($Bound.Contains('FipsModuleConfig')) { $Bound['FipsModuleConfig'] } else { '' })
        OpenSslExe = $null
        OpenSslVersion = $null
        Quadrants = $quadrants
        WindowsBuild = $winBuild
        Windows10 = $isWin10
        QuadrantWasChosen = $Bound.Contains('Quadrant')

        # actions
        Password      = [string]$(if ($Bound.Contains('Password')) { $Bound['Password'] } else { 'Abc12345!' })
        LegacyPfx     = (& $flag 'LegacyPfx')
        InstallTrust  = (& $flag 'InstallTrust')
        Clean         = (& $flag 'Clean')
        RemoveTrust   = (& $flag 'RemoveTrust')
        RemoveAllTrust = (& $flag 'RemoveAllTrust')
        SkipLeaf      = (& $flag 'SkipLeaf')
        UnblockOnly   = (& $flag 'Unblock')
        ShowNamesOnly = (& $flag 'ShowNames')
        ReinstallTrust = (& $flag 'ReinstallTrust')
        ClassicPki    = (& $flag 'ClassicPKI')

        # Enterprise Root signed by a public CA (see PUBLIC-CA-ENTERPRISE-ROOT.txt)
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
    if ($c.IntermediateRsaBits -notin 4096, 8192) { [void]$errors.Add("IntermediateRsaBits must be 4096 or 8192 (got $($c.IntermediateRsaBits)).") }
    if ($c.PqcAlgorithm -notmatch '^(?i)ml-?dsa-?(44|65|87)$') { [void]$errors.Add("PqcAlgorithm must be mldsa44, mldsa65 or mldsa87 (got $($c.PqcAlgorithm)).") }
    if ($c.PqcLeafAlgorithm -notmatch '^(?i)ml-?dsa-?(44|65|87)$') { [void]$errors.Add("PqcLeafAlgorithm must be mldsa44, mldsa65 or mldsa87 (got $($c.PqcLeafAlgorithm)).") }
    if ($c.FallbackRsaBits -notin 4096, 8192) { [void]$errors.Add("FallbackRsaBits must be 4096 or 8192 (got $($c.FallbackRsaBits)).") }
    if ($c.IntermediateCurve -notin 'P-256', 'P-384', 'P-521') { [void]$errors.Add("IntermediateCurve must be P-256, P-384 or P-521 (got $($c.IntermediateCurve)).") }

    if (-not ($c.RootYears -gt $c.TrackYears -and $c.TrackYears -gt $c.QuadrantYears -and $c.QuadrantYears -gt $c.IntYears -and $c.IntYears -ge 1)) {
        [void]$errors.Add("Validity must shrink at every level: RootYears ($($c.RootYears)) > TrackYears ($($c.TrackYears)) > QuadrantYears ($($c.QuadrantYears)) > IntYears ($($c.IntYears)) >= 1.")
    }
    if ($c.RootYears -gt 1000) { [void]$errors.Add('RootYears may not exceed 1000.') }
    if ($c.LeafDays -lt 1 -or $c.LeafDays -gt 398) { [void]$errors.Add("EV leaf validity (LeafDays) must be 1..398 days (got $($c.LeafDays)).") }
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
