# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 01b_CaNaming.ps1  -  NAMING CONFIGURATION of all roots and intermediates
#
# Everything that decides what a CA is CALLED lives here:
#   * the common name (CN) template of every kind of CA
#   * the company prefix, the word for the Quantum track, the generation labels
#   * the file-name stem ("slug") used in the CRL / CA-issuer URLs and in pki\publish
#
# The values below are the DEFAULTS. Change them in either place:
#   1. agantra_pki.cnf, section [ ca_names ]   (recommended: no script change, keeps your update safe)
#   2. this file, $script:PkiNamingDefaults     (edit the default itself)
# Precedence:  [ ca_names ] in agantra_pki.cnf  >  this file
#
# TOKENS usable in a template (case-sensitive, in braces):
#   {Prefix}        company prefix                     Agantra Inovatif
#   {QuantumLabel}  word for the Quantum track         PQC-PostQuantum
#   {Gen}           generation label of the CA         G1 (Enterprise, Classic)  G2 (Quantum)
#   {N}             quadrant number IN NAMES           1 = non-FIPS, 2 = FIPS  (both tracks; the Quantum quadrants 3 / 4 are
#                                                      called Q1 / Q2 too: the track label and {Gen} tell them apart)
#   {Level}         intermediate level                 DV | OV | EV
#   {Algorithm}     key algorithm of the CA            RSA-4096 | ECDSA-P384 FIPS | ML-DSA-87 ...
#   {Track}         Classic | Quantum | Enterprise
#   {Id}            catalog id (INTERNAL)              root, classic-root, q1-root, q3-ev ...   (still q1 .. q4)
#
# RULES enforced at start (the script stops with the reason when one fails):
#   * a common name may not be longer than 64 characters (X.520)
#   * every CA must have a different common name (Windows builds chains by name)
#   * only these tokens; no empty result
#
# Preview without generating anything:   .\pki_setup.ps1 -ShowNames
#
# LEAF CERTIFICATES (GenerateLeafCertificate.ps1) use the same module. Their names are configurable in
# agantra_pki.cnf [ leaf_names ] (defaults below, $script:PkiLeafNamingDefaults):
#   OutputFolder  folder of ALL leaf folders: a name = next to the scripts, NOT in pki   leafcerts
#                 (an absolute path is used as it is; -OutputRoot overrides it)
#   Folder        name of the folder of ONE leaf                              {Name}
#   Stem          file-name stem of the files in it                           {Name}-{Level}-{Tag}
#   UniqueSuffix  added to Folder when that folder already exists             _{Date}-{Time}
#   PurposeFolder folder of ONE purpose inside a set (one certificate per EKU)  {PurposeName}
#   PurposeStem   file-name stem inside a set                                   {Name}-{Purpose}-{Level}-{Tag}
# Tokens: {Name} {Level} {Quadrant} {Tag} {Algorithm} {Track} {Fips} {Purpose} {PurposeName} {Date} {Time}
# If the folder exists, a NEW folder with the date and time is created; nothing is overwritten.
#
# Provides : Get-PkiNamingConfig, Get-PkiCaCommonName, Get-PkiCaSlug, Get-PkiAlgorithmLabel,
#            Test-PkiNaming, Show-PkiCaNames, Expand-PkiNameTemplate,
#            Get-PkiLeafNamingConfig, Get-PkiLeafNames, Get-PkiLeafRoot, New-PkiUniqueFolder, Test-PkiLeafNaming,
#            ConvertTo-PkiSafeName
# Requires : 00_Common (Write-PkiLog), 01_Configuration ($script:Pki, Get-PkiIniValue, ConvertTo-PkiAscii)
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# DEFAULTS  (edit here or override in agantra_pki.cnf [ ca_names ])
# ------------------------------------------------------------
$script:PkiNamingDefaults = [ordered]@{
    Prefix        = 'Agantra Inovatif'
    QuantumLabel  = 'PQC-PostQuantum'
    SlugPrefix    = 'agantra'
    NoCrLabel     = '(NoCR)'          # added to every CA name of a PKI made with -NoCaRevocationInfo
    ReleaseLabel  = 'R{N}'            # added from release 2 on:  R2, R3 ...   ({N} = the release number)
    QuantumLabelShort = 'PQC'         # replaces QuantumLabel in ALL names of a PKI when a name would be longer than 64 characters (NoCR + R2 ...)
    GenEnterprise = 'G1'
    GenClassic    = 'G1'
    GenQuantum    = 'G2'
    Templates     = [ordered]@{
        EnterpriseRoot      = '{Prefix} Enterprise Root CA {Gen}'
        ClassicTrackRoot    = '{Prefix} Enterprise Classic Root CA {Gen}'
        QuantumTrackRoot    = '{Prefix} Enterprise {QuantumLabel} Root CA {Gen}'
        ClassicQuadrantRoot = '{Prefix} Enterprise Classic Q{N} Root CA {Gen}'
        QuantumQuadrantRoot = '{Prefix} Enterprise {QuantumLabel} Q{N} Root CA {Gen}'
        Intermediate        = '{Prefix} {Level} {Algorithm} {Gen} CA'
    }
}

$script:PkiNamingTokens = @('Prefix', 'QuantumLabel', 'Gen', 'N', 'Level', 'Algorithm', 'Track', 'Id')

function Get-PkiNamingConfig {
    # defaults < legacy keys of [ pki_settings ] < [ ca_names ]
    $d = $script:PkiNamingDefaults
    $n = [ordered]@{
        Prefix = $d.Prefix; QuantumLabel = $d.QuantumLabel; SlugPrefix = $d.SlugPrefix
        NoCrLabel = $d.NoCrLabel; ReleaseLabel = $d.ReleaseLabel; QuantumLabelShort = $d.QuantumLabelShort
        GenEnterprise = $d.GenEnterprise; GenClassic = $d.GenClassic; GenQuantum = $d.GenQuantum
        Templates = [ordered]@{}
    }
    foreach ($k in $d.Templates.Keys) { $n.Templates[$k] = $d.Templates[$k] }

    $ini = $script:Pki.Ini
    $legacy = Get-PkiIniValue -Ini $ini -Section 'pki_settings' -Key 'CaNamePrefix' -Default ''
    if ($legacy -ne '') { $n.Prefix = $legacy }
    $legacy = Get-PkiIniValue -Ini $ini -Section 'pki_settings' -Key 'QuantumLabel' -Default ''
    if ($legacy -ne '') { $n.QuantumLabel = $legacy }

    foreach ($k in 'Prefix', 'QuantumLabel', 'SlugPrefix', 'NoCrLabel', 'ReleaseLabel', 'QuantumLabelShort', 'GenEnterprise', 'GenClassic', 'GenQuantum') {
        $v = Get-PkiIniValue -Ini $ini -Section 'ca_names' -Key $k -Default ''
        if ($v -ne '') { $n[$k] = $v }
    }
    foreach ($k in @($n.Templates.Keys)) {
        $v = Get-PkiIniValue -Ini $ini -Section 'ca_names' -Key $k -Default ''
        if ($v -ne '') { $n.Templates[$k] = $v }
    }
    foreach ($k in 'Prefix', 'QuantumLabel', 'QuantumLabelShort', 'NoCrLabel') { $n[$k] = ConvertTo-PkiAscii $n[$k] }
    return $n
}

function Expand-PkiNameTemplate {
    param([Parameter(Mandatory)][string]$Template, [Parameter(Mandatory)][hashtable]$Tokens, [string[]]$Allowed = $script:PkiNamingTokens)
    $evaluator = [System.Text.RegularExpressions.MatchEvaluator] {
        param($m)
        $k = $m.Groups['k'].Value
        if (-not $Tokens.ContainsKey($k)) {
            throw "Unknown token {$k} in the name template '$Template'. Allowed tokens: $(($Allowed | ForEach-Object { "{$_}" }) -join ' ')"
        }
        return [string]$Tokens[$k]
    }
    $r = [regex]::Replace($Template, '\{(?<k>[A-Za-z]+)\}', $evaluator)
    return (($r -replace '\s+', ' ').Trim())
}

function Get-PkiAlgorithmLabel {
    # The key that really exists (Actual) or, before generation, the planned one.
    param([Parameter(Mandatory)][hashtable]$Ca)
    $label = if ($null -ne $Ca.Actual) { $Ca.Actual.Algorithm }
             else {
                 switch ($Ca.Family) {
                     'rsa'   { "RSA-$($Ca.Bits)" }
                     'ecdsa' { "ECDSA-$($Ca.Curve -replace '-','')" }
                     'pqc'   { Get-PkiPqcDisplayName $Ca.PqcAlg }
                 }
             }
    if ($Ca.Fips) { $label += ' FIPS' }
    return $label
}

function Get-PkiNamingQuadrant {
    # The number a quadrant carries in NAMES (common name, file-name stem): 1 = non-FIPS, 2 = FIPS, in both tracks.
    # The internal quadrant number (1 .. 4: -Quadrant, catalog ids, folders) is unchanged. 0 = not a quadrant CA.
    param([Parameter(Mandatory)][hashtable]$Ca)
    if ([int]$Ca.Quadrant -le 0) { return 0 }
    if ($Ca.Fips) { return 2 } else { return 1 }
}

function Get-PkiNameSuffix {
    # " (NoCR) R2" - what the variant and the release add to every CA name. Release 1 of the normal PKI adds nothing.
    $c = $script:Pki; $n = $c.Naming
    $parts = [System.Collections.Generic.List[string]]::new()
    if ($c.Contains('NoCaRevocationInfo') -and [bool]$c.NoCaRevocationInfo) { [void]$parts.Add([string]$n.NoCrLabel) }
    if ($c.Contains('Release') -and [int]$c.Release -gt 1) { [void]$parts.Add((([string]$n.ReleaseLabel) -replace '\{N\}', [string][int]$c.Release)) }
    if ($parts.Count -eq 0) { return '' }
    return (' ' + ($parts -join ' '))
}

function Get-PkiCaNameBase {
    # the name from the template, WITHOUT suffix, with the given quantum label
    param([Parameter(Mandatory)][hashtable]$Ca, [Parameter(Mandatory)][string]$QuantumLabel)
    $n = $script:Pki.Naming
    $key = switch ($Ca.Kind) {
        'root'         { 'EnterpriseRoot' }
        'track'        { if ($Ca.Track -eq 'Classic') { 'ClassicTrackRoot' } else { 'QuantumTrackRoot' } }
        'quadrant'     { if ($Ca.Track -eq 'Classic') { 'ClassicQuadrantRoot' } else { 'QuantumQuadrantRoot' } }
        'intermediate' { 'Intermediate' }
    }
    $tokens = @{
        Prefix = $n.Prefix; QuantumLabel = $QuantumLabel; Gen = $Ca.Gen
        N = [string](Get-PkiNamingQuadrant -Ca $Ca); Level = [string]$Ca.Validation
        Algorithm = (Get-PkiAlgorithmLabel -Ca $Ca); Track = $Ca.Track; Id = $Ca.Id
    }
    return (ConvertTo-PkiAscii (Expand-PkiNameTemplate -Template $n.Templates[$key] -Tokens $tokens))
}

function Get-PkiQuantumLabelInUse {
    # The Quantum label of THIS PKI. A common name may have 64 characters at most: when the suffix (NoCR, R2 ...) makes one longer,
    # the short label (PQC) is used in ALL names of the PKI, so that they stay alike.
    $c = $script:Pki; $n = $c.Naming
    if ($c.Contains('QuantumLabelInUse') -and $c.QuantumLabelInUse) { return [string]$c.QuantumLabelInUse }
    $label = [string]$n.QuantumLabel
    if ($null -ne $c.Catalog -and $n.QuantumLabelShort -and $n.QuantumLabelShort -ne $n.QuantumLabel) {
        $suffix = Get-PkiNameSuffix
        foreach ($ca in $c.Catalog) {
            try { if ((Get-PkiCaNameBase -Ca $ca -QuantumLabel $n.QuantumLabel).Length + $suffix.Length -gt 64) { $label = [string]$n.QuantumLabelShort; break } } catch { }
        }
        $c['QuantumLabelInUse'] = $label
    }
    return $label
}

function Get-PkiCaCommonName {
    param([Parameter(Mandatory)][hashtable]$Ca)
    return ((Get-PkiCaNameBase -Ca $Ca -QuantumLabel (Get-PkiQuantumLabelInUse)) + (Get-PkiNameSuffix))
}

function Get-PkiCaSlug {
    # File-name stem: agantra-q1-ev-g1, agantra-enterprise-root-g1 ...   (NoCR: ...-g1-nocr, release 2: ...-g1-r2, both: ...-g1-nocr-r2)
    param([Parameter(Mandatory)][hashtable]$Ca)
    $name = if ($Ca.Kind -eq 'root') { 'enterprise-root' } else { $Ca.Id }
    if ([int]$Ca.Quadrant -gt 0) { $name = $name -replace '^q\d+', ('q' + (Get-PkiNamingQuadrant -Ca $Ca)) }    # q3-ev -> q1-ev, q4-ev -> q2-ev (the generation tells the tracks apart)
    $slug = "$($script:Pki.Naming.SlugPrefix)-$name-$($Ca.Gen.ToLowerInvariant())".ToLowerInvariant()
    # the variant and the release are part of the file stem (CRL / CA-issuer URLs): all PKIs can be served by one server
    if ($script:Pki.Contains('NoCaRevocationInfo') -and [bool]$script:Pki.NoCaRevocationInfo) { $slug += '-nocr' }
    if ($script:Pki.Contains('Release') -and [int]$script:Pki.Release -gt 1) { $slug += "-r$([int]$script:Pki.Release)" }
    return $slug
}

function Test-PkiNaming {
    # Called at start with the planned catalog.
    $problems = [System.Collections.Generic.List[string]]::new()
    $seen = @{}
    $seenSlug = @{}
    foreach ($ca in $script:Pki.Catalog) {
        try { $cn = Get-PkiCaCommonName -Ca $ca }
        catch { [void]$problems.Add("$($ca.Id): $($_.Exception.Message)"); continue }
        if ([string]::IsNullOrWhiteSpace($cn)) { [void]$problems.Add("$($ca.Id): the common name is empty"); continue }
        if ($cn.Length -gt 64) { [void]$problems.Add("$($ca.Id): the common name '$cn' has $($cn.Length) characters (maximum 64)") }
        $k = $cn.ToLowerInvariant()
        if ($seen.ContainsKey($k)) { [void]$problems.Add("$($ca.Id) and $($seen[$k]) have the same common name '$cn'") } else { $seen[$k] = $ca.Id }
        if ($seenSlug.ContainsKey($ca.Slug)) { [void]$problems.Add("$($ca.Id) and $($seenSlug[$ca.Slug]) have the same file-name stem '$($ca.Slug)': Quadrants 1 and 3 (and 2 and 4) are both called Q1 (Q2), so GenClassic and GenQuantum must differ") } else { $seenSlug[$ca.Slug] = $ca.Id }
        if ($ca.Slug -notmatch '^[a-z0-9][a-z0-9-]*$') { [void]$problems.Add("$($ca.Id): the file-name stem '$($ca.Slug)' may only contain a-z, 0-9 and '-' (check SlugPrefix and the generation labels)") }
    }
    if ($problems.Count -gt 0) {
        throw ("Invalid CA naming (agantra_pki.cnf [ ca_names ] / 01b_CaNaming.ps1):`n  - " + ($problems -join "`n  - "))
    }
}

function Show-PkiCaNames {
    # .\pki_setup.ps1 -ShowNames
    $n = $script:Pki.Naming
    Write-Host ''
    Write-Host 'CA NAMING  (defaults: scripts\01b_CaNaming.ps1, overrides: agantra_pki.cnf [ ca_names ])' -ForegroundColor Cyan
    Write-Host "Prefix '$($n.Prefix)'   QuantumLabel '$($n.QuantumLabel)' (short '$($n.QuantumLabelShort)')   SlugPrefix '$($n.SlugPrefix)'   Generations $($n.GenEnterprise) / $($n.GenClassic) / $($n.GenQuantum)"
    Write-Host "PKI shown     : release R$([int]$script:Pki.Release)$(if ($script:Pki.NoCaRevocationInfo) { ', variant NoCR' })   suffix '$((Get-PkiNameSuffix).Trim())'   (NoCrLabel '$($n.NoCrLabel)', ReleaseLabel '$($n.ReleaseLabel)')   Quantum label in use: '$(Get-PkiQuantumLabelInUse)'   folder: $($script:Pki.PkiRoot)"
    Write-Host ''
    Write-Host 'TEMPLATES' -ForegroundColor Cyan
    foreach ($k in $n.Templates.Keys) { Write-Host ('  {0,-20} {1}' -f $k, $n.Templates[$k]) }
    Write-Host ''
    Write-Host ('{0,-13} {1,-13} {2,-58} {3,3}  {4}' -f 'ID', 'KIND', 'COMMON NAME', 'LEN', 'FILE STEM / OU') -ForegroundColor Cyan
    foreach ($ca in $script:Pki.Catalog) {
        $cn = Get-PkiCaCommonName -Ca $ca
        Write-Host ('{0,-13} {1,-13} {2,-58} {3,3}  {4}  /  {5}' -f $ca.Id, $ca.Kind, $cn, $cn.Length, $ca.Slug, $ca.Ou)
    }
    Write-Host ''
    Write-Host 'Intermediate names show the PLANNED algorithm; after generation they show the key that really exists.'
    Write-Host 'Quadrant numbers in names: Q1 = non-FIPS, Q2 = FIPS, in both tracks (ID column: the internal quadrant ids q1 .. q4 are unchanged).'
}

# ============================================================
# LEAF NAMING  (GenerateLeafCertificate.ps1)
# ============================================================
$script:PkiLeafNamingDefaults = [ordered]@{
    OutputFolder  = 'leafcerts'
    Folder        = '{Name}'
    Stem          = '{Name}-{Level}-{Tag}'
    UniqueSuffix  = '_{Date}-{Time}'
    PurposeFolder = '{PurposeName}'
    PurposeStem   = '{Name}-{Purpose}-{Level}-{Tag}'
}
$script:PkiLeafNamingTokens = @('Name', 'Level', 'Quadrant', 'Tag', 'Algorithm', 'Track', 'Fips', 'Purpose', 'PurposeName', 'Date', 'Time')

function ConvertTo-PkiSafeName {
    # File / folder name: letters, digits, . _ -  ("*.example.com" becomes "wildcard.example.com")
    param([Parameter(Mandatory)][string]$Text)
    $t = $Text -replace '^\*\.', 'wildcard.'
    $t = ($t -replace '[^A-Za-z0-9._-]', '_').Trim('_', '.')
    if ([string]::IsNullOrWhiteSpace($t)) { return 'leaf' }
    return $t
}

function Get-PkiLeafNamingConfig {
    # defaults < [ leaf_names ] in agantra_pki.cnf
    $d = $script:PkiLeafNamingDefaults
    $n = [ordered]@{}
    foreach ($k in $d.Keys) { $n[$k] = $d[$k] }
    foreach ($k in @($n.Keys)) {
        $v = Get-PkiIniValue -Ini $script:Pki.Ini -Section 'leaf_names' -Key $k -Default ''
        if ($v -ne '') { $n[$k] = $v }
    }
    return $n
}

function Get-PkiLeafNames {
    # -> @{ Folder; Stem; PurposeFolder; PurposeStem; OutputFolder; UniqueSuffix } from the templates.
    # $Tokens: Name Level Quadrant Tag Algorithm Track Fips Purpose PurposeName Date Time
    param([Parameter(Mandatory)][hashtable]$Tokens)
    $n = Get-PkiLeafNamingConfig
    $ex = { param($t) ConvertTo-PkiSafeName (Expand-PkiNameTemplate -Template $t -Tokens $Tokens -Allowed $script:PkiLeafNamingTokens) }
    return [ordered]@{
        Folder = (& $ex $n.Folder); Stem = (& $ex $n.Stem)
        PurposeFolder = (& $ex $n.PurposeFolder); PurposeStem = (& $ex $n.PurposeStem)
        OutputFolder = $n.OutputFolder; UniqueSuffix = $n.UniqueSuffix
    }
}

function Get-PkiLeafRoot {
    <#
    .SYNOPSIS
        The folder that receives ALL leaf folders: <script folder>\leafcerts (NOT inside pki).
        Order: -OutputRoot > [ leaf_names ] OutputFolder (a name is relative to the script folder, a full path is used as it is).
    #>
    $c = $script:Pki
    if ($c.Contains('Bound') -and $c.Bound.Contains('OutputRoot') -and -not [string]::IsNullOrWhiteSpace([string]$c.Bound['OutputRoot'])) {
        return [System.IO.Path]::GetFullPath([string]$c.Bound['OutputRoot'])
    }
    $f = (Get-PkiLeafNamingConfig).OutputFolder
    if ([System.IO.Path]::IsPathRooted($f)) { return $f }
    $base = if ($c.Contains('ScriptRoot') -and $c.ScriptRoot) { $c.ScriptRoot } else { (Get-Location).Path }
    return (Join-Path $base $f)
}

function New-PkiUniqueFolder {
    <#
    .SYNOPSIS
        Creates <Root>\<Name>. If it exists already, creates <Root>\<Name><UniqueSuffix> (date and time) instead,
        and -N when even that exists. Nothing existing is touched.
    .OUTPUTS
        @{ Path; Name; Renamed; Existing }
    #>
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Name, [string]$SuffixTemplate = '_{Date}-{Time}')
    Ensure-PkiDirectory -Path $Root
    $path = Join-Path $Root $Name
    if (-not (Test-Path -LiteralPath $path)) {
        [void][System.IO.Directory]::CreateDirectory($path)
        return [ordered]@{ Path = $path; Name = $Name; Renamed = $false; Existing = $null }
    }
    $now = Get-Date
    $suffix = Expand-PkiNameTemplate -Template $SuffixTemplate -Tokens @{ Date = $now.ToString('yyyyMMdd'); Time = $now.ToString('HHmmss') } -Allowed @('Date', 'Time')
    $candidate = ConvertTo-PkiSafeName ($Name + $suffix)
    $final = $candidate; $i = 1
    while (Test-Path -LiteralPath (Join-Path $Root $final)) { $i++; $final = "$candidate-$i" }
    $np = Join-Path $Root $final
    [void][System.IO.Directory]::CreateDirectory($np)
    return [ordered]@{ Path = $np; Name = $final; Renamed = $true; Existing = $path }
}

function Test-PkiLeafNaming {
    # Called at start: the templates must produce valid folder and file names.
    $sample = @{ Name = 'example.com'; Level = 'ev'; Quadrant = 'q1'; Tag = 'q1-rsa2048'; Algorithm = 'RSA-2048'; Track = 'classic'; Fips = 'nonfips'; Purpose = 'server'; PurposeName = 'serverauth'; Date = '20260101'; Time = '120000' }
    $n = Get-PkiLeafNamingConfig
    $problems = [System.Collections.Generic.List[string]]::new()
    try {
        $r = Get-PkiLeafNames -Tokens $sample
        foreach ($k in 'Folder', 'Stem', 'PurposeFolder', 'PurposeStem') {
            if ($r[$k].Length -gt 100) { [void]$problems.Add("$k '$($r[$k])' is longer than 100 characters") }
            if ($r[$k] -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { [void]$problems.Add("$k '$($r[$k])' is not a valid name") }
        }
        [void](Expand-PkiNameTemplate -Template $n.UniqueSuffix -Tokens @{ Date = '20260101'; Time = '120000' } -Allowed @('Date', 'Time'))
    }
    catch { [void]$problems.Add($_.Exception.Message) }
    if ($n.OutputFolder -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { [void]$problems.Add("OutputFolder '$($n.OutputFolder)' is not a valid folder name") }
    if ($problems.Count -gt 0) { throw ("Invalid leaf naming (agantra_pki.cnf [ leaf_names ] / 01b_CaNaming.ps1):`n  - " + ($problems -join "`n  - ")) }
}
