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
#   {N}             quadrant number                    1 .. 4
#   {Level}         intermediate level                 DV | OV | EV
#   {Algorithm}     key algorithm of the CA            RSA-4096 | ECDSA-P384 FIPS | ML-DSA-87 ...
#   {Track}         Classic | Quantum | Enterprise
#   {Id}            catalog id                         root, classic-root, q1-root, q3-ev ...
#
# RULES enforced at start (the script stops with the reason when one fails):
#   * a common name may not be longer than 64 characters (X.520)
#   * every CA must have a different common name (Windows builds chains by name)
#   * only these tokens; no empty result
#
# Preview without generating anything:   .\pki_setup.ps1 -ShowNames
#
# Provides : Get-PkiNamingConfig, Get-PkiCaCommonName, Get-PkiCaSlug, Get-PkiAlgorithmLabel,
#            Test-PkiNaming, Show-PkiCaNames, Expand-PkiNameTemplate
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
        GenEnterprise = $d.GenEnterprise; GenClassic = $d.GenClassic; GenQuantum = $d.GenQuantum
        Templates = [ordered]@{}
    }
    foreach ($k in $d.Templates.Keys) { $n.Templates[$k] = $d.Templates[$k] }

    $ini = $script:Pki.Ini
    $legacy = Get-PkiIniValue -Ini $ini -Section 'pki_settings' -Key 'CaNamePrefix' -Default ''
    if ($legacy -ne '') { $n.Prefix = $legacy }
    $legacy = Get-PkiIniValue -Ini $ini -Section 'pki_settings' -Key 'QuantumLabel' -Default ''
    if ($legacy -ne '') { $n.QuantumLabel = $legacy }

    foreach ($k in 'Prefix', 'QuantumLabel', 'SlugPrefix', 'GenEnterprise', 'GenClassic', 'GenQuantum') {
        $v = Get-PkiIniValue -Ini $ini -Section 'ca_names' -Key $k -Default ''
        if ($v -ne '') { $n[$k] = $v }
    }
    foreach ($k in @($n.Templates.Keys)) {
        $v = Get-PkiIniValue -Ini $ini -Section 'ca_names' -Key $k -Default ''
        if ($v -ne '') { $n.Templates[$k] = $v }
    }
    foreach ($k in 'Prefix', 'QuantumLabel') { $n[$k] = ConvertTo-PkiAscii $n[$k] }
    return $n
}

function Expand-PkiNameTemplate {
    param([Parameter(Mandatory)][string]$Template, [Parameter(Mandatory)][hashtable]$Tokens)
    $evaluator = [System.Text.RegularExpressions.MatchEvaluator] {
        param($m)
        $k = $m.Groups['k'].Value
        if (-not $Tokens.ContainsKey($k)) {
            throw "Unknown token {$k} in the name template '$Template'. Allowed tokens: $(($script:PkiNamingTokens | ForEach-Object { "{$_}" }) -join ' ')"
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

function Get-PkiCaCommonName {
    param([Parameter(Mandatory)][hashtable]$Ca)
    $n = $script:Pki.Naming
    $key = switch ($Ca.Kind) {
        'root'         { 'EnterpriseRoot' }
        'track'        { if ($Ca.Track -eq 'Classic') { 'ClassicTrackRoot' } else { 'QuantumTrackRoot' } }
        'quadrant'     { if ($Ca.Track -eq 'Classic') { 'ClassicQuadrantRoot' } else { 'QuantumQuadrantRoot' } }
        'intermediate' { 'Intermediate' }
    }
    $tokens = @{
        Prefix = $n.Prefix; QuantumLabel = $n.QuantumLabel; Gen = $Ca.Gen
        N = [string]$Ca.Quadrant; Level = [string]$Ca.Validation
        Algorithm = (Get-PkiAlgorithmLabel -Ca $Ca); Track = $Ca.Track; Id = $Ca.Id
    }
    return (ConvertTo-PkiAscii (Expand-PkiNameTemplate -Template $n.Templates[$key] -Tokens $tokens))
}

function Get-PkiCaSlug {
    # File-name stem: agantra-q1-ev-g1, agantra-enterprise-root-g1 ...
    param([Parameter(Mandatory)][hashtable]$Ca)
    $name = if ($Ca.Kind -eq 'root') { 'enterprise-root' } else { $Ca.Id }
    return "$($script:Pki.Naming.SlugPrefix)-$name-$($Ca.Gen.ToLowerInvariant())".ToLowerInvariant()
}

function Test-PkiNaming {
    # Called at start with the planned catalog.
    $problems = [System.Collections.Generic.List[string]]::new()
    $seen = @{}
    foreach ($ca in $script:Pki.Catalog) {
        try { $cn = Get-PkiCaCommonName -Ca $ca }
        catch { [void]$problems.Add("$($ca.Id): $($_.Exception.Message)"); continue }
        if ([string]::IsNullOrWhiteSpace($cn)) { [void]$problems.Add("$($ca.Id): the common name is empty"); continue }
        if ($cn.Length -gt 64) { [void]$problems.Add("$($ca.Id): the common name '$cn' has $($cn.Length) characters (maximum 64)") }
        $k = $cn.ToLowerInvariant()
        if ($seen.ContainsKey($k)) { [void]$problems.Add("$($ca.Id) and $($seen[$k]) have the same common name '$cn'") } else { $seen[$k] = $ca.Id }
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
    Write-Host "Prefix '$($n.Prefix)'   QuantumLabel '$($n.QuantumLabel)'   SlugPrefix '$($n.SlugPrefix)'   Generations $($n.GenEnterprise) / $($n.GenClassic) / $($n.GenQuantum)"
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
}
