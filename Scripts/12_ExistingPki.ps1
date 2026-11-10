# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 12_ExistingPki.ps1  -  load a PKI that already exists on disk
#
# Reads pki-manifest.json and rebuilds the in-memory state (catalog, the key each CA really
# has, built certificates, leaves, public-CA information), so a script can work with an existing
# PKI without generating anything:
#     -Verify                      (this generator)
#     GenerateLeafCertificate.ps1  (Phase B: issues leaves from the intermediates)
#     transport / install script   (Phase C: reads thumbprints and files)
#
# Provides : Import-PkiExisting, ConvertTo-PkiActualKey, Repair-PkiRelocatedPaths
# Requires : 00_Common, 01_Configuration (+ Initialize-PkiConfiguration already run),
#            01b_CaNaming, 02_OpenSSL, 03_RuntimeConfig
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-PkiActualKey {
    # "RSA-8192" | "ECDSA-P521" | "ML-DSA-87" -> key description
    param([string]$Algorithm)
    if ($Algorithm -match '^RSA-(\d+)$') { return [ordered]@{ Family = 'rsa'; Bits = [int]$Matches[1]; Curve = $null; Algorithm = $Algorithm; Fallback = $false } }
    if ($Algorithm -match '^ML-DSA-(\d+)$') { return [ordered]@{ Family = 'pqc'; Bits = 0; Curve = $null; Algorithm = $Algorithm; Fallback = $false } }
    if ($Algorithm -match '^ECDSA-P(\d+)$') { return [ordered]@{ Family = 'ecdsa'; Bits = 0; Curve = "P-$($Matches[1])"; Algorithm = $Algorithm; Fallback = $false } }
    throw "Unknown key algorithm in the manifest: '$Algorithm'"
}

function Repair-PkiRelocatedPaths {
    <#
    .SYNOPSIS
        A PKI folder that was renamed or moved (pki-default-01 -> pki-agantra-01, or the whole project to another drive) still has
        the OLD absolute path in the "dir =" line of every CA configuration (<id>.cnf). OpenSSL then looks for the CA key in the
        old folder ("Could not open file or uri for loading CA private key"). The line is always the folder of the file itself,
        so it is set again here. Only that line changes; a file that is right is not touched.
    .OUTPUTS
        the number of configuration files that were corrected.
    #>
    param([Parameter(Mandatory)][string]$PkiRoot)
    $fixed = 0
    foreach ($f in @(Get-ChildItem -LiteralPath $PkiRoot -Recurse -File -Filter '*.cnf' -ErrorAction SilentlyContinue)) {
        $text = [System.IO.File]::ReadAllText($f.FullName)
        if ($text -notmatch '(?m)^\[ CA_default \]\s*$') { continue }
        $want = ConvertTo-PkiConfValue (ConvertTo-PkiConfPath $f.DirectoryName)
        $m = [regex]::Match($text, '(?m)^dir[ \t]*=[ \t]*(.*?)[ \t]*\r?$')
        if (-not $m.Success -or $m.Groups[1].Value -ceq $want) { continue }
        $new = $text.Substring(0, $m.Index) + 'dir             = ' + $want + $text.Substring($m.Index + $m.Length - $(if ($m.Value.EndsWith("`r")) { 1 } else { 0 }))
        $attr = $f.Attributes
        try {
            if ($f.IsReadOnly) { $f.IsReadOnly = $false }
            Write-Utf8NoBom -Path $f.FullName -Content $new
        } finally { try { $f.Attributes = $attr } catch { } }
        $fixed++
    }
    if ($fixed -gt 0) { Write-PkiLog "The PKI folder was renamed or moved: the folder path was corrected in $fixed CA configuration file(s) of $PkiRoot" 'WARN' }
    return $fixed
}

function Import-PkiExisting {
    param([switch]$SkipProviders)   # trust-only scripts need no OpenSSL providers
    <#
    .SYNOPSIS
        Loads the PKI in $script:Pki.PkiRoot into $script:Pki (Quadrants, Catalog with Actual keys,
        Built, Leaves, ExternalRoot) and returns the parsed manifest.
    .DESCRIPTION
        Needs OpenSSL initialised already (Initialize-OpenSSL). Provider configuration files are
        rewritten (the FIPS module is needed when quadrant 2 or 4 exists).
    #>
    $c = $script:Pki
    $manifestPath = Join-Path $c.PkiRoot 'pki-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath)) { throw "No pki-manifest.json in $($c.PkiRoot). Generate a PKI first, or point -PkiRoot at the folder." }
    $m = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -AsHashtable
    if (-not $m.ContainsKey('certificateAuthorities') -or -not $m.ContainsKey('quadrants')) {
        throw 'This manifest was made by an older generator (no certificateAuthorities / quadrants). Regenerate with -Clean.'
    }

    $c.Quadrants = @($m['quadrants'] | ForEach-Object { [int]$_ })
    # release and variant of THIS PKI come from its manifest (names and file stems depend on them); an older manifest = release 1, normal
    $c.Release = $(if ($m.ContainsKey('release') -and [int]$m['release'] -gt 0) { [int]$m['release'] } else { $c.Release })
    $c.NoCaRevocationInfo = $(if ($m.ContainsKey('noCaRevocationInfo')) { [bool]$m['noCaRevocationInfo'] } else { [bool]$c.NoCaRevocationInfo })
    if ($c.Contains('QuantumLabelInUse')) { $c.Remove('QuantumLabelInUse') }
    [void](Repair-PkiRelocatedPaths -PkiRoot $c.PkiRoot)
    $c.Catalog = New-PkiCatalog
    if (-not $SkipProviders) { Initialize-PkiProviderConfigs }

    $c.Built.Clear(); $c.Leaves.Clear()
    foreach ($ca in $c.Catalog) {
        $entry = @($m['certificateAuthorities'] | Where-Object { $_['id'] -eq $ca.Id }) | Select-Object -First 1
        if ($null -eq $entry) { throw "The manifest has no entry for CA '$($ca.Id)'." }
        $ca.Actual = ConvertTo-PkiActualKey -Algorithm $entry['keyAlgorithm']
        $ca.Done = $true
        $h = [ordered]@{}
        foreach ($k in $entry.Keys) { $h[$k] = $entry[$k] }
        $c.Built[$ca.Id] = $h
    }
    foreach ($l in @($m['leaves'])) { [void]$c.Leaves.Add($l) }

    # Enterprise Root signed by a public CA?
    $c.ExternalRoot = $null
    if ($m.ContainsKey('enterpriseRoot') -and $null -ne $m['enterpriseRoot'] -and $m['enterpriseRoot']['externallySigned']) {
        $er = $m['enterpriseRoot']
        $chain = Join-Path $c.PkiRoot 'root\external-chain.pem'
        $c.ExternalRoot = [ordered]@{
            Signed = $true; CaName = [string]$er['externalCa']
            Chain = $(if (Test-Path -LiteralPath $chain) { $chain } else { $null })
            NotAfter = [string]$er['notAfter']
        }
    }
    return $m
}
