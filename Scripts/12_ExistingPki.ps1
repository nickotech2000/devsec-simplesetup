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
# Provides : Import-PkiExisting, ConvertTo-PkiActualKey
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
