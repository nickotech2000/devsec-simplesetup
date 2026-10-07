# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 05_LeafCertificates.ps1
#
# The DEFAULT EV leaf certificates made by pki_setup.ps1: one per selected quadrant, issued by that
# quadrant's EV intermediate (qN-ev).
#
#   Q1  RSA (default 2048)   Non-FIPS Classic      Q2  ECDSA P-256   FIPS Classic
#   3   ML-DSA-65            Non-FIPS Quantum      4   ML-DSA-65     FIPS Quantum   (named Quantum Q1 / Q2)
#
# The work is done by the SAME generator that GenerateLeafCertificate.ps1 uses
# (14_LeafGenerator.ps1: New-PkiLeafSpec / New-PkiLeafCertificate). This file only decides WHICH default
# leaves exist and keeps their Phase A file names (<name>-<tag>.* in pki\leaf, e.g. nextmantra.com-q1-rsa2048).
# Every other leaf (DV, OV, other purposes, formats, names): GenerateLeafCertificate.ps1.
#
# Provides : Get-PkiLeafSpecs, New-PkiEvLeaf, New-AllLeafCertificates
# Requires : 14_LeafGenerator
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PkiLeafSpecs {
    # One spec per default leaf certificate.
    $c = $script:Pki
    $specs = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($q in $c.Quadrants) {
        $ca = Get-PkiCa -Id "q$q-ev"
        switch ($q) {
            1 { foreach ($bits in $c.LeafSizes) { [void]$specs.Add(@{ Quadrant = 1; Ca = $ca; Family = 'rsa'; Bits = $bits; Curve = $null; PqcAlg = $null; Tag = "q1-rsa$bits" }) } }
            2 { [void]$specs.Add(@{ Quadrant = 2; Ca = $ca; Family = 'ecdsa'; Bits = 0; Curve = 'P-256'; PqcAlg = $null; Tag = 'q2-ecdsa-p256' }) }
            default {
                $alg = $c.PqcLeafAlgorithm
                [void]$specs.Add(@{ Quadrant = $q; Ca = $ca; Family = 'pqc'; Bits = 0; Curve = $null; PqcAlg = $alg; Tag = "q$(Get-PkiNamingQuadrant -Ca $ca)-$($alg.ToLowerInvariant() -replace '[^a-z0-9]','')" })
            }
        }
    }
    return $specs
}

function New-PkiEvLeaf {
    param([Parameter(Mandatory)][hashtable]$Spec)
    $c = $script:Pki
    if ($c.LeafDays -gt 398) { throw 'An EV leaf certificate may not be valid longer than 398 days.' }

    $keyType = switch ($Spec.Family) { 'rsa' { 'RSA' } 'ecdsa' { 'ECDSA' } default { 'MLDSA' } }
    $s = New-PkiLeafSpec -Options @{
        Level = 'EV'; Quadrant = $Spec.Quadrant; KeyType = $keyType; KeyBits = $Spec.Bits; Curve = $Spec.Curve
        PqcAlgorithm = $Spec.PqcAlg; Days = $c.LeafDays; Format = @('PFX')
    }
    $s.Stem = "$(ConvertTo-PkiSafeName $s.Primary)-$($Spec.Tag)"      # Phase A name: <name>-<tag>
    Ensure-PkiDirectory -Path $c.LeafDir
    $s.OutDir = $c.LeafDir
    $r = New-PkiLeafCertificate -Spec $s

    [void]$c.Leaves.Add([ordered]@{
        name = $r.Stem; quadrant = $Spec.Quadrant; issuer = $s.Ca.Id; fips = [bool]$s.Fips
        requestedFamily = $Spec.Family; keyAlgorithm = $r.Actual.Algorithm; pqcFallback = [bool]$r.Actual.Fallback
        validation = 'EV'; days = $r.Days; signatureDigest = $r.Md
        certificate = $r.Crt; key = $r.Key; fullchain = $r.Full; pfx = $r.Pfx; pfxFips = $r.PfxFips
        sha1 = $r.Sha1; sha256 = $r.Sha256
    })
}

function New-AllLeafCertificates {
    foreach ($spec in (Get-PkiLeafSpecs)) { New-PkiEvLeaf -Spec $spec }
}
