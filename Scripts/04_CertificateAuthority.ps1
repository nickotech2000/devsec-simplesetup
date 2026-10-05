# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 04_CertificateAuthority.ps1
#
# Builds the CA hierarchy defined in 01_Configuration.ps1:
#
#   Enterprise Root (self-signed)  1000 years  RSA 8192 / SHA-512  (root key policy: see 01_Configuration.ps1)
#   Track Roots                     500 years  signed by the Enterprise Root
#   Quadrant Roots                  400 years  signed by their Track Root
#   Intermediates (DV/OV/EV)        250 years  signed by their Quadrant Root
#
# Per CA: key -> <id>.cnf -> CSR -> certificate -> PFX -> chain file.
# Every CA keeps its own database (index.txt, serial, crlnumber) so it can
# issue certificates and a CRL.
#
# Length-extension / digest shield (what is enforced, and why):
#   * CA signatures use SHA-512 (roots) or SHA-256/384 (below); SHA-1 and
#     MD5 are rejected by 06_Validation.ps1.
#   * A signature covers the complete DER TBSCertificate, which starts with its
#     own length, so a length-extension attack (a MAC-style attack on
#     H(secret||message)) does not apply to X.509. The shield therefore
#     hardens the parts that do matter: critical basicConstraints with a
#     fixed pathlen at every level, keyCertSign/cRLSign only, 128-bit random
#     serials, restricted key-file ACLs, and optionally -RsaPss (randomized
#     RSASSA-PSS padding with MGF1 over the same digest).
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PkiValidityDays {
    param([Parameter(Mandatory)][ValidateRange(1, 1000)][int]$Years)
    $from = [DateTime]::UtcNow
    return [int][Math]::Floor(($from.AddYears($Years) - $from).TotalDays)
}

# ------------------------------------------------------------
# PEM helpers
# ------------------------------------------------------------
function Get-PkiCaAncestors {
    # Parent first, up to (and including) the Enterprise Root.
    param([Parameter(Mandatory)][hashtable]$Ca)
    $list = [System.Collections.Generic.List[hashtable]]::new()
    $cur = $Ca
    while ($null -ne $cur.Parent) {
        $cur = Get-PkiCa -Id $cur.Parent
        [void]$list.Add($cur)
    }
    return $list
}

function Write-PkiChainFile {
    # Certificate + all issuing CAs. The self-signed Enterprise Root is left out (clients install it).
    # When the Enterprise Root was signed by a public CA it is an ordinary intermediate: it IS included,
    # followed by the public CA intermediates (never the public root, clients already have it).
    param([Parameter(Mandatory)][hashtable]$Ca, [switch]$IncludeRoot)
    $paths = Get-PkiCaPaths -Ca $Ca
    $ext = ($null -ne $script:Pki.ExternalRoot)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append(([System.IO.File]::ReadAllText($paths.Crt)).TrimEnd() + "`n")
    foreach ($anc in (Get-PkiCaAncestors -Ca $Ca)) {
        if ($anc.Kind -eq 'root' -and -not $IncludeRoot -and -not $ext) { continue }
        $ap = Get-PkiCaPaths -Ca $anc
        [void]$sb.Append(([System.IO.File]::ReadAllText($ap.Crt)).TrimEnd() + "`n")
    }
    if ($ext) { foreach ($pem in (Get-PkiExternalChainIntermediates)) { [void]$sb.Append($pem.TrimEnd() + "`n") } }
    Write-Utf8NoBom -Path $paths.Chain -Content $sb.ToString()
}

# ------------------------------------------------------------
# PFX
# ------------------------------------------------------------
function New-PkiPfxFile {
    <#
    .SYNOPSIS
        Writes a PKCS#12 (.pfx) file.
    .DESCRIPTION
        Normal container (default): packaged with the DEFAULT provider (AES-256 + PKCS#12 KDF MAC),
        the form Windows imports. The key itself may come from the FIPS provider: packaging is not a key
        operation, and the FIPS provider has no PKCS#12 KDF.
        -FipsContainer: packaged inside the FIPS provider with PBMAC1 / PBKDF2 (RFC 9579), the
        FIPS-conformant form. Windows may not import it; OpenSSL 3.4+ and Linux tools read it.
    #>
    param(
        [Parameter(Mandatory)][string]$KeyPath,
        [Parameter(Mandatory)][string]$CertPath,
        [Parameter(Mandatory)][string]$PfxPath,
        [string]$ChainPath,
        [string]$Name = 'certificate',
        [switch]$Legacy,
        [switch]$FipsContainer
    )
    $args = @('pkcs12', '-export', '-inkey', $KeyPath, '-in', $CertPath, '-out', $PfxPath,
              '-name', $Name, '-passout', 'env:PKI_PFX_PASSWORD')
    if (-not [string]::IsNullOrWhiteSpace($ChainPath)) { $args += @('-certfile', $ChainPath) }
    if ($Legacy -and -not $FipsContainer) { $args += @('-keypbe', 'PBE-SHA1-3DES', '-certpbe', 'PBE-SHA1-3DES', '-macalg', 'sha1') }
    if ($FipsContainer) { $args += '-pbmac1_pbkdf2' }
    $args += (Get-PkiProviderArgs -Fips ([bool]$FipsContainer))
    [void](Invoke-OpenSSL -Arguments $args -ConfigPath (Get-PkiProviderConfigPath -Fips ([bool]$FipsContainer)))
    Assert-PkiFile -Path $PfxPath
}

# ------------------------------------------------------------
# Build one CA
# ------------------------------------------------------------
function New-PkiCa {
    param([Parameter(Mandatory)][hashtable]$Ca)

    $p = Get-PkiCaPaths -Ca $Ca
    $fips = [bool]$Ca.Fips
    $mode = if ($fips) { 'FIPS' } else { 'non-FIPS' }
    Write-PkiLog "Building $($Ca.Id) [$($Ca.Kind), $mode, requested $($Ca.Family)]"

    Initialize-PkiCaDatabase -Ca $Ca

    # 1. key
    $Ca.Actual = New-PkiPrivateKey -KeyPath $p.Key -Family $Ca.Family -Bits $Ca.Bits -Curve $Ca.Curve -Fips $fips -Label $Ca.Id -PqcAlgorithm $Ca.PqcAlg -FallbackBits $Ca.FallbackBits
    $cn = Get-PkiCaCommonName -Ca $Ca
    Write-PkiLog "  Subject CN : $cn"
    Write-PkiLog "  Key        : $($Ca.Actual.Algorithm)$(if ($Ca.Actual.Fallback) { '  (FALLBACK, not quantum-safe)' })"

    # 2. configuration with the real subject
    [void](Write-PkiCaConfig -Ca $Ca)
    $days = Get-PkiValidityDays -Years $Ca.Years
    $limited = $false
    if ($null -ne $Ca.Parent) {
        # a CA may not outlive its issuer (important when the Enterprise Root comes from a public CA)
        $room = Get-PkiIssuerRemainingDays -IssuerId $Ca.Parent
        if ($null -ne $room -and $days -gt $room) {
            Write-PkiLog "  $($Ca.Id): validity limited by its issuer $($Ca.Parent): $days -> $room days (instead of $($Ca.Years) years)" 'WARN'
            $days = $room; $limited = $true
        }
    }
    $prov = Get-PkiProviderArgs -Fips $fips

    if ($null -eq $Ca.Parent) {
        # Self-signed Enterprise Root
        $md = 'sha512'
        $args = @('req', '-x509', '-new', '-key', $p.Key, '-config', $p.Cnf, '-extensions', 'ext',
                  '-days', [string]$days, '-set_serial', "0x$(New-PkiRandomSerialHex)", '-out', $p.Crt)
        $args += (Get-PkiMdArgs -Md $md)
        $args += (Get-PkiSigOpts -Family $Ca.Actual.Family -Md $md)
        $args += $prov
        [void](Invoke-OpenSSL -Arguments $args -ConfigPath $p.Cnf)
    }
    else {
        # CSR signed by the CA's own key
        $ownMd = Get-PkiOwnMd -Kind $Ca.Kind -Family $Ca.Actual.Family
        $csrArgs = @('req', '-new', '-key', $p.Key, '-config', $p.Cnf, '-out', $p.Csr)
        $csrArgs += (Get-PkiMdArgs -Md $ownMd)
        $csrArgs += $prov
        [void](Invoke-OpenSSL -Arguments $csrArgs -ConfigPath $p.Cnf)

        # The parent signs. Provider, key and digest are the PARENT's.
        $parent = Get-PkiCa -Id $Ca.Parent
        $pp = Get-PkiCaPaths -Ca $parent
        $parentMd = Get-PkiIssueMd -Kind $parent.Kind -Family $parent.Actual.Family
        $caArgs = @('ca', '-batch', '-notext', '-utf8', '-preserveDN', '-config', $pp.Cnf,
                    '-in', $p.Csr, '-out', $p.Crt, '-extfile', $p.Cnf, '-extensions', 'ext',
                    '-days', [string]$days, '-md', $parentMd)
        $caArgs += (Get-PkiSigOpts -Family $parent.Actual.Family -Md $parentMd)
        $caArgs += (Get-PkiProviderArgs -Fips ([bool]$parent.Fips))
        [void](Invoke-OpenSSL -Arguments $caArgs -ConfigPath $pp.Cnf)
        $md = $parentMd
    }
    Assert-PkiFile -Path $p.Crt

    # 3. chain, PFX, fingerprint
    Write-PkiChainFile -Ca $Ca
    try {
        New-PkiPfxFile -KeyPath $p.Key -CertPath $p.Crt -PfxPath $p.Pfx -Name $cn -Legacy:$script:Pki.LegacyPfx
    }
    catch {
        Write-PkiLog "PFX for $($Ca.Id) was not created: $($_.Exception.Message.Split("`n")[0])" 'WARN'
    }
    $fp = Get-PkiCertificateFingerprint -Path $p.Crt
    $notAfter = ''
    try {
        $endText = (Invoke-OpenSSL -ConfigPath (Get-PkiProviderConfigPath -Fips $fips) -Arguments (@('x509', '-in', $p.Crt, '-noout', '-enddate') + $prov)).StdOut.Trim() -replace '^notAfter=', ''
        $notAfter = ([DateTime]::ParseExact(($endText -replace ' GMT', '' -replace '\s+', ' ').Trim(), 'MMM d HH:mm:ss yyyy', [Globalization.CultureInfo]::InvariantCulture)).ToString('yyyy-MM-dd')
    }
    catch { }
    $Ca.Done = $true
    $script:Pki.Built[$Ca.Id] = [ordered]@{
        id = $Ca.Id; kind = $Ca.Kind; commonName = $cn; track = $Ca.Track; quadrant = $Ca.Quadrant
        fips = $fips; validation = $Ca.Validation; generation = $Ca.Gen; parent = $Ca.Parent
        requestedFamily = $Ca.Family; keyAlgorithm = $Ca.Actual.Algorithm; pqcFallback = [bool]$Ca.Actual.Fallback
        signatureDigest = $md; validityYears = $(if ($limited) { [Math]::Round($days / 365.25, 1) } else { $Ca.Years }); pathLen = $Ca.PathLen
        slug = $Ca.Slug; notAfter = $notAfter; certificate = $p.Crt; sha1 = $fp.Sha1; sha256 = $fp.Sha256
        externallySigned = $false; store = $(if ($Ca.Kind -in 'root', 'track', 'quadrant') { 'Root' } else { 'CA' })
    }
    Write-PkiLog "  Thumbprint : $($fp.Sha1)" 'OK'
}

function New-PkiHierarchy {
    foreach ($ca in $script:Pki.Catalog) {
        if ($ca.Kind -eq 'root' -and $null -ne $script:Pki.ExternalRoot) { Use-PkiExternalRoot -Ca $ca }
        else { New-PkiCa -Ca $ca }
    }
}

# ------------------------------------------------------------
# Publish CRLs, CA-issuer files, bundles
# ------------------------------------------------------------
function Publish-PkiCaFiles {
    $pub = $script:Pki.PublishDir
    Ensure-PkiDirectory -Path $pub
    $bundle = [System.Text.StringBuilder]::new()

    foreach ($ca in $script:Pki.Catalog) {
        $p = Get-PkiCaPaths -Ca $ca
        $prov = Get-PkiProviderArgs -Fips ([bool]$ca.Fips)

        # CA-issuer certificate (DER) + PEM
        [void](Invoke-OpenSSL -ConfigPath $p.Cnf -Arguments (@('x509', '-in', $p.Crt, '-outform', 'DER', '-out', (Join-Path $pub "$($ca.Slug).crt")) + $prov))
        Copy-Item -LiteralPath $p.Crt -Destination (Join-Path $pub "$($ca.Slug).pem") -Force
        [void]$bundle.Append(([System.IO.File]::ReadAllText($p.Crt)).TrimEnd() + "`n")

        # CRL (PEM then DER)
        $md = Get-PkiIssueMd -Kind $ca.Kind -Family $ca.Actual.Family
        $crlArgs = @('ca', '-gencrl', '-config', $p.Cnf, '-out', $p.CrlPem, '-md', $md)
        $crlArgs += (Get-PkiSigOpts -Family $ca.Actual.Family -Md $md)
        $crlArgs += $prov
        [void](Invoke-OpenSSL -ConfigPath $p.Cnf -Arguments $crlArgs)
        [void](Invoke-OpenSSL -ConfigPath $p.Cnf -Arguments (@('crl', '-in', $p.CrlPem, '-outform', 'DER', '-out', (Join-Path $pub "$($ca.Slug).crl")) + $prov))
        Copy-Item -LiteralPath $p.CrlPem -Destination (Join-Path $pub "$($ca.Slug).crl.pem") -Force
    }

    Write-Utf8NoBom -Path (Join-Path $pub 'ca-bundle.crt') -Content $bundle.ToString()

    $rootCrt = (Get-PkiCaPaths -Ca (Get-PkiCa -Id 'root')).Crt
    Copy-Item -LiteralPath $rootCrt -Destination (Join-Path $pub 'root.crt') -Force
    if ($null -ne $script:Pki.ExternalRoot -and $script:Pki.ExternalRoot.Chain) {
        Copy-Item -LiteralPath $script:Pki.ExternalRoot.Chain -Destination (Join-Path $pub 'external-chain.pem') -Force
    }

    $readme = @"
PKI publish folder - generated by pki_setup.ps1 $($script:PkiGeneratorVersion)

root.crt          Enterprise Root CA (PEM). Self-signed: install it on every client. Signed by a public CA:
                  it is an intermediate; clients that trust the public root need nothing (see external-chain.pem).
ca-bundle.crt     Every CA certificate (PEM): root, track roots, quadrant roots, intermediates.
<slug>.crt        CA certificate, DER   -> serve at the CA Issuers URLs in agantra_pki.cnf
<slug>.crl        CRL, DER              -> serve at the CRL URLs in agantra_pki.cnf
<slug>.crl.pem    CRL, PEM
<slug>.pem        CA certificate, PEM

The CRL expires after 365 days. Renew it before then, per CA:
  openssl ca -gencrl -config <ca dir>\<id>.cnf -out <id>.crl.pem   (add -provider default, or the FIPS flags)

Lab OCSP responder for one CA (example, Q1 EV intermediate):
  openssl ocsp -index pki\classical\q1\ev\index.txt -port 2560 -rsigner <responder.crt> -rkey <responder.key> -CA pki\classical\q1\ev\q1-ev.crt
"@
    Write-Utf8NoBom -Path (Join-Path $pub 'README.txt') -Content $readme
    Write-PkiLog "Published CRLs and CA files to $pub" 'OK'
}
