# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 05_LeafCertificates.ps1
#
# Default EV leaf certificates made by pki_setup.ps1: one per selected
# quadrant, issued by that quadrant's EV intermediate (qN-ev).
#
#   Q1  RSA (default 2048)   Non-FIPS Classic      Q2  ECDSA P-256   FIPS Classic
#   Q3  ML-DSA-65            Non-FIPS Quantum      Q4  ML-DSA-65     FIPS Quantum
#
# Every leaf is EV: EKU serverAuth + clientAuth, policy 2.23.140.1.1 plus
# the custom policies of agantra_pki.cnf, EV subject fields, CRL / OCSP /
# CA Issuers locations, at most 398 days.
#
# GenerateLeafCertificate.ps1 (Phase B) issues every other kind of leaf
# (DV, OV, other EKUs, formats, extra policies).
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PkiSafeFileStem {
    param([Parameter(Mandatory)][string]$Text)
    return (($Text -replace '[^A-Za-z0-9._-]', '_').Trim('_'))
}

function Test-PkiDnsName {
    param([string]$Name)
    $n = $Name
    if ($n.StartsWith('*.')) { $n = $n.Substring(2) }
    return ($n -match '^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')
}

function Get-PkiLeafSan {
    # DNS / IP / e-mail entries from [ leaf_san ]; -Domain replaces the first DNS name.
    $ini = $script:Pki.Ini
    $dns = [System.Collections.Generic.List[string]]::new()
    $ip = [System.Collections.Generic.List[string]]::new()
    $mail = [System.Collections.Generic.List[string]]::new()
    foreach ($e in (Get-PkiIniEntries -Ini $ini -Section 'leaf_san')) {
        if ($e.Value -eq '') { continue }
        if ($e.Key -match '^(?i)DNS(\.\d+)?$') { [void]$dns.Add($e.Value) }
        elseif ($e.Key -match '^(?i)IP(\.\d+)?$') { [void]$ip.Add($e.Value) }
        elseif ($e.Key -match '^(?i)email(\.\d+)?$') { [void]$mail.Add($e.Value) }
    }
    $domain = $script:Pki.Domain
    if (-not [string]::IsNullOrWhiteSpace($domain)) {
        $old = @($dns)
        $dns.Clear()
        [void]$dns.Add($domain)
        if (-not $domain.StartsWith('*.') -and -not $domain.StartsWith('www.')) { [void]$dns.Add("www.$domain") }
        foreach ($d in $old) { if ($dns -notcontains $d -and $d -in @('localhost')) { [void]$dns.Add($d) } }
    }
    foreach ($d in $dns) {
        if (-not (Test-PkiDnsName -Name $d)) { throw "Invalid DNS name in the SAN: '$d'" }
        if ($d.StartsWith('*.')) { Write-PkiLog "Wildcard SAN '$d' is allowed in this private PKI (a public EV certificate may not contain it)." 'WARN' }
    }
    foreach ($a in $ip) {
        $tmp = $null
        if (-not [System.Net.IPAddress]::TryParse($a, [ref]$tmp)) { throw "Invalid IP address in the SAN: '$a'" }
    }
    return [ordered]@{ Dns = @($dns); Ip = @($ip); Email = @($mail) }
}

function Get-PkiLeafSubjectValue {
    # command line (only when passed) > [ subject_ev ] > [ subject_ov ] > default
    param([string]$ParamName, [string]$IniKey, [string]$Default = '')
    $c = $script:Pki
    if (-not [string]::IsNullOrWhiteSpace($ParamName) -and $c.Bound.Contains($ParamName)) { return [string]$c.Bound[$ParamName] }
    $v = Get-PkiIniValue -Ini $c.Ini -Section 'subject_ev' -Key $IniKey -Default ''
    if ($v -eq '') { $v = Get-PkiIniValue -Ini $c.Ini -Section 'subject_ov' -Key $IniKey -Default '' }
    if ($v -eq '') { return $Default }
    return $v
}

function Get-PkiEvLeafDn {
    param($San)
    $c = $script:Pki
    $org = ConvertTo-PkiAscii (Get-PkiLeafSubjectValue 'Organization' 'O' 'Agantra Inovatif OU')
    $cn = if ($San.Dns.Count -gt 0) { $San.Dns[0] } else { $org }

    $pairs = [System.Collections.Generic.List[object]]::new()
    $add = { param($k, $v) if (-not [string]::IsNullOrWhiteSpace($v)) { [void]$pairs.Add(@($k, (ConvertTo-PkiAscii $v))) } }
    & $add 'businessCategory' (Get-PkiLeafSubjectValue 'BusinessCategory' 'businessCategory' 'Private Organization')
    & $add 'jurisdictionCountryName' (Get-PkiLeafSubjectValue 'JurisdictionCountry' 'jurisdictionCountryName' 'EE')
    & $add 'jurisdictionStateOrProvinceName' (Get-PkiLeafSubjectValue 'JurisdictionState' 'jurisdictionStateOrProvinceName' 'Tallinn')
    & $add 'jurisdictionLocalityName' (Get-PkiLeafSubjectValue 'JurisdictionLocality' '' '')
    & $add 'serialNumber' (Get-PkiLeafSubjectValue 'Serial' 'serialNumber' '17344131')
    & $add 'C' (Get-PkiLeafSubjectValue 'Country' 'C' 'EE')
    & $add 'ST' (Get-PkiLeafSubjectValue 'State' 'ST' 'Tallinn')
    & $add 'L' (Get-PkiLeafSubjectValue 'Locality' 'L' 'Tallinn')
    & $add 'street' (Get-PkiLeafSubjectValue 'Street' '' '')
    & $add 'postalCode' (Get-PkiLeafSubjectValue 'PostalCode' 'postalCode' '15199')
    & $add 'O' $org
    & $add 'OU' (Get-PkiLeafSubjectValue 'OrganizationalUnit' 'OU' '')
    $cnIni = Get-PkiIniValue -Ini $c.Ini -Section 'subject_ov' -Key 'CN' -Default ''
    & $add 'CN' $(if ($c.Bound.Contains('Domain')) { $cn } elseif ($cnIni -ne '') { $cnIni } else { $cn })
    # contact fields: the leaf has its own defaults, not the CA's contact
    $cName = if ($c.Bound.Contains('ContactName')) { [string]$c.Bound['ContactName'] } else { Get-PkiIniValue -Ini $c.Ini -Section 'subject_ov' -Key 'ContactName' -Default 'BizDevSecOps Administrator' }
    $cMail = if ($c.Bound.Contains('ContactEmail')) { [string]$c.Bound['ContactEmail'] } else { Get-PkiIniValue -Ini $c.Ini -Section 'subject_ov' -Key 'ContactEmail' -Default 'info@nextmantra.com' }
    $cTel  = if ($c.Bound.Contains('ContactPhone')) { [string]$c.Bound['ContactPhone'] } else { Get-PkiIniValue -Ini $c.Ini -Section 'subject_ov' -Key 'ContactPhone' -Default '(+372)53194019' }
    & $add 'name' $cName
    & $add 'emailAddress' $cMail
    & $add 'telephoneNumber' $cTel
    return $pairs
}

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
                [void]$specs.Add(@{ Quadrant = $q; Ca = $ca; Family = 'pqc'; Bits = 0; Curve = $null; PqcAlg = $alg; Tag = "q$q-$($alg.ToLowerInvariant() -replace '[^a-z0-9]','')" })
            }
        }
    }
    return $specs
}

function New-PkiEvLeaf {
    param([Parameter(Mandatory)][hashtable]$Spec)

    $c = $script:Pki
    $ca = $Spec.Ca
    $cp = Get-PkiCaPaths -Ca $ca
    $fips = [bool]$ca.Fips
    if ($c.LeafDays -gt 398) { throw 'An EV leaf certificate may not be valid longer than 398 days.' }

    $san = Get-PkiLeafSan
    $primary = if ($san.Dns.Count -gt 0) { $san.Dns[0] } else { 'agantra' }
    $stem = "$(Get-PkiSafeFileStem $primary)-$($Spec.Tag)"
    Ensure-PkiDirectory -Path $c.LeafDir
    $key = Join-Path $c.LeafDir "$stem.key"
    $csr = Join-Path $c.LeafDir "$stem.csr"
    $crt = Join-Path $c.LeafDir "$stem.crt"
    $cnf = Join-Path $c.LeafDir "$stem.cnf"
    $full = Join-Path $c.LeafDir "$stem-fullchain.crt"
    $pfx = Join-Path $c.LeafDir "$stem.pfx"
    $pfxFips = Join-Path $c.LeafDir "$stem-fips.pfx"

    Write-PkiLog "Leaf $stem (issuer $($ca.Id))"
    $actual = New-PkiPrivateKey -KeyPath $key -Family $Spec.Family -Bits $Spec.Bits -Curve $Spec.Curve -Fips $fips -Label $stem -PqcAlgorithm $Spec.PqcAlg -FallbackBits $c.FallbackRsaBits
    Write-PkiLog "  Key        : $($actual.Algorithm)$(if ($actual.Fallback) { '  (FALLBACK, not quantum-safe)' })"

    # ---- configuration: [ req ] [ dn ] [ ext ] ----
    $L = [System.Collections.Generic.List[string]]::new()
    foreach ($h in (Get-PkiProviderConfigHeader -Fips $fips)) { [void]$L.Add($h) }
    [void]$L.Add('[ req ]'); [void]$L.Add('prompt = no'); [void]$L.Add('utf8 = yes')
    [void]$L.Add('string_mask = utf8only'); [void]$L.Add('distinguished_name = dn'); [void]$L.Add('')
    [void]$L.Add('[ dn ]')
    foreach ($pair in (Get-PkiEvLeafDn -San $san)) { [void]$L.Add("$($pair[0]) = $(ConvertTo-PkiConfValue $pair[1])") }
    [void]$L.Add('')

    $policies = [System.Collections.Generic.List[object]]::new()
    [void]$policies.Add([ordered]@{ Label = 'EV'; Oid = $script:PkiPolicyOid.EV; Cps = $c.CpsUrl })
    foreach ($p in (Get-PkiExtraPolicies -Level 'EV')) { [void]$policies.Add($p) }
    $policyRefs = Add-PkiPolicySections -Lines $L -Policies $policies -Prefix 'lp'
    $loc = Add-PkiLocationSections -Lines $L -IssuerSlug $ca.Slug -Prefix 'll'

    [void]$L.Add('[ san ]')
    $i = 0; foreach ($d in $san.Dns)   { $i++; [void]$L.Add("DNS.$i = $(ConvertTo-PkiConfValue $d)") }
    $i = 0; foreach ($a in $san.Ip)    { $i++; [void]$L.Add("IP.$i = $a") }
    $i = 0; foreach ($m in $san.Email) { $i++; [void]$L.Add("email.$i = $(ConvertTo-PkiConfValue $m)") }
    [void]$L.Add('')

    $ku = if ($actual.Family -eq 'rsa') { 'critical,digitalSignature,keyEncipherment' } else { 'critical,digitalSignature' }
    [void]$L.Add('[ ext ]')
    [void]$L.Add('basicConstraints = critical,CA:false')
    [void]$L.Add("keyUsage = $ku")
    [void]$L.Add('extendedKeyUsage = serverAuth,clientAuth')
    [void]$L.Add('subjectKeyIdentifier = hash')
    [void]$L.Add('authorityKeyIdentifier = keyid,issuer')
    if ($san.Dns.Count + $san.Ip.Count + $san.Email.Count -gt 0) { [void]$L.Add('subjectAltName = @san') }
    [void]$L.Add("certificatePolicies = $policyRefs")
    if ($loc.Crl) { [void]$L.Add('crlDistributionPoints = @ll_crl') }
    if ($loc.Aia) { [void]$L.Add('authorityInfoAccess = @ll_aia') }
    Write-Utf8NoBom -Path $cnf -Content (($L -join "`n") + "`n")

    # ---- CSR (own key / own provider) ----
    $csrMd = switch ($actual.Family) { 'rsa' { 'sha256' } 'ecdsa' { 'sha384' } default { 'default' } }
    $csrArgs = @('req', '-new', '-key', $key, '-config', $cnf, '-out', $csr)
    $csrArgs += (Get-PkiMdArgs -Md $csrMd)
    $csrArgs += (Get-PkiProviderArgs -Fips $fips)
    [void](Invoke-OpenSSL -Arguments $csrArgs -ConfigPath $cnf)

    # ---- issue (issuer's key / provider / digest) ----
    $md = Get-PkiIssueMd -Kind 'intermediate' -Family $ca.Actual.Family
    $leafDays = [int]$c.LeafDays
    $room = Get-PkiIssuerRemainingDays -IssuerId $ca.Id
    if ($null -ne $room -and $leafDays -gt $room) { Write-PkiLog "  leaf validity limited by its issuer: $leafDays -> $room days" 'WARN'; $leafDays = $room }
    $caArgs = @('ca', '-batch', '-notext', '-utf8', '-preserveDN', '-config', $cp.Cnf, '-in', $csr, '-out', $crt,
                '-extfile', $cnf, '-extensions', 'ext', '-days', [string]$leafDays, '-md', $md)
    $caArgs += (Get-PkiSigOpts -Family $ca.Actual.Family -Md $md)
    $caArgs += (Get-PkiProviderArgs -Fips $fips)
    [void](Invoke-OpenSSL -Arguments $caArgs -ConfigPath $cp.Cnf)
    Assert-PkiFile -Path $crt

    # ---- full chain: leaf + intermediate + quadrant root + track root ----
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append(([System.IO.File]::ReadAllText($crt)).TrimEnd() + "`n")
    $chainOnly = [System.Text.StringBuilder]::new()
    foreach ($anc in @($ca) + @(Get-PkiCaAncestors -Ca $ca)) {
        if ($anc.Kind -eq 'root' -and $null -eq $script:Pki.ExternalRoot) { continue }
        $t = ([System.IO.File]::ReadAllText((Get-PkiCaPaths -Ca $anc).Crt)).TrimEnd() + "`n"
        [void]$sb.Append($t); [void]$chainOnly.Append($t)
    }
    if ($null -ne $script:Pki.ExternalRoot) {
        foreach ($pem in (Get-PkiExternalChainIntermediates)) { [void]$sb.Append($pem.TrimEnd() + "`n"); [void]$chainOnly.Append($pem.TrimEnd() + "`n") }
    }
    Write-Utf8NoBom -Path $full -Content $sb.ToString()
    $chainTmp = Join-Path $c.LeafDir "$stem.chain.tmp"
    Write-Utf8NoBom -Path $chainTmp -Content $chainOnly.ToString()

    $pfxOk = $false
    try {
        New-PkiPfxFile -KeyPath $key -CertPath $crt -PfxPath $pfx -ChainPath $chainTmp -Name $primary -Legacy:$c.LegacyPfx
        $pfxOk = $true
    }
    catch { Write-PkiLog "PFX for $stem was not created: $($_.Exception.Message.Split("`n")[0])" 'WARN' }
    $pfxFipsOk = $false
    if ($fips) {
        try {
            New-PkiPfxFile -KeyPath $key -CertPath $crt -PfxPath $pfxFips -ChainPath $chainTmp -Name $primary -FipsContainer
            $pfxFipsOk = $true
        }
        catch { Write-PkiLog "FIPS-conformant PFX for $stem was not created: $($_.Exception.Message.Split("`n")[0])" 'WARN' }
    }
    Remove-Item -LiteralPath $chainTmp -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $csr -Force -ErrorAction SilentlyContinue

    $fp = Get-PkiCertificateFingerprint -Path $crt
    [void]$c.Leaves.Add([ordered]@{
        name = $stem; quadrant = $Spec.Quadrant; issuer = $ca.Id; fips = $fips
        requestedFamily = $Spec.Family; keyAlgorithm = $actual.Algorithm; pqcFallback = [bool]$actual.Fallback
        validation = 'EV'; days = $leafDays; signatureDigest = $md
        certificate = $crt; key = $key; fullchain = $full; pfx = $(if ($pfxOk) { $pfx } else { $null }); pfxFips = $(if ($pfxFipsOk) { $pfxFips } else { $null })
        sha1 = $fp.Sha1; sha256 = $fp.Sha256
    })
    Write-PkiLog "  Thumbprint : $($fp.Sha1)" 'OK'
}

function New-AllLeafCertificates {
    foreach ($spec in (Get-PkiLeafSpecs)) { New-PkiEvLeaf -Spec $spec }
}
