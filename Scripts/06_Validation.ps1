# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-OpenSslKey {
    param([Parameter(Mandatory)][string]$Path)
    Invoke-OpenSSL -Arguments @('pkey','-in',$Path,'-check','-noout') | Out-Null
}

function Test-OpenSslCertificate {
    param([Parameter(Mandatory)][string]$Path)
    Invoke-OpenSSL -Arguments @('x509','-in',$Path,'-noout','-subject','-issuer','-dates') | Out-Null
}

function Test-PfxFile {
    param([Parameter(Mandatory)][string]$Path)
    $arguments = @('pkcs12')
    if ($script:Pki.LegacyPfx) { $arguments += '-legacy' }
    $arguments += @('-in', $Path, '-passin', 'env:PKI_PFX_PASSWORD', '-noout')
    Invoke-OpenSSL -Arguments $arguments | Out-Null
}

function Test-PkiChain {
    $p = $script:Pki
    Invoke-OpenSSL -Arguments @('verify','-CAfile',$p.RootCrt,$p.IntermediateCrt) | Out-Null
    foreach ($leaf in $p.LeafFiles) {
        Invoke-OpenSSL -Arguments @('verify','-CAfile',$p.RootCrt,'-untrusted',$p.IntermediateCrt,$leaf.Crt) | Out-Null
    }
}

function Get-CertificateDnsNames {
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $names = [System.Collections.Generic.List[string]]::new()
    try {
        $ext = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
        if ($ext) {
            $san = [System.Security.Cryptography.X509Certificates.X509SubjectAlternativeNameExtension]$ext
            foreach ($dns in $san.EnumerateDnsNames()) { [void]$names.Add($dns) }
        }
    }
    catch { }
    return @($names | Sort-Object -Unique)
}

function ConvertTo-OidDerBytes {
    # DER encoding (tag 0x06 + length + content) of a dotted OID.
    param([Parameter(Mandatory)][string]$Oid)

    $parts = @($Oid.Split('.') | ForEach-Object { [uint64]$_ })
    $content = [System.Collections.Generic.List[byte]]::new()
    [void]$content.Add([byte](40 * $parts[0] + $parts[1]))

    for ($i = 2; $i -lt $parts.Count; $i++) {
        $value = $parts[$i]
        $chunk = [System.Collections.Generic.List[byte]]::new()
        [void]$chunk.Add([byte]($value -band 0x7F))
        $value = $value -shr 7
        while ($value -gt 0) {
            [void]$chunk.Add([byte](($value -band 0x7F) -bor 0x80))
            $value = $value -shr 7
        }
        $chunk.Reverse()
        $content.AddRange($chunk)
    }

    $der = [System.Collections.Generic.List[byte]]::new()
    [void]$der.Add(0x06)
    [void]$der.Add([byte]$content.Count)
    $der.AddRange($content)
    return ,$der.ToArray()
}

function Test-ByteSequence {
    param([byte[]]$Data, [byte[]]$Pattern)

    for ($i = 0; $i -le ($Data.Length - $Pattern.Length); $i++) {
        $match = $true
        for ($j = 0; $j -lt $Pattern.Length; $j++) {
            if ($Data[$i + $j] -ne $Pattern[$j]) { $match = $false; break }
        }
        if ($match) { return $true }
    }

    return $false
}

function Get-CertificateSubjectMap {
    # Subject attributes of a certificate as a name -> value table
    # (OpenSSL long names, e.g. jurisdictionCountryName).
    param([Parameter(Mandatory)][string]$Path)

    $subjectText = Invoke-OpenSSL -Arguments @(
        'x509', '-in', $Path, '-noout', '-subject', '-nameopt', 'multiline,utf8'
    )

    $actual = @{}
    foreach ($line in ($subjectText -split "`r?`n")) {
        if ($line -match '^\s+(\S+)\s*=\s*(.*?)\s*$') { $actual[$Matches[1]] = $Matches[2] }
    }

    return $actual
}

function Test-SubjectFields {
    # Every field from the profile must be present in the certificate subject
    # with the expected value.
    param(
        [Parameter(Mandatory)]$Actual,
        [Parameter(Mandatory)]$Fields,
        [Parameter(Mandatory)]$Problems,
        [string]$Source = 'ev_pki.cnf',
        [switch]$Ascii
    )

    foreach ($field in $Fields) {
        $long = $script:EvDnLongNames[$field.Canonical]
        $found = $null
        foreach ($name in @($long, $field.Key, $field.Canonical)) {
            if (-not [string]::IsNullOrWhiteSpace($name) -and $Actual.ContainsKey($name)) {
                $found = $Actual[$name]; break
            }
        }

        if ($null -eq $found) {
            [void]$Problems.Add("Subject field '$($field.Key)' is missing from the certificate.")
            continue
        }

        # Console decoding can alter non-ASCII text, so only ASCII values are compared exactly.
        $expected = ConvertFrom-OpenSslConfValue -Raw $field.Raw
        if ($Ascii) { $expected = ConvertTo-Ascii -Text $expected }

        if ($expected -match '^[\x20-\x7E]+$' -and $found -ine $expected) {
            [void]$Problems.Add("Subject field '$($field.Key)' is '$found' but $Source expects '$expected'.")
        }
    }
}

function Test-LeafEvCertificate {
    # Confirms a signed leaf really is an EV TLS certificate:
    #   - certificatePolicies carries the EV OID
    #   - every EV subject field from ev_pki.cnf is present
    #     (including OU, L, C and jurisdictionC defaults)
    #   - EKU is exactly serverAuth + clientAuth
    #   - CA:FALSE, SAN lists the common name (wildcards are allowed: lab PKI)
    #   - CRL distribution points and AIA (OCSP + CA Issuers) are present
    #   - validity is at most 398 days
    param([Parameter(Mandatory)]$Leaf)

    $p  = $script:Pki
    $ev = $p.Ev
    $problems = [System.Collections.Generic.List[string]]::new()

    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Leaf.Crt)
    try {
        # --- certificate policies (DER match, independent of text formatting)
        $policyExt = $cert.Extensions |
            Where-Object { $_.Oid.Value -eq '2.5.29.32' } |
            Select-Object -First 1

        if ($null -eq $policyExt) {
            [void]$problems.Add('certificatePolicies extension is missing.')
        }
        elseif (-not (Test-ByteSequence -Data $policyExt.RawData -Pattern (ConvertTo-OidDerBytes -Oid $ev.PolicyOid))) {
            [void]$problems.Add("certificatePolicies does not contain the EV OID $($ev.PolicyOid).")
        }

        # --- EKU: exactly serverAuth + clientAuth
        $ekuExt = $cert.Extensions |
            Where-Object { $_.Oid.Value -eq '2.5.29.37' } |
            Select-Object -First 1

        if ($null -eq $ekuExt) {
            [void]$problems.Add('extendedKeyUsage extension is missing.')
        }
        else {
            $ekuOids = @(
                ([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$ekuExt).EnhancedKeyUsages |
                    ForEach-Object { $_.Value }
            )

            foreach ($needed in @('1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2')) {
                if ($needed -notin $ekuOids) {
                    [void]$problems.Add("extendedKeyUsage is missing $needed (serverAuth = ...3.1, clientAuth = ...3.2).")
                }
            }

            $extra = @($ekuOids | Where-Object { $_ -notin @('1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2') })
            if ($extra.Count -gt 0) {
                [void]$problems.Add("extendedKeyUsage has EKUs an EV TLS certificate may not carry: $($extra -join ', ').")
            }
        }

        # --- validity
        $lifetimeDays = [math]::Ceiling(($cert.NotAfter - $cert.NotBefore).TotalDays)
        if ($lifetimeDays -gt $script:EvMaxLeafDays) {
            [void]$problems.Add("validity is $lifetimeDays days; EV certificates may be valid for at most $($script:EvMaxLeafDays) days.")
        }
    }
    finally { $cert.Dispose() }

    # --- subject fields
    $actual = Get-CertificateSubjectMap -Path $Leaf.Crt
    Test-SubjectFields -Actual $actual -Fields $ev.DnFields -Problems $problems

    # --- extensions
    $text = Invoke-OpenSSL -Arguments @('x509', '-in', $Leaf.Crt, '-noout', '-text')

    if ($text -notmatch 'CA:FALSE') {
        [void]$problems.Add('basicConstraints is not CA:FALSE.')
    }

    if ($text -notmatch 'TLS Web Server Authentication') {
        [void]$problems.Add('extendedKeyUsage does not include serverAuth.')
    }

    if ($text -notmatch 'TLS Web Client Authentication') {
        [void]$problems.Add('extendedKeyUsage does not include clientAuth.')
    }

    if ($text -match 'DNS:\*') {
        Write-PkiLog 'SAN contains a wildcard name: allowed in this private / lab PKI, not EV-compliant for public use.' 'WARN'
    }

    if ($text -notmatch 'CRL Distribution Points' -or $text -notmatch 'Authority Information Access') {
        Write-PkiLog 'The leaf has no CRL Distribution Points / Authority Information Access. Check [ v3_leaf ] in ev_pki.cnf.' 'WARN'
    }
    else {
        foreach ($uri in @($ev.CrlUris) + @($ev.OcspUris) + @($ev.CaIssuerUris)) {
            if ($text -notmatch ('URI:' + [regex]::Escape($uri))) {
                [void]$problems.Add("The certificate does not contain the URI $uri.")
            }
        }
    }

    foreach ($dns in $ev.DnsNames) {
        if ($text -notmatch ('DNS:' + [regex]::Escape($dns) + '(,|\s|$)')) {
            [void]$problems.Add("SAN is missing DNS:$dns.")
        }
    }

    if ($problems.Count -gt 0) {
        throw ("EV verification failed for {0}:`n - {1}" -f $Leaf.Crt, ($problems -join "`n - "))
    }

    Write-PkiLog "EV verified: $([IO.Path]::GetFileName($Leaf.Crt)) (policy $($ev.PolicyOid), EKU serverAuth+clientAuth, OU $(Get-EvDnValue -Fields $ev.DnFields -Canonical 'OU'))" 'OK'
}

function Test-CaEvSubject {
    # Root / Intermediate subject must carry jurisdictionC, serialNumber,
    # locality and the contact fields defined in ev_pki.cnf.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Fields,
        [Parameter(Mandatory)][string]$Name
    )

    $problems = [System.Collections.Generic.List[string]]::new()

    $actual = Get-CertificateSubjectMap -Path $Path
    Test-SubjectFields -Actual $actual -Fields $Fields -Problems $problems -Source 'the CA subject profile' -Ascii

    foreach ($required in @('jurisdictionCountryName', 'serialNumber', 'localityName')) {
        if (-not $actual.ContainsKey($required)) {
            [void]$problems.Add("CA subject is missing $required.")
        }
    }

    if ($problems.Count -gt 0) {
        throw ("{0} subject verification failed for {1}:`n - {2}" -f $Name, $Path, ($problems -join "`n - "))
    }

    Write-PkiLog "$Name subject verified: jurisdictionC=$($actual['jurisdictionCountryName']), serialNumber=$($actual['serialNumber']), L=$($actual['localityName'])" 'OK'
}

function Test-PublishedCaFiles {
    # The CRL must verify against the Intermediate CA, and the CA Issuers
    # file must be the Intermediate certificate itself.
    $p  = $script:Pki
    $ev = $p.Ev

    $crlDer = Join-Path $p.PublishDir $ev.CrlFileName
    $caDer  = Join-Path $p.PublishDir $ev.CaIssuerFileName

    Assert-PkiFile -Path $crlDer
    Assert-PkiFile -Path $caDer

    Invoke-OpenSSL -Arguments @(
        'crl', '-in', $crlDer, '-inform', 'DER', '-CAfile', $p.IntermediateCrt, '-noout'
    ) | Out-Null

    $published = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($caDer)
    $original  = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($p.IntermediateCrt)
    try {
        if ($published.Thumbprint -ne $original.Thumbprint) {
            throw "The published CA Issuers file is not the Intermediate CA certificate: $caDer"
        }
    }
    finally { $published.Dispose(); $original.Dispose() }

    Write-PkiLog "Published CRL verified against the Intermediate CA: $($ev.CrlFileName)" 'OK'
}

function Test-PkiOutputBeforeGeneration {
    $p = $script:Pki
    $artifactPaths = @(
        $p.RootKey, $p.RootPub, $p.RootCrt, $p.RootPfx,
        $p.IntermediateKey, $p.IntermediatePub, $p.IntermediateCsr, $p.IntermediateCrt, $p.IntermediatePfx,
        $p.ManifestFile, $p.RuntimeConfig, $p.LeafReqConfig, $p.RootReqConfig, $p.IntermediateReqConfig, $p.IndexFile, $p.IndexAttrFile, $p.SerialFile, $p.RootSerialFile
    )
    foreach ($leaf in @($p.LeafFiles)) {
        $artifactPaths += @($leaf.Key,$leaf.Pub,$leaf.Csr,$leaf.Crt,$leaf.Pfx,$leaf.FullChain)
    }
    $existing = @($artifactPaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    if ($existing.Count -gt 0) {
        throw "Existing PKI artifact was found. Use -Clean before generating a new PKI. First existing file: $($existing[0])"
    }
}

function Write-PkiManifest {
    $p = $script:Pki
    $root = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($p.RootCrt)
    $intermediate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($p.IntermediateCrt)
    try {
        $manifest = [ordered]@{
            schemaVersion = 1
            generatedAtUtc = (Get-PkiNowUtc).ToString('o')
            domain = $p.Domain
            organization = $p.Organization
            country = $p.Country
            root = [ordered]@{ thumbprint = $root.Thumbprint; subject = $root.Subject; path = $p.RootCrt }
            intermediate = [ordered]@{ thumbprint = $intermediate.Thumbprint; subject = $intermediate.Subject; path = $p.IntermediateCrt }
            ev = [ordered]@{
                policyOid            = $p.Ev.PolicyOid
                businessCategory     = (Get-EvDnValue -Fields $p.Ev.DnFields -Canonical 'businessCategory')
                jurisdictionCountry  = (Get-EvDnValue -Fields $p.Ev.DnFields -Canonical 'jurisdictionC')
                serialNumber         = (Get-EvDnValue -Fields $p.Ev.DnFields -Canonical 'serialNumber')
                locality             = (Get-EvDnValue -Fields $p.Ev.DnFields -Canonical 'L')
                organizationalUnit   = (Get-EvDnValue -Fields $p.Ev.DnFields -Canonical 'OU')
                eku                  = @('serverAuth', 'clientAuth')
                maxLeafDays          = $script:EvMaxLeafDays
                dnsNames             = @($p.Ev.DnsNames)
            }
            leaf = @()
        }
        $leafList = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $p.LeafFiles) {
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($item.Crt)
            try {
                [void]$leafList.Add([ordered]@{ ev = $true; bits = $item.Bits; thumbprint = $cert.Thumbprint; subject = $cert.Subject; path = $item.Crt })
            }
            finally { $cert.Dispose() }
        }
        $manifest.leaf = @($leafList)
        $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $p.ManifestFile -Encoding utf8NoBOM
    }
    finally {
        $root.Dispose()
        $intermediate.Dispose()
    }
}

function Validate-AllPkiArtifacts {
    $p = $script:Pki
    foreach ($key in @($p.RootKey,$p.IntermediateKey)) { Assert-PkiFile $key; Test-OpenSslKey $key }
    foreach ($cert in @($p.RootCrt,$p.IntermediateCrt)) { Assert-PkiFile $cert; Test-OpenSslCertificate $cert }
    foreach ($pfx in @($p.RootPfx,$p.IntermediatePfx)) { Assert-PkiFile $pfx; Test-PfxFile $pfx }
    Test-CaEvSubject -Path $p.RootCrt -Fields $p.Ev.RootDnFields -Name 'Root CA'
    Test-CaEvSubject -Path $p.IntermediateCrt -Fields $p.Ev.IntermediateDnFields -Name 'Intermediate CA'
    Test-PublishedCaFiles
    foreach ($leaf in $p.LeafFiles) {
        foreach ($path in @($leaf.Key,$leaf.Pub,$leaf.Csr,$leaf.Crt,$leaf.Pfx,$leaf.FullChain)) { Assert-PkiFile $path }
        Test-OpenSslKey $leaf.Key
        Test-OpenSslCertificate $leaf.Crt
        Test-LeafEvCertificate -Leaf $leaf
        Test-PfxFile $leaf.Pfx
    }
    Test-PkiChain
    Write-PkiManifest
}