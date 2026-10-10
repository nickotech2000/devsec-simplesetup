# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 06_Validation.ps1
#
# Checks every generated CA and leaf, then writes pki-manifest.json.
#
#   CA     : CA:TRUE + pathlen, keyCertSign/cRLSign, signature digest allow-list
#            (no SHA-1 / MD5; SHA-512 for every root-level CA; ML-DSA below an ML-DSA
#            issuer), root key policy (RSA 8192 | ECDSA P-521 | ML-DSA-87), RSA floor 3072 below the roots,
#            private key matches certificate, policy OIDs,
#            chain verifies up to the Enterprise Root (-x509_strict)
#   Leaf   : EKU serverAuth+clientAuth, CA:FALSE, EV policy, validity <= 398 days,
#            RSA >= 2048, chain verifies, key matches
#   PFX    : opens with the configured password
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PkiCertText {
    param([string]$Path, [bool]$Fips = $false)
    $r = Invoke-OpenSSL -ConfigPath (Get-PkiProviderConfigPath -Fips $Fips) -Arguments (@('x509', '-in', $Path, '-noout', '-text') + (Get-PkiProviderArgs -Fips $Fips))
    return $r.StdOut
}

function Get-PkiPublicKeyPem {
    param([string]$Path, [string]$Kind, [bool]$Fips)   # Kind: cert | key | pub
    $prov = Get-PkiProviderArgs -Fips $Fips
    $cnf = Get-PkiProviderConfigPath -Fips $Fips
    if ($Kind -eq 'cert') {
        $r = Invoke-OpenSSL -ConfigPath $cnf -Arguments (@('x509', '-in', $Path, '-noout', '-pubkey') + $prov)
    }
    elseif ($Kind -eq 'pub') {
        $r = Invoke-OpenSSL -ConfigPath $cnf -Arguments (@('pkey', '-pubin', '-in', $Path, '-pubout') + $prov)
    }
    else {
        $r = Invoke-OpenSSL -ConfigPath $cnf -Arguments (@('pkey', '-in', $Path, '-pubout') + $prov)
    }
    return (($r.StdOut -replace '\s', ''))
}

function Assert-PkiSignatureDigest {
    # Digest allow-list ("shield"): never SHA-1/MD5; SHA-512 for root-level CAs.
    # -ExpectPqc: the ISSUER is a post-quantum CA, so the certificate must carry an ML-DSA signature
    # (a pure signature, no external digest). The reverse is rejected too.
    param([string]$Text, [string]$Kind, [string]$Id, [bool]$ExpectPqc = $false)
    if ($Text -notmatch '(?m)^\s*Signature Algorithm:\s*(?<alg>\S+)') { throw "[$Id] cannot read the signature algorithm." }
    $alg = $Matches['alg']
    if ($alg -match '(?i)md5|sha1(?!\d)|sha-1') { throw "[$Id] signature algorithm $alg is rejected (SHA-1 / MD5)." }
    if ($ExpectPqc) {
        if ($alg -notmatch '(?i)ML-?DSA') { throw "[$Id] its issuer is a post-quantum CA, so it must carry an ML-DSA signature (found $alg)." }
        return $alg
    }
    if ($alg -match '(?i)ML-?DSA|SLH-DSA') { throw "[$Id] unexpected post-quantum signature ($alg): its issuer is a classical CA." }
    if ($alg -match '(?i)rsassaPss|RSASSA-PSS') {
        # The digest of a PSS signature is in its parameters, not in the algorithm name.
        if ($Text -notmatch '(?m)^\s*Hash Algorithm:\s*(?<h>\S+)') { throw "[$Id] cannot read the RSASSA-PSS hash algorithm." }
        $alg = "rsassaPss-$($Matches['h'])"
    }
    if ($Kind -in 'root', 'track', 'quadrant') {
        if ($alg -notmatch '(?i)sha512') { throw "[$Id] root-level certificates must be signed with SHA-512 (found $alg)." }
    }
    elseif ($alg -notmatch '(?i)sha(256|384|512)') {
        throw "[$Id] weak or unknown signature algorithm $alg."
    }
    return $alg
}

function Test-PkiIssuerIsPqc {
    param([hashtable]$Ca)
    if ($null -eq $Ca.Parent) { return $false }
    return ((Get-PkiCa -Id $Ca.Parent).Actual.Family -eq 'pqc')
}

function Test-PkiCaCertificate {
    param([Parameter(Mandatory)][hashtable]$Ca)
    $p = Get-PkiCaPaths -Ca $Ca
    $fips = [bool]$Ca.Fips
    $t = Get-PkiCertText -Path $p.Crt -Fips $fips
    # Enterprise Root signed by a public CA: the CA decides pathlen, digest, policies and validity.
    $extRoot = ($Ca.Kind -eq 'root' -and $null -ne $script:Pki.ExternalRoot)

    if ($t -notmatch 'CA:TRUE') { throw "[$($Ca.Id)] basicConstraints CA:TRUE is missing." }
    if ($extRoot) {
        if ($t -match 'pathlen:(?<n>\d+)' -and [int]$Matches['n'] -lt $Ca.PathLen) { throw "[$($Ca.Id)] the public CA allows pathlen $($Matches['n']) but this PKI needs at least $($Ca.PathLen)." }
    }
    elseif ($t -notmatch "pathlen:$($Ca.PathLen)(?!\d)") { throw "[$($Ca.Id)] pathlen:$($Ca.PathLen) is missing." }
    if ($t -notmatch 'Certificate Sign' -or $t -notmatch 'CRL Sign') { throw "[$($Ca.Id)] keyUsage keyCertSign/cRLSign is missing." }
    if ($t -notmatch '(?s)Basic Constraints:\s*critical') { throw "[$($Ca.Id)] basicConstraints is not critical." }

    if ($extRoot) {
        $sigAlg = if ($t -match '(?m)^\s*Signature Algorithm:\s*(?<alg>\S+)') { $Matches['alg'] } else { 'unknown' }
        if ($sigAlg -match '(?i)md5|sha1(?!\d)') { throw "[$($Ca.Id)] the public CA signed the Enterprise Root with $sigAlg (SHA-1 / MD5): rejected." }
    }
    else { $sigAlg = Assert-PkiSignatureDigest -Text $t -Kind $Ca.Kind -Id $Ca.Id -ExpectPqc (Test-PkiIssuerIsPqc -Ca $Ca) }

    $rootLevel = $Ca.Kind -in 'root', 'track', 'quadrant'
    switch ($Ca.Actual.Family) {
        'rsa' {
            if ($t -match 'Public-Key:\s*\((?<bits>\d+) bit\)') {
                $bits = [int]$Matches['bits']
                $floor = if ($extRoot) { 4096 } elseif ($rootLevel) { $script:PkiRootRsaBits } else { 3072 }
                if ($bits -lt $floor) { throw "[$($Ca.Id)] RSA key $bits bits is below the $floor bit minimum for this level." }
            }
        }
        'ecdsa' {
            if ($rootLevel -and $t -notmatch 'P-521|secp521r1') { throw "[$($Ca.Id)] root-level ECDSA keys must use P-521 (the strongest NIST curve)." }
        }
        'pqc' {
            if ($rootLevel -and $t -notmatch '(?i)ML-?DSA-?87') { throw "[$($Ca.Id)] root-level post-quantum keys must be ML-DSA-87 (the highest parameter set)." }
        }
    }

    if (-not $extRoot) {
        foreach ($pol in (Get-PkiCaPolicies -Ca $Ca)) {
            # OpenSSL prints anyPolicy (2.5.29.32.0) as "Any Policy", every other policy as its number
            $found = if ($pol.Oid -eq $script:PkiAnyPolicyOid) { $t -match '(?i)Any Policy|2\.5\.29\.32\.0' } else { $t -match [regex]::Escape($pol.Oid) }
            if (-not $found) { throw "[$($Ca.Id)] policy $($pol.Oid) ($($pol.Label)) is missing." }
        }
        if ($Ca.Kind -eq 'root' -or $Ca.Kind -eq 'track') {
            # The Enterprise Root and the Track Roots carry All issuance policies + EV and NOTHING else.
            foreach ($lvl in 'OV', 'DV') { if ($t -match [regex]::Escape($script:PkiPolicyOid[$lvl])) { throw "[$($Ca.Id)] carries the $lvl policy $($script:PkiPolicyOid[$lvl]): the Enterprise Root and the Track Roots carry only All issuance policies + EV." } }
            if (-not [string]::IsNullOrWhiteSpace([string]$script:Pki.IanaPen) -and $t -match [regex]::Escape("1.3.6.1.4.1.$($script:Pki.IanaPen).")) { throw "[$($Ca.Id)] carries a PEN policy: the PEN policies start at the Quadrant Roots." }
        }
    }

    $a = Get-PkiPublicKeyPem -Path $p.Crt -Kind cert -Fips $fips
    $b = Get-PkiPublicKeyPem -Path $p.Key -Kind key -Fips $fips
    if ($a -ne $b) { throw "[$($Ca.Id)] private key does not match the certificate." }

    return $sigAlg
}

function Test-PkiCaChain {
    param([Parameter(Mandatory)][hashtable]$Ca)
    $p = Get-PkiCaPaths -Ca $Ca
    $fips = [bool]$Ca.Fips
    $anchor = Get-PkiTrustAnchor
    # -x509_strict is for chains made entirely by this PKI; a public CA's certificates are checked normally
    $args = @('verify'); if ($anchor.RootIsAnchor) { $args += '-x509_strict' }
    $args += @('-CAfile', $anchor.Anchor)
    $untrusted = @(Get-PkiCaAncestors -Ca $Ca | Where-Object { -not $anchor.RootIsAnchor -or $_.Kind -ne 'root' })
    $tmp = $null
    if ($untrusted.Count -gt 0) {
        $tmp = Join-Path $script:Pki.PkiRoot "$($Ca.Id).untrusted.tmp"
        $sb = [System.Text.StringBuilder]::new()
        foreach ($u in $untrusted) { [void]$sb.Append(([System.IO.File]::ReadAllText((Get-PkiCaPaths -Ca $u).Crt)).TrimEnd() + "`n") }
        Write-Utf8NoBom -Path $tmp -Content $sb.ToString()
        $args += @('-untrusted', $tmp)
    }
    $args += (Get-PkiProviderArgs -Fips $fips)
    $args += $p.Crt          # certificate files must come last for 'openssl verify'
    try { [void](Invoke-OpenSSL -Arguments $args -ConfigPath (Get-PkiProviderConfigPath -Fips $fips)) }
    finally { if ($tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } }
}

function Test-PkiLeaf {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Leaf)
    $ca = Get-PkiCa -Id $Leaf.issuer
    $fips = [bool]$Leaf.fips
    $t = Get-PkiCertText -Path $Leaf.certificate -Fips $fips
    $id = $Leaf.name

    if ($t -notmatch 'CA:FALSE') { throw "[$id] CA:FALSE is missing." }
    if ($t -notmatch 'TLS Web Server Authentication' -or $t -notmatch 'TLS Web Client Authentication') { throw "[$id] EKU must be serverAuth + clientAuth." }
    if ($t -notmatch [regex]::Escape($script:PkiPolicyOid.EV)) { throw "[$id] EV policy OID is missing." }
    foreach ($cp in (Get-PkiExtraPolicies -Level 'EV')) { if ($t -notmatch [regex]::Escape($cp.Oid)) { throw "[$id] custom policy $($cp.Oid) is missing." } }
    [void](Assert-PkiSignatureDigest -Text $t -Kind 'leaf' -Id $id -ExpectPqc ($ca.Actual.Family -eq 'pqc'))

    if ($t -match 'Not Before:\s*(?<a>.+?)\r?\n\s*Not After\s*:\s*(?<b>.+?)\r?\n') {
        $fmt = 'MMM d HH:mm:ss yyyy'
        $inv = [Globalization.CultureInfo]::InvariantCulture
        $nb = [DateTime]::ParseExact((($Matches['a'] -replace ' GMT', '') -replace '\s+', ' ').Trim(), $fmt, $inv)
        $na = [DateTime]::ParseExact((($Matches['b'] -replace ' GMT', '') -replace '\s+', ' ').Trim(), $fmt, $inv)
        if (($na - $nb).TotalDays -gt 398.5) { throw "[$id] validity exceeds 398 days." }
    }
    if ($Leaf.keyAlgorithm -like 'RSA-*') {
        if ([int]($Leaf.keyAlgorithm -replace 'RSA-', '') -lt 2048) { throw "[$id] RSA key below 2048 bits." }
    }

    $a = Get-PkiPublicKeyPem -Path $Leaf.certificate -Kind cert -Fips $fips
    $b = Get-PkiPublicKeyPem -Path $Leaf.key -Kind key -Fips $fips
    if ($a -ne $b) { throw "[$id] private key does not match the certificate." }

    # chain: leaf -> intermediate -> quadrant root -> track root -> Enterprise Root
    $anchor = Get-PkiTrustAnchor
    $args = @('verify'); if ($anchor.RootIsAnchor) { $args += '-x509_strict' }
    $args += @('-purpose', 'sslserver', '-CAfile', $anchor.Anchor)
    $tmp = Join-Path $script:Pki.PkiRoot "$id.untrusted.tmp"
    $sb = [System.Text.StringBuilder]::new()
    foreach ($anc in (@($ca) + @(Get-PkiCaAncestors -Ca $ca))) {
        if ($anc.Kind -eq 'root' -and $anchor.RootIsAnchor) { continue }
        [void]$sb.Append(([System.IO.File]::ReadAllText((Get-PkiCaPaths -Ca $anc).Crt)).TrimEnd() + "`n")
    }
    Write-Utf8NoBom -Path $tmp -Content $sb.ToString()
    try {
        [void](Invoke-OpenSSL -ConfigPath (Get-PkiProviderConfigPath -Fips $fips) -Arguments ($args + @('-untrusted', $tmp) + (Get-PkiProviderArgs -Fips $fips) + @($Leaf.certificate)))
    }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }

    if ($Leaf.Contains('pfxFips') -and $Leaf.pfxFips) {
        [void](Invoke-OpenSSL -ConfigPath (Get-PkiProviderConfigPath -Fips $true) -Arguments (@('pkcs12', '-in', $Leaf.pfxFips, '-noout', '-passin', 'env:PKI_PFX_PASSWORD') + (Get-PkiProviderArgs -Fips $true)))
    }
    if ($Leaf.pfx) {
        # the importable container is packaged with the default provider (see New-PkiPfxFile)
        [void](Invoke-OpenSSL -ConfigPath (Get-PkiProviderConfigPath -Fips $false) -Arguments (@('pkcs12', '-in', $Leaf.pfx, '-noout', '-passin', 'env:PKI_PFX_PASSWORD') + (Get-PkiProviderArgs -Fips $false)))
    }
}

function Test-PkiOutputBeforeGeneration {
    $rootCrt = Join-Path $script:Pki.PkiRoot 'root\root.crt'
    if (Test-Path -LiteralPath $rootCrt) {
        throw "A PKI already exists in $($script:Pki.PkiRoot).`nUse -Clean to remove it first (and its Windows trust), or pki_reuse.ps1 to adopt it."
    }
}

function Write-PkiManifest {
    $c = $script:Pki
    $manifest = [ordered]@{
        schemaVersion = 2
        generator = "pki_setup.ps1 $($script:PkiGeneratorVersion)"
        generatedAtUtc = [DateTime]::UtcNow.ToString('o')
        openssl = $c.OpenSslVersion
        providers = [ordered]@{ nonFips = 'default'; fips = 'fips+base'; engineApi = 'not used'; oqsprovider = 'not used' }
        configFile = $c.ConfigPath
        mode = $(if ($c.ClassicPki) { 'ClassicPKI' } else { 'Full' })
        quadrants = @($c.Quadrants)
        enterpriseRoot = [ordered]@{
            externallySigned = ($null -ne $c.ExternalRoot)
            externalCa = $(if ($null -ne $c.ExternalRoot) { $c.ExternalRoot.CaName } else { $null })
            issuer = $(if ($null -ne $c.ExternalRoot) { $c.ExternalRoot.Issuer } else { $null })
            notAfter = $(if ($null -ne $c.ExternalRoot) { $c.ExternalRoot.NotAfter } else { $null })
            chain = $(if ($null -ne $c.ExternalRoot) { $c.ExternalRoot.Chain } else { $null })
            crossCertificates = @()
        }
        naming = [ordered]@{ prefix = $c.Naming.Prefix; quantumLabel = $c.Naming.QuantumLabel; templates = $c.Naming.Templates }
        rsaPss = $c.RsaPss
        pqcAlgorithmRequested = $c.PqcAlgorithm
        pqcLeafAlgorithm = $c.PqcLeafAlgorithm
        pqcFallbackEnabled = $c.PqcFallback
        pqcFallbackCount = $c.PqcFallbacks.Count
        pqcFallbacks = @($c.PqcFallbacks)
        policyOids = [ordered]@{ ev = $script:PkiPolicyOid.EV; ov = $script:PkiPolicyOid.OV; dv = $script:PkiPolicyOid.DV }
        ianaPen = $(if ([string]::IsNullOrWhiteSpace($c.IanaPen)) { $null } else { $c.IanaPen })
        leafValidity = [ordered]@{ evDays = $c.LeafDays; ovYears = $c.OvLeafYears; dvYears = $c.DvLeafYears }
        customPolicies = @($c.CustomPolicies | ForEach-Object { [ordered]@{ label = $_.Label; oid = $_.Oid; cps = $_.Cps } })
        certificateAuthorities = @($c.Built.Values)
        leaves = @($c.Leaves)
    }
    $path = Join-Path $c.PkiRoot 'pki-manifest.json'
    Write-Utf8NoBom -Path $path -Content ($manifest | ConvertTo-Json -Depth 8)
    Write-PkiLog "Manifest: $path"
}

function Test-AllPkiArtifacts {
    param([switch]$NoManifest)   # -Verify checks only: do not rewrite the manifest
    foreach ($ca in $script:Pki.Catalog) {
        $sig = Test-PkiCaCertificate -Ca $ca
        Test-PkiCaChain -Ca $ca
        Write-PkiLog "  OK $($ca.Id.PadRight(13)) $($script:Pki.Built[$ca.Id].keyAlgorithm.PadRight(11)) $sig" 'OK'
    }
    foreach ($leaf in $script:Pki.Leaves) {
        Test-PkiLeaf -Leaf $leaf
        Write-PkiLog "  OK leaf $($leaf.name) ($($leaf.keyAlgorithm))" 'OK'
    }
    if (-not $NoManifest) { Write-PkiManifest }
}
