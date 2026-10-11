# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 13_ExternalRoot.ps1  -  Enterprise Root signed by a public CA (DigiCert, GlobalSign, Sectigo ...)
#
# Full explanation, requirements and cautions: docs\PUBLIC-CA-ENTERPRISE-ROOT.txt
#
# Two models, both prepared here:
#
#  A. SUBORDINATE (the Enterprise Root BECOMES a subordinate CA of the public CA)
#       1. .\pki_setup.ps1 -EnterpriseRootCsr [-ExternalCa DigiCert] [-ClassicPKI]
#            creates pki\root\root.key and pki\root\root.csr and a request sheet, then stops
#       2. send root.csr to the public CA, receive the signed certificate (+ chain)
#       3. .\pki_setup.ps1 -ImportEnterpriseRoot <signed.pem> -ExternalChain <chain.pem> [-InstallTrust]
#            checks the certificate (CA flag, path length, key, validity, constraints, chain), then
#            builds every other CA under it. Clients that trust the public root need nothing else.
#
#  B. CROSS-SIGN (the existing self-signed Enterprise Root keeps working; the public CA ADDS a
#     certificate for the same key, so clients that only know the public root can chain to it)
#       1. .\pki_setup.ps1 -CrossSignCsr         (needs an existing PKI)
#       2. send pki\root\cross-sign\root-cross.csr to the public CA
#       3. .\pki_setup.ps1 -ImportCrossCert <cross.pem> -ExternalChain <chain.pem>
#            stores it, publishes it, writes <leaf>-fullchain-cross.crt for every leaf
#
# Provides : Invoke-PkiEnterpriseRootCsr, Import-PkiEnterpriseRoot, Use-PkiExternalRoot, Get-PkiLatestCrossCertificate,
#            New-PkiCrossFullchainFile,
#            Invoke-PkiCrossSignCsr, Invoke-PkiImportCrossCert, Get-PkiTrustAnchor,
#            Get-PkiExternalChainIntermediates, Test-PkiPemSelfSigned, Get-PkiIssuerRemainingDays
# Requires : 00_Common, 01_Configuration, 01b_CaNaming, 02_OpenSSL, 03_RuntimeConfig,
#            04_CertificateAuthority, 12_ExistingPki
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The Enterprise Root signs Track Root -> Quadrant Root -> Intermediate: three CAs below it.
$script:PkiExternalRootMinPathLen = 3

function Get-PkiExternalPaths {
    $root = Join-Path $script:Pki.PkiRoot 'root'
    return [ordered]@{
        Dir = $root; Key = Join-Path $root 'root.key'; Csr = Join-Path $root 'root.csr'
        Crt = Join-Path $root 'root.crt'; Cnf = Join-Path $root 'root.cnf'
        State = Join-Path $root 'external-state.json'; Request = Join-Path $root 'external-request.txt'
        Chain = Join-Path $root 'external-chain.pem'
        CrossDir = Join-Path $root 'cross-sign'; CrossState = Join-Path (Join-Path $root 'cross-sign') 'cross-state.json'
    }
}

# ------------------------------------------------------------
# small OpenSSL helpers (default provider, no PKI configuration needed)
# ------------------------------------------------------------
function Get-PkiOpenSslCertText {
    param([Parameter(Mandatory)][string]$Path, [string]$InForm = 'PEM')
    $cnf = Get-PkiProviderConfigPath -Fips $false
    return (Invoke-OpenSSL -ConfigPath $cnf -Arguments (@('x509', '-in', $Path, '-inform', $InForm, '-noout', '-text') + (Get-PkiProviderArgs -Fips $false))).StdOut
}

function ConvertTo-PkiPemFile {
    # Accepts PEM or DER; writes PEM to $Destination.
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Destination)
    $head = [System.IO.File]::ReadAllText($Source)
    if ($head -match '-----BEGIN CERTIFICATE-----') {
        $blocks = Split-PkiPemBundle -Path $Source
        Write-Utf8NoBom -Path $Destination -Content ($blocks[0])
    }
    else {
        [void](Invoke-OpenSSL -ConfigPath (Get-PkiProviderConfigPath -Fips $false) -Arguments (@('x509', '-in', $Source, '-inform', 'DER', '-outform', 'PEM', '-out', $Destination) + (Get-PkiProviderArgs -Fips $false)))
    }
    Assert-PkiFile -Path $Destination
}

function Test-PkiPemSelfSigned {
    # $Pem = text of ONE certificate
    param([Parameter(Mandatory)][string]$Pem)
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "pki-ss-$([guid]::NewGuid().ToString('N')).pem"
    try {
        Write-Utf8NoBom -Path $tmp -Content $Pem
        $r = Invoke-OpenSSL -ConfigPath (Get-PkiProviderConfigPath -Fips $false) -Arguments (@('x509', '-in', $tmp, '-noout', '-subject', '-issuer', '-nameopt', 'RFC2253') + (Get-PkiProviderArgs -Fips $false))
        $subj = ($r.StdOut -split "`n" | Where-Object { $_ -like 'subject=*' } | Select-Object -First 1) -replace '^subject=\s*', ''
        $iss  = ($r.StdOut -split "`n" | Where-Object { $_ -like 'issuer=*' } | Select-Object -First 1) -replace '^issuer=\s*', ''
        return ($subj.Trim() -ceq $iss.Trim())
    }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}

function Get-PkiExternalChainIntermediates {
    # The certificates of the public CA's chain that clients do NOT already have as a root:
    # everything except the self-signed public root. Servers send these after our certificates.
    $p = Get-PkiExternalPaths
    $out = [System.Collections.Generic.List[string]]::new()
    if (-not (Test-Path -LiteralPath $p.Chain -PathType Leaf)) { return ,$out }
    foreach ($pem in (Split-PkiPemBundle -Path $p.Chain)) {
        if (-not (Test-PkiPemSelfSigned -Pem $pem)) { [void]$out.Add($pem) }
    }
    return ,$out
}

function Get-PkiTrustAnchor {
    # What a chain must end in. Self-signed Enterprise Root: root.crt. Public-CA signed: the
    # public chain file (the root is then an intermediate and must be passed as untrusted).
    $c = $script:Pki
    if ($null -ne $c.ExternalRoot) {
        $chain = (Get-PkiExternalPaths).Chain
        if (-not (Test-Path -LiteralPath $chain -PathType Leaf)) {
            throw 'The Enterprise Root is signed by a public CA but pki\root\external-chain.pem is missing: chains cannot be verified without it (import it with -ImportEnterpriseRoot ... -ExternalChain).'
        }
        return [ordered]@{ Anchor = $chain; RootIsAnchor = $false }
    }
    return [ordered]@{ Anchor = (Get-PkiCaPaths -Ca (Get-PkiCa -Id 'root')).Crt; RootIsAnchor = $true }
}

function Get-PkiIssuerRemainingDays {
    # Days until a built CA expires (a child may not outlive its issuer). $null when unknown.
    param([Parameter(Mandatory)][string]$IssuerId)
    $b = $script:Pki.Built[$IssuerId]
    if ($null -eq $b -or [string]::IsNullOrWhiteSpace([string]$b['notAfter'])) { return $null }
    try {
        $na = [DateTime]::ParseExact([string]$b['notAfter'], 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        return [int][Math]::Floor(($na - [DateTime]::UtcNow).TotalDays) - 1
    }
    catch { return $null }
}

# ------------------------------------------------------------
# A. step 1: key + CSR for the Enterprise Root
# ------------------------------------------------------------
function Invoke-PkiEnterpriseRootCsr {
    $c = $script:Pki
    $p = Get-PkiExternalPaths
    if (Test-Path -LiteralPath $p.Crt) { throw "A PKI already exists in $($c.PkiRoot) (root.crt). Use -Clean to remove it first." }
    if ((Test-Path -LiteralPath $p.Key) -or (Test-Path -LiteralPath $p.State)) {
        throw "An Enterprise Root request already exists in $($p.Dir).`nImport the signed certificate with -ImportEnterpriseRoot <file>, or start over with -Clean (this deletes the key)."
    }

    Initialize-OpenSSL
    $q = $c.Quadrants; $c.Quadrants = @(1)         # only the default provider is needed for the root
    try { Initialize-PkiProviderConfigs } finally { $c.Quadrants = $q }

    $root = Get-PkiCa -Id 'root'
    Ensure-PkiDirectory -Path $p.Dir
    Write-PkiFolderMarker -Folder $c.PkiRoot
    $root.Actual = New-PkiPrivateKey -KeyPath $p.Key -Family 'rsa' -Bits $c.EnterpriseRootKeyBits -Label 'root'
    [void](Write-PkiCaConfig -Ca $root)
    [void](Invoke-OpenSSL -ConfigPath $p.Cnf -Arguments (@('req', '-new', '-key', $p.Key, '-config', $p.Cnf, '-sha512', '-out', $p.Csr) + (Get-PkiProviderArgs -Fips $false)))
    Assert-PkiFile -Path $p.Csr

    $cn = Get-PkiCaCommonName -Ca $root
    $subject = (Invoke-OpenSSL -ConfigPath $p.Cnf -Arguments (@('req', '-in', $p.Csr, '-noout', '-subject', '-nameopt', 'multiline,utf8') + (Get-PkiProviderArgs -Fips $false))).StdOut.Trim()
    $caLabel = if ([string]::IsNullOrWhiteSpace($c.ExternalCa)) { 'the public CA' } else { $c.ExternalCa }
    $mode = if ($c.ClassicPki) { 'ClassicPKI (Enterprise Root, Classic Track Root, Q1 Root, DV / OV / EV intermediates)' } else { 'full PKI (all selected quadrants)' }

    $sheet = @"
ENTERPRISE ROOT REQUEST SHEET                       created $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm')) UTC
=====================================================================================================
For            : $caLabel
Common name    : $cn
Key            : RSA-$($c.EnterpriseRootKeyBits)   (the private key stays in pki\root\root.key - never send it)
Request file   : root.csr  (PKCS#10, signed with SHA-512)
PKI to build   : $mode

WHAT YOU ARE ASKING FOR   a SUBORDINATE CA certificate (some CAs call it a "private SubCA", "dedicated
issuing CA", "managed PKI CA" or "cross-certificate") for the key in root.csr.

REQUIRED so that the rest of this PKI works below it
  basicConstraints   CA:TRUE, critical, pathlen >= $script:PkiExternalRootMinPathLen
                     (Enterprise Root -> Track Root -> Quadrant Root -> Intermediate = 3 CAs below it;
                      a CA that only allows pathlen 0 or 1 cannot be used at this level, see the
                      documentation, section "Which level to sign")
  keyUsage           keyCertSign, cRLSign (critical)
  extendedKeyUsage   if the CA adds one it must contain serverAuth AND clientAuth (every certificate
                     below inherits the restriction; code signing / e-mail leaves need more)
  validity           as long as the CA allows; every CA below is shortened to fit inside it
  name constraints   if the CA imposes permitted DNS names, every SAN of your leaves must be inside them

ASK THE CA
  1. Is this key size accepted (RSA-$($c.EnterpriseRootKeyBits))? Public CAs often accept 4096 at most.
  2. Which pathlen, EKU and name constraints will the certificate carry?
  3. Which maximum validity? Which leaf validity may this CA issue (public TLS: 398 days; this PKI: EV 397)?
  4. Is an audit (WebTrust / ETSI) or a technically-constrained profile required?
  5. Which chain file (intermediates + root) do they deliver, in PEM?

SUBJECT IN THE REQUEST
$subject

NEXT STEP when you have the certificate (PEM or DER) and the chain:
  .\pki_setup.ps1 -ImportEnterpriseRoot <signed-certificate> -ExternalChain <chain.pem>$(if ($c.ClassicPki) { ' -ClassicPKI' }) -InstallTrust
"@
    Write-Utf8NoBom -Path $p.Request -Content ($sheet + "`n")

    $state = [ordered]@{
        status = 'csr'; createdUtc = [DateTime]::UtcNow.ToString('o'); externalCa = $c.ExternalCa
        keyBits = $c.EnterpriseRootKeyBits; commonName = $cn; classicPki = [bool]$c.ClassicPki
        quadrants = @($c.Quadrants); generator = $script:PkiGeneratorVersion
    }
    Write-Utf8NoBom -Path $p.State -Content ($state | ConvertTo-Json -Depth 4)

    Write-PkiLog "Key     : $($p.Key)" 'OK'
    Write-PkiLog "Request : $($p.Csr)" 'OK'
    Write-PkiLog "Sheet   : $($p.Request)  (what to ask $caLabel)" 'OK'
    Write-PkiLog "Send root.csr to $caLabel. When the signed certificate arrives run:" 'INFO'
    Write-PkiLog "  .\pki_setup.ps1 -ImportEnterpriseRoot <signed-certificate> -ExternalChain <chain.pem>$(if ($c.ClassicPki) { ' -ClassicPKI' }) -InstallTrust" 'INFO'
}

# ------------------------------------------------------------
# A. step 2: validate and adopt the signed certificate
# ------------------------------------------------------------
function Import-PkiEnterpriseRoot {
    $c = $script:Pki
    $p = Get-PkiExternalPaths
    if (-not (Test-Path -LiteralPath $p.Key) -or -not (Test-Path -LiteralPath $p.State)) {
        throw "No Enterprise Root request found in $($p.Dir). Run .\pki_setup.ps1 -EnterpriseRootCsr first."
    }
    if (Test-Path -LiteralPath $p.Crt) { throw "$($p.Crt) exists already: the Enterprise Root was imported before. Use -Clean to start over." }
    $state = Get-Content -LiteralPath $p.State -Raw | ConvertFrom-Json -AsHashtable

    # the request decides the shape of the PKI
    if ($state['classicPki'] -and -not $c.ClassicPki) {
        Write-PkiLog 'The request was made with -ClassicPKI: building the Classic PKI (Enterprise Root, Classic Track Root, Q1 Root, DV / OV / EV).' 'INFO'
        $c.ClassicPki = $true; $c.Quadrants = @(1); $c.Catalog = New-PkiCatalog
        Test-PkiNaming
    }
    if ([string]::IsNullOrWhiteSpace($c.ExternalCa)) { $c.ExternalCa = [string]$state['externalCa'] }
    $c.EnterpriseRootKeyBits = [int]$state['keyBits']

    $work = Join-Path $p.Dir 'import.tmp.pem'
    ConvertTo-PkiPemFile -Source $c.ImportEnterpriseRoot -Destination $work
    try { $t = Get-PkiOpenSslCertText -Path $work } catch { Remove-Item -LiteralPath $work -Force -ErrorAction SilentlyContinue; throw }
    $problems = [System.Collections.Generic.List[string]]::new()
    $notes = [System.Collections.Generic.List[string]]::new()

    # 1. CA certificate with enough path length
    if ($t -notmatch 'CA:TRUE') { [void]$problems.Add('The certificate is not a CA certificate (basicConstraints CA:TRUE is missing).') }
    elseif ($t -match 'pathlen:(?<n>\d+)') {
        $pl = [int]$Matches['n']
        if ($pl -lt $script:PkiExternalRootMinPathLen) {
            [void]$problems.Add("Its path length is $pl, but this PKI needs at least $script:PkiExternalRootMinPathLen (three CA levels below the Enterprise Root). Ask the CA for pathlen >= $script:PkiExternalRootMinPathLen, or let it sign a lower level (see docs\PUBLIC-CA-ENTERPRISE-ROOT.txt, 'Which level to sign').")
        }
        else { [void]$notes.Add("pathlen $pl") }
    }
    else { [void]$notes.Add('no path length limit') }
    if ($t -notmatch 'Certificate Sign') { [void]$problems.Add('keyUsage keyCertSign is missing.') }

    # 2. the certificate is for OUR key
    $a = Get-PkiPublicKeyPem -Path $work -Kind cert -Fips $false
    $b = Get-PkiPublicKeyPem -Path $p.Key -Kind key -Fips $false
    if ($a -ne $b) { [void]$problems.Add('The public key of the certificate is not the key of pki\root\root.key (the CA signed a different request).') }

    # 3. validity
    $fmt = 'MMM d HH:mm:ss yyyy'
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $notAfter = $null
    if ($t -match 'Not After\s*:\s*(?<b>.+?)\r?\n') {
        $notAfter = [DateTime]::ParseExact((($Matches['b'] -replace ' GMT', '') -replace '\s+', ' ').Trim(), $fmt, $inv)
        if ($notAfter -le [DateTime]::UtcNow) { [void]$problems.Add("The certificate has expired ($($notAfter.ToString('yyyy-MM-dd'))).") }
        else {
            $years = [Math]::Round(($notAfter - [DateTime]::UtcNow).TotalDays / 365.25, 1)
            [void]$notes.Add("valid until $($notAfter.ToString('yyyy-MM-dd')) ($years years)")
            if ($years -lt $c.TrackYears) { [void]$notes.Add("every CA below is shortened to fit inside it (requested Track Root $($c.TrackYears) y, Quadrant $($c.QuadrantYears) y, Intermediate $($c.IntYears) y)") }
        }
    }

    # 4. restrictions that reach every certificate below
    if ($t -match 'X509v3 Extended Key Usage:\s*(?:critical)?\s*\r?\n\s*(?<e>[^\r\n]+)') {
        $eku = $Matches['e']
        [void]$notes.Add("EKU restriction: $eku")
        if ($eku -notmatch 'TLS Web Server Authentication' -or $eku -notmatch 'TLS Web Client Authentication') {
            [void]$problems.Add("The CA's extended key usage ($eku) lacks serverAuth and/or clientAuth: the EV leaves of this PKI (serverAuth + clientAuth) would not validate in Windows.")
        }
    }
    if ($t -match 'X509v3 Name Constraints') {
        $nc = ($t -split "`n" | Select-String -Pattern 'DNS:|IP:|email:' | ForEach-Object { $_.Line.Trim() }) -join ' '
        [void]$notes.Add("NAME CONSTRAINTS present: $nc")
        Write-PkiLog "The certificate carries name constraints: every DNS name of your leaves must be inside them ($nc)." 'WARN'
    }
    if ($t -match 'Signature Algorithm:\s*(?<s>\S+)') { [void]$notes.Add("signed with $($Matches['s'])") }
    $issuer = ''
    if ($t -match '(?m)^\s*Issuer:\s*(?<i>.+)$') { $issuer = $Matches['i'].Trim() }
    $subject = ''
    if ($t -match '(?m)^\s*Subject:\s*(?<s>.+)$') { $subject = $Matches['s'].Trim() }

    # 5. public chain
    if (-not [string]::IsNullOrWhiteSpace($c.ExternalChain)) {
        Copy-Item -LiteralPath $c.ExternalChain -Destination $p.Chain -Force
        $vf = Invoke-OpenSSL -ConfigPath (Get-PkiProviderConfigPath -Fips $false) -AllowFailure -Arguments (@('verify', '-CAfile', $p.Chain) + (Get-PkiProviderArgs -Fips $false) + @($work))
        if ($vf.ExitCode -ne 0) {
            $vf = Invoke-OpenSSL -ConfigPath (Get-PkiProviderConfigPath -Fips $false) -AllowFailure -Arguments (@('verify', '-partial_chain', '-CAfile', $p.Chain) + (Get-PkiProviderArgs -Fips $false) + @($work))
            if ($vf.ExitCode -eq 0) { [void]$notes.Add('the chain file has no self-signed public root: verified as a partial chain') }
            else { [void]$problems.Add("The certificate does not chain to the file given with -ExternalChain: $(($vf.StdErr -split "`n" | Select-Object -First 2) -join ' | ')") }
        }
    }
    else { Write-PkiLog 'No -ExternalChain given: servers cannot send the public CA intermediates, and the chain cannot be verified here. Add it with -ExternalChain <chain.pem>.' 'WARN' }

    if ($problems.Count -gt 0) {
        Remove-Item -LiteralPath $work -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $p.Chain) { Remove-Item -LiteralPath $p.Chain -Force -ErrorAction SilentlyContinue }
        throw ("The signed Enterprise Root certificate cannot be used:`n  - " + ($problems -join "`n  - "))
    }

    Move-Item -LiteralPath $work -Destination $p.Crt -Force
    $c.ExternalRoot = [ordered]@{
        Signed = $true; CaName = $c.ExternalCa; Chain = $(if (Test-Path -LiteralPath $p.Chain) { $p.Chain } else { $null })
        NotAfter = $(if ($null -ne $notAfter) { $notAfter.ToString('yyyy-MM-dd') } else { '' }); Issuer = $issuer; Subject = $subject
    }
    $state['status'] = 'imported'; $state['importedUtc'] = [DateTime]::UtcNow.ToString('o'); $state['issuer'] = $issuer
    Write-Utf8NoBom -Path $p.State -Content ($state | ConvertTo-Json -Depth 4)
    Write-PkiLog "Enterprise Root accepted. Issuer: $issuer" 'OK'
    foreach ($n in $notes) { Write-PkiLog "  $n" 'INFO' }
}

# ------------------------------------------------------------
# A. build step: the Enterprise Root is the imported certificate (key + certificate exist)
# ------------------------------------------------------------
function Use-PkiExternalRoot {
    param([Parameter(Mandatory)][hashtable]$Ca)
    $p = Get-PkiCaPaths -Ca $Ca
    $x = Get-PkiExternalPaths
    Write-PkiLog "Using the Enterprise Root signed by $(if ($script:Pki.ExternalRoot.CaName) { $script:Pki.ExternalRoot.CaName } else { 'a public CA' }) [root, externally signed]"
    Initialize-PkiCaDatabase -Ca $Ca

    $t = Get-PkiOpenSslCertText -Path $p.Crt
    if ($t -notmatch 'Public-Key:\s*\((?<bits>\d+) bit\)') { throw 'Cannot read the key size of the imported Enterprise Root.' }
    $Ca.Actual = ConvertTo-PkiActualKey -Algorithm "RSA-$($Matches['bits'])"
    $cn = Get-PkiCaCommonName -Ca $Ca
    [void](Write-PkiCaConfig -Ca $Ca)                   # the database section is used to sign the Track Roots

    Write-PkiChainFile -Ca $Ca
    try { New-PkiPfxFile -KeyPath $p.Key -CertPath $p.Crt -PfxPath $p.Pfx -Name $cn -Legacy:$script:Pki.LegacyPfx }
    catch { Write-PkiLog "PFX for root was not created: $($_.Exception.Message.Split("`n")[0])" 'WARN' }

    $fp = Get-PkiCertificateFingerprint -Path $p.Crt
    $sig = ''
    if ($t -match 'Signature Algorithm:\s*(?<s>\S+)') { $sig = $Matches['s'] }
    if ($sig -match '(?i)^(sha\d+)with') { $sig = $Matches[1].ToLowerInvariant() } elseif ($sig -match '(?i)ecdsa-with-(sha\d+)') { $sig = $Matches[1].ToLowerInvariant() }
    $Ca.Done = $true
    $script:Pki.Built[$Ca.Id] = [ordered]@{
        id = $Ca.Id; kind = $Ca.Kind; commonName = $cn; track = $Ca.Track; quadrant = $Ca.Quadrant
        fips = $false; validation = $null; generation = $Ca.Gen; parent = $null
        requestedFamily = 'rsa'; keyAlgorithm = $Ca.Actual.Algorithm; pqcFallback = $false
        signatureDigest = $sig; validityYears = [Math]::Round((([DateTime]::ParseExact($script:Pki.ExternalRoot.NotAfter, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)) - [DateTime]::UtcNow).TotalDays / 365.25, 1)
        pathLen = $Ca.PathLen; slug = $Ca.Slug; notAfter = $script:Pki.ExternalRoot.NotAfter
        certificate = $p.Crt; sha1 = $fp.Sha1; sha256 = $fp.Sha256
        externallySigned = $true; store = 'CA'; issuer = $script:Pki.ExternalRoot.Issuer
    }
    Write-PkiLog "  Thumbprint : $($fp.Sha1)" 'OK'
}

# ------------------------------------------------------------
# B. cross-signing the existing (self-signed) Enterprise Root key
# ------------------------------------------------------------
function Get-PkiLatestCrossCertificate {
    # The newest cross-certificate imported with -ImportCrossCert, or $null.
    $p = Get-PkiExternalPaths
    if (-not (Test-Path -LiteralPath $p.CrossState)) { return $null }
    $state = @(Get-Content -LiteralPath $p.CrossState -Raw | ConvertFrom-Json -AsHashtable)
    if ($state.Count -eq 0) { return $null }
    return $state[$state.Count - 1]
}

function New-PkiCrossFullchainFile {
    # <leaf>-fullchain.crt -> <leaf>-fullchain-cross.crt = fullchain + cross-certificate + public CA intermediates.
    # Servers that must also serve clients which only know the public root send this file.
    param([Parameter(Mandatory)][string]$FullChain, [Parameter(Mandatory)]$Cross)
    $out = $FullChain -replace '-fullchain\.crt$', '-fullchain-cross.crt'
    if ($out -eq $FullChain -or -not (Test-Path -LiteralPath $Cross['certificate'])) { return $null }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append(([System.IO.File]::ReadAllText($FullChain)).TrimEnd() + "`n")
    [void]$sb.Append(([System.IO.File]::ReadAllText($Cross['certificate'])).TrimEnd() + "`n")
    if ($Cross['chain'] -and (Test-Path -LiteralPath $Cross['chain'])) {
        foreach ($pem in (Split-PkiPemBundle -Path $Cross['chain'])) { if (-not (Test-PkiPemSelfSigned -Pem $pem)) { [void]$sb.Append($pem.TrimEnd() + "`n") } }
    }
    Write-Utf8NoBom -Path $out -Content $sb.ToString()
    return $out
}

function Invoke-PkiCrossSignCsr {
    $c = $script:Pki
    $p = Get-PkiExternalPaths
    Initialize-OpenSSL
    $m = Import-PkiExisting
    if ($null -ne $c.ExternalRoot) { throw 'The Enterprise Root of this PKI is already signed by a public CA: cross-signing is for a self-signed Enterprise Root.' }
    Ensure-PkiDirectory -Path $p.CrossDir
    $csr = Join-Path $p.CrossDir 'root-cross.csr'
    $prov = Get-PkiProviderArgs -Fips $false
    # same key, same subject (root.cnf holds the subject the root certificate was issued with)
    [void](Invoke-OpenSSL -ConfigPath $p.Cnf -Arguments (@('req', '-new', '-key', $p.Key, '-config', $p.Cnf, '-sha512', '-out', $csr) + $prov))
    $cnf = Get-PkiProviderConfigPath -Fips $false
    $csrSubj = (Invoke-OpenSSL -ConfigPath $cnf -Arguments (@('req', '-in', $csr, '-noout', '-subject', '-nameopt', 'RFC2253') + $prov)).StdOut.Trim() -replace '^subject=\s*', ''
    $crtSubj = (Invoke-OpenSSL -ConfigPath $cnf -Arguments (@('x509', '-in', $p.Crt, '-noout', '-subject', '-nameopt', 'RFC2253') + $prov)).StdOut.Trim() -replace '^subject=\s*', ''
    if ($csrSubj -cne $crtSubj) { Write-PkiLog "The request subject differs from the Enterprise Root subject (names changed since generation?):`n  request: $csrSubj`n  root   : $crtSubj" 'WARN' }

    $caLabel = if ([string]::IsNullOrWhiteSpace($c.ExternalCa)) { 'the public CA' } else { $c.ExternalCa }
    $sheet = @"
CROSS-SIGN REQUEST SHEET                            created $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm')) UTC
=====================================================================================================
For            : $caLabel
Subject        : $crtSubj
Key            : the key of the existing Enterprise Root ($($c.Built['root'].keyAlgorithm))
Request file   : root-cross.csr  (same key and same subject as the self-signed Enterprise Root)

You ask $caLabel for a CROSS-CERTIFICATE: a CA certificate for the SAME key and subject, issued by their
public root. The self-signed Enterprise Root keeps working; clients that only know the public root can
now also build a chain to your CAs.
REQUIRED: CA:TRUE, pathlen >= $script:PkiExternalRootMinPathLen, keyCertSign + cRLSign, EKU (if any) with serverAuth + clientAuth.

NEXT STEP:  .\pki_setup.ps1 -ImportCrossCert <cross-certificate> -ExternalChain <chain.pem>
"@
    Write-Utf8NoBom -Path (Join-Path $p.CrossDir 'cross-sign-request.txt') -Content ($sheet + "`n")
    Write-PkiLog "Request : $csr" 'OK'
    Write-PkiLog "Sheet   : $(Join-Path $p.CrossDir 'cross-sign-request.txt')" 'OK'
    Write-PkiLog "Send root-cross.csr to $caLabel, then: .\pki_setup.ps1 -ImportCrossCert <cross-certificate> -ExternalChain <chain.pem>" 'INFO'
}

function Invoke-PkiImportCrossCert {
    $c = $script:Pki
    $p = Get-PkiExternalPaths
    Initialize-OpenSSL
    $m = Import-PkiExisting
    if ($null -ne $c.ExternalRoot) { throw 'The Enterprise Root of this PKI is already signed by a public CA: cross-signing is for a self-signed Enterprise Root.' }
    Ensure-PkiDirectory -Path $p.CrossDir
    $work = Join-Path $p.CrossDir 'import.tmp.pem'
    ConvertTo-PkiPemFile -Source $c.ImportCrossCert -Destination $work
    $t = Get-PkiOpenSslCertText -Path $work
    $cnf = Get-PkiProviderConfigPath -Fips $false
    $prov = Get-PkiProviderArgs -Fips $false
    $problems = [System.Collections.Generic.List[string]]::new()

    if ($t -notmatch 'CA:TRUE') { [void]$problems.Add('Not a CA certificate (CA:TRUE missing).') }
    if ($t -match 'pathlen:(?<n>\d+)' -and [int]$Matches['n'] -lt $script:PkiExternalRootMinPathLen) { [void]$problems.Add("Path length $($Matches['n']) is below $script:PkiExternalRootMinPathLen.") }
    if ((Get-PkiPublicKeyPem -Path $work -Kind cert -Fips $false) -ne (Get-PkiPublicKeyPem -Path $p.Key -Kind key -Fips $false)) {
        [void]$problems.Add('The public key is not the key of the Enterprise Root: this is not a cross-certificate of your root.')
    }
    $crossSubj = (Invoke-OpenSSL -ConfigPath $cnf -Arguments (@('x509', '-in', $work, '-noout', '-subject', '-nameopt', 'RFC2253') + $prov)).StdOut.Trim() -replace '^subject=\s*', ''
    $rootSubj  = (Invoke-OpenSSL -ConfigPath $cnf -Arguments (@('x509', '-in', $p.Crt, '-noout', '-subject', '-nameopt', 'RFC2253') + $prov)).StdOut.Trim() -replace '^subject=\s*', ''
    if ($crossSubj -cne $rootSubj) { [void]$problems.Add("The subject differs from the Enterprise Root ($crossSubj): a cross-certificate must carry the same subject, or chains cannot be built.") }

    $chainFile = $null
    if (-not [string]::IsNullOrWhiteSpace($c.ExternalChain)) {
        $chainFile = $c.ExternalChain
        $vf = Invoke-OpenSSL -ConfigPath $cnf -AllowFailure -Arguments (@('verify', '-CAfile', $chainFile) + $prov + @($work))
        if ($vf.ExitCode -ne 0) {
            $vf = Invoke-OpenSSL -ConfigPath $cnf -AllowFailure -Arguments (@('verify', '-partial_chain', '-CAfile', $chainFile) + $prov + @($work))
            if ($vf.ExitCode -ne 0) { [void]$problems.Add("Does not chain to the file given with -ExternalChain: $(($vf.StdErr -split "`n" | Select-Object -First 2) -join ' | ')") }
        }
    }
    else { Write-PkiLog 'No -ExternalChain given: the cross-certificate is stored but cannot be verified.' 'WARN' }
    if ($problems.Count -gt 0) {
        Remove-Item -LiteralPath $work -Force -ErrorAction SilentlyContinue
        throw ("The cross-certificate cannot be used:`n  - " + ($problems -join "`n  - "))
    }

    # keep it
    $state = @()
    if (Test-Path -LiteralPath $p.CrossState) { $state = @(Get-Content -LiteralPath $p.CrossState -Raw | ConvertFrom-Json -AsHashtable) }
    $n = $state.Count + 1
    $crossCrt = Join-Path $p.CrossDir "root-cross-$n.crt"
    Move-Item -LiteralPath $work -Destination $crossCrt -Force
    $chainOut = $null
    if ($chainFile) { $chainOut = Join-Path $p.CrossDir "root-cross-$n-chain.pem"; Copy-Item -LiteralPath $chainFile -Destination $chainOut -Force }
    $issuer = ''
    if ($t -match '(?m)^\s*Issuer:\s*(?<i>.+)$') { $issuer = $Matches['i'].Trim() }
    $fp = Get-PkiCertificateFingerprint -Path $crossCrt
    $state += [ordered]@{ number = $n; certificate = $crossCrt; chain = $chainOut; issuer = $issuer; sha1 = $fp.Sha1; externalCa = $c.ExternalCa; importedUtc = [DateTime]::UtcNow.ToString('o') }
    Write-Utf8NoBom -Path $p.CrossState -Content (ConvertTo-Json -InputObject @($state) -Depth 5)

    # publish and build the leaf chains that clients with only the public root need
    Ensure-PkiDirectory -Path $c.PublishDir
    $slug = (Get-PkiCa -Id 'root').Slug
    Copy-Item -LiteralPath $crossCrt -Destination (Join-Path $c.PublishDir "$slug-cross-$n.pem") -Force
    $cross = $state[$state.Count - 1]
    $made = 0
    foreach ($l in $c.Leaves) {
        $full = [string]$l['fullchain']
        if ($full -and (Test-Path -LiteralPath $full) -and (New-PkiCrossFullchainFile -FullChain $full -Cross $cross)) { $made++ }
    }
    # leaves made by GenerateLeafCertificate.ps1 (leafcerts\leaf-index.json, next to the scripts)
    $leafRoot = Get-PkiLeafRoot
    $idx = Join-Path $leafRoot 'leaf-index.json'
    if (Test-Path -LiteralPath $idx) {
        foreach ($e in @(Get-Content -LiteralPath $idx -Raw | ConvertFrom-Json -AsHashtable)) {
            $full = Join-Path (Join-Path $leafRoot $e['folder']) "$($e['stem'])-fullchain.crt"
            if (Test-Path -LiteralPath $full) { if (New-PkiCrossFullchainFile -FullChain $full -Cross $cross) { $made++ } }
        }
    }

    # record in the manifest
    $mp = Join-Path $c.PkiRoot 'pki-manifest.json'
    $man = Get-Content -LiteralPath $mp -Raw | ConvertFrom-Json -AsHashtable
    if (-not $man.ContainsKey('enterpriseRoot') -or $null -eq $man['enterpriseRoot']) { $man['enterpriseRoot'] = [ordered]@{ externallySigned = $false } }
    $man['enterpriseRoot']['crossCertificates'] = @($state)
    Write-Utf8NoBom -Path $mp -Content ($man | ConvertTo-Json -Depth 10)

    Write-PkiLog "Cross-certificate stored: $crossCrt" 'OK'
    Write-PkiLog "  issuer: $issuer" 'INFO'
    Write-PkiLog "  $made leaf chain file(s) written (<leaf>-fullchain-cross.crt, default leaves and leafcerts): servers that must serve clients without your Enterprise Root send these." 'OK'
}
