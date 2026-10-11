# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 18_Revocation.ps1  -  CRLs, revocation, OCSP responder and time stamp certificates, revocation information
#
# Used by pki_setup.ps1 (generates them with the PKI) and by PkiRevocation.ps1 (shows, edits, renews).
# Provides : Get-PkiRevocationCas, Update-PkiCrl, Revoke-PkiCertificate, New-PkiServiceCertificate (OCSP responder / time
#            stamp), New-PkiRevocationServiceSet, Invoke-PkiSignServiceCsr, Get-PkiRevocationStatus, Write-PkiRevocationInfo
# Layout   : pki\ocsp\<ca id>\<ca id>-ocsp.crt / .key / .pub / -fullchain.crt / ocsp-info.json    (one responder per issuing CA)
#            pki\tsa\<ca id>\<ca id>-tsa.crt  ...                                                  (time stamping)
#            pki\revocation-info.json + REVOCATION-INFO.txt                                         (URLs, CRL dates, responders)
# Requires : 00-04, 06, 12, 14
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:PkiRevocationReasons = @('unspecified', 'keyCompromise', 'CACompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation', 'certificateHold')

function Get-PkiOcspRoot { return (Join-Path $script:Pki.PkiRoot 'ocsp') }
function Get-PkiTsaRoot { return (Join-Path $script:Pki.PkiRoot 'tsa') }

function ConvertFrom-PkiOpenSslDate {
    param([string]$Text)
    try { return ([DateTime]::ParseExact(($Text -replace ' GMT', '' -replace '\s+', ' ').Trim(), 'MMM d HH:mm:ss yyyy', [Globalization.CultureInfo]::InvariantCulture)).ToUniversalTime() }
    catch { return $null }
}

function Get-PkiRevocationCas {
    <#
    .SYNOPSIS
        Resolves -Ca: ids (q1-ev), "all", or nothing (= every loaded CA). -IssuingOnly keeps the intermediates (they issue the leaves).
    #>
    param([string[]]$Id = @(), [switch]$IssuingOnly, [switch]$ClassicOnly)
    $all = @($script:Pki.Catalog | Where-Object { $null -ne $_.Actual })
    $want = @($Id | Where-Object { $_ -and $_ -ne 'all' })
    $sel = if ($want.Count -gt 0) {
        foreach ($w in $want) { if (-not ($all | Where-Object { $_.Id -eq $w })) { throw "Unknown or not built CA '$w'. Built: $((@($all | ForEach-Object { $_.Id }) -join ', '))." } }
        @($all | Where-Object { $want -contains $_.Id })
    } else { $all }
    if ($IssuingOnly) { $sel = @($sel | Where-Object { $_.Kind -eq 'intermediate' }) }
    if ($ClassicOnly -and $want.Count -eq 0) { $sel = @($sel | Where-Object { $_.Track -eq 'Classic' }) }
    return @($sel)
}

# ------------------------------------------------------------
# CRL
# ------------------------------------------------------------
function Update-PkiCrl {
    <#
    .SYNOPSIS
        New CRL of one CA: pki\<dir>\<id>.crl.pem and, in pki\publish, <slug>.crl (DER) and <slug>.crl.pem. -Days = its validity.
    #>
    param([Parameter(Mandatory)][hashtable]$Ca, [int]$Days = 0)
    if ($Days -le 0) { $Days = [int]$script:Pki.CrlDays }
    $p = Get-PkiCaPaths -Ca $Ca
    $prov = Get-PkiProviderArgs -Fips ([bool]$Ca.Fips)
    $md = Get-PkiIssueMd -Kind $Ca.Kind -Family $Ca.Actual.Family
    $crlArgs = @('ca', '-gencrl', '-config', $p.Cnf, '-out', $p.CrlPem, '-md', $md, '-crldays', [string]$Days)
    $crlArgs += (Get-PkiSigOpts -Family $Ca.Actual.Family -Md $md)
    $crlArgs += $prov
    [void](Invoke-OpenSSL -ConfigPath $p.Cnf -Arguments $crlArgs)
    $pub = $script:Pki.PublishDir
    Ensure-PkiDirectory -Path $pub
    [void](Invoke-OpenSSL -ConfigPath $p.Cnf -Arguments (@('crl', '-in', $p.CrlPem, '-outform', 'DER', '-out', (Join-Path $pub "$($Ca.Slug).crl")) + $prov))
    Copy-Item -LiteralPath $p.CrlPem -Destination (Join-Path $pub "$($Ca.Slug).crl.pem") -Force
    foreach ($f in @($p.CrlPem, (Join-Path $pub "$($Ca.Slug).crl.pem"))) { [void](ConvertTo-PkiLfFile -Path $f) }
    Write-PkiLog "CRL $($Ca.Id): valid $Days days  ->  $(Join-Path $pub "$($Ca.Slug).crl")" 'OK'
}

function Get-PkiCaIndexEntries {
    param([Parameter(Mandatory)][hashtable]$Ca)
    $p = Get-PkiCaPaths -Ca $Ca
    if (-not (Test-Path -LiteralPath $p.Index)) { return @() }
    return @(Get-Content -LiteralPath $p.Index | Where-Object { $_.Trim() } | ForEach-Object {
        $f = $_ -split "`t"
        [pscustomobject]@{ Status = $f[0]; Expiry = $f[1]; Revoked = $f[2]; Serial = $f[3]; Subject = $(if ($f.Count -gt 5) { $f[5] } else { '' }) }
    })
}

function Revoke-PkiCertificate {
    <#
    .SYNOPSIS
        Revokes an issued certificate (by file, or by serial + CA) and makes the new CRL of its issuer, unless -NoCrl.
    #>
    param([string]$CertificateFile, [string]$Serial, [string]$CaId, [string]$Reason = 'unspecified', [switch]$NoCrl, [int]$CrlDays = 0)
    if ($script:PkiRevocationReasons -notcontains $Reason) { throw "Reason '$Reason' is not valid. Use: $($script:PkiRevocationReasons -join ', ')." }
    $ca = $null; $file = $null
    if ($CertificateFile) {
        if (-not (Test-Path -LiteralPath $CertificateFile -PathType Leaf)) { throw "Certificate file not found: $CertificateFile" }
        $file = (Resolve-Path -LiteralPath $CertificateFile).Path
        $cfg0 = Get-PkiProviderConfigPath -Fips $false; $prov0 = Get-PkiProviderArgs -Fips $false
        $ih = (Invoke-OpenSSL -ConfigPath $cfg0 -Arguments (@('x509', '-in', $file, '-noout', '-issuer_hash') + $prov0)).StdOut.Trim()
        foreach ($c in (Get-PkiRevocationCas)) {
            $sh = (Invoke-OpenSSL -ConfigPath $cfg0 -Arguments (@('x509', '-in', (Get-PkiCaPaths -Ca $c).Crt, '-noout', '-subject_hash') + $prov0)).StdOut.Trim()
            if ($sh -eq $ih -and $c.Kind -ne 'root') { $ca = $c; break }
            if ($sh -eq $ih -and $null -eq $ca) { $ca = $c }
        }
        if ($null -eq $ca) { throw 'The certificate was not issued by a CA of this PKI.' }
        if ($CaId -and $CaId -ne $ca.Id) { throw "The certificate was issued by $($ca.Id), not by $CaId." }
    }
    elseif ($Serial) {
        if (-not $CaId) { throw '-Serial needs -Ca <issuing CA id> (for example q1-ev).' }
        $ca = @(Get-PkiRevocationCas -Id @($CaId))[0]
        $hex = ($Serial -replace '^0[xX]', '').ToUpperInvariant()
        $file = Join-Path (Get-PkiCaPaths -Ca $ca).Issued "$hex.pem"
        if (-not (Test-Path -LiteralPath $file)) { throw "No issued certificate with serial $hex in $($ca.Id) ($file). Give the certificate file with -Certificate." }
    }
    else { throw 'Give -Certificate <file> or -Serial <hex> with -Ca <id>.' }

    $p = Get-PkiCaPaths -Ca $ca
    $r = Invoke-OpenSSL -AllowFailure -ConfigPath $p.Cnf -Arguments (@('ca', '-config', $p.Cnf, '-revoke', $file, '-crl_reason', $Reason) + (Get-PkiProviderArgs -Fips ([bool]$ca.Fips)))
    if ($r.ExitCode -ne 0) {
        if (($r.StdErr + $r.StdOut) -match 'already revoked') { Write-PkiLog "Already revoked in $($ca.Id): $file" 'WARN' }
        else { throw "Revocation failed: $((($r.StdErr + $r.StdOut) -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 2) -join ' | ')" }
    }
    else { Write-PkiLog "Revoked ($Reason) in $($ca.Id): $file" 'OK' }
    if (-not $NoCrl) { Update-PkiCrl -Ca $ca -Days $CrlDays }
    return $ca
}

# ------------------------------------------------------------
# OCSP responder and time stamp certificates (made with the leaf generator, in their own folder)
# ------------------------------------------------------------
function New-PkiServiceCertificate {
    <#
    .SYNOPSIS
        Kind Ocsp: one OCSP responder certificate for the CA $Ca, in pki\ocsp\<ca id>\.
        Kind Tsa : the time stamping certificate (Classic non-FIPS Quadrant 1 by default, see [ timestamp ]), in pki\tsa\<ca id>\.
        The certificate is a normal leaf (same generator, same checks); key PKCS#8, LF line endings, .pub public key.
    .PARAMETER Replace
        An existing certificate is archived to old-<date>\ and a new one is made (this is how a responder certificate is "edited":
        change -Days, -KeyBits, -CommonName ... and run again with -Replace).
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('Ocsp', 'Tsa')][string]$Kind,
        [hashtable]$Ca, [string]$Level = 'EV',
        [int]$Days = 0, [int]$KeyBits = 0, [string]$KeyType = '', [string]$CommonName = '',
        [switch]$Replace, [switch]$RevokeOld
    )
    $c = $script:Pki
    $eku = if ($Kind -eq 'Ocsp') { 'OcspSigning' } else { 'TimeStamping' }
    $o = @{ Eku = @($eku); Format = @('PEM'); SetMode = $false }
    if ($Kind -eq 'Ocsp') {
        if ($null -eq $Ca -or $Ca.Kind -ne 'intermediate') { throw 'An OCSP responder certificate is made for an intermediate CA (q1-ev, q1-ov, q1-dv, q2-...).' }
        $o.Level = $Ca.Validation; $o.Quadrant = [int]$Ca.Quadrant
        $o.KeyBits = $(if ($KeyBits -gt 0) { $KeyBits } else { [int]$c.OcspKeyBits })
    }
    else {
        $o.Level = $Level.ToUpperInvariant(); $o.Quadrant = 1      # the quadrant of a time stamping certificate comes from [ timestamp ] / -TimestampQuadrant
        if ($KeyBits -gt 0) { $o.KeyBits = $KeyBits }
    }
    if ($KeyType) { $o.KeyType = $KeyType }
    if ($Days -gt 0) { $o.Days = $Days }
    $org = ConvertTo-PkiAscii (Get-PkiLeafSubjectValue 'Organization' 'O' 'Agantra Inovatif OU' $o.Level)
    if ($CommonName) { $o.CommonName = $CommonName }
    elseif ($Kind -eq 'Ocsp') {
        $cn = "$($c.Built[$Ca.Id].commonName) OCSP Responder"
        if ($cn.Length -gt 64) { $cn = "$org OCSP Responder $($Ca.Id)" }
        $o.CommonName = $cn
    }
    else { $o.CommonName = "$org Time Stamping Authority" }

    $spec = New-PkiLeafSpec -Options $o
    $root = if ($Kind -eq 'Ocsp') { Get-PkiOcspRoot } else { Get-PkiTsaRoot }
    $caId = $spec.Ca.Id
    $dir = Join-Path $root $caId
    $stem = "$caId-$(if ($Kind -eq 'Ocsp') { 'ocsp' } else { 'tsa' })"
    $spec.Stem = $stem
    $crt = Join-Path $dir "$stem.crt"
    $oldSerial = $null
    if (Test-Path -LiteralPath $crt) {
        if (-not $Replace) { Write-PkiLog "$Kind certificate of $caId exists already ($crt). -Replace makes a new one (the old one is archived)." 'INFO'; return @{ Status = 'exists'; Dir = $dir; Stem = $stem; Spec = $spec } }
        $cfg0 = Get-PkiProviderConfigPath -Fips $false
        try { $oldSerial = ((Invoke-OpenSSL -ConfigPath $cfg0 -Arguments (@('x509', '-in', $crt, '-noout', '-serial') + (Get-PkiProviderArgs -Fips $false))).StdOut.Trim() -replace '^serial=', '') } catch { }
        $arch = Join-Path $dir ('old-' + (Get-Date).ToString('yyyyMMdd-HHmmss'))
        [void][System.IO.Directory]::CreateDirectory($arch)
        foreach ($f in (Get-ChildItem -LiteralPath $dir -File)) { Move-Item -LiteralPath $f.FullName -Destination $arch -Force }
        Write-PkiLog "The previous $Kind certificate of $caId was archived: $arch"
    }
    [void][System.IO.Directory]::CreateDirectory($dir)
    $spec.OutDir = $dir
    foreach ($n in $spec.Notes) { Write-PkiLog "  note: $n" 'WARN' }
    $r = New-PkiLeafCertificate -Spec $spec
    [void](Test-PkiLeafResult -Spec $spec -R $r)
    foreach ($x in "$stem.cnf") { Remove-Item -LiteralPath (Join-Path $dir $x) -Force -ErrorAction SilentlyContinue }

    $cfg0 = Get-PkiProviderConfigPath -Fips $false; $prov0 = Get-PkiProviderArgs -Fips $false
    $txt = (Invoke-OpenSSL -ConfigPath $cfg0 -Arguments (@('x509', '-in', $r.Crt, '-noout', '-serial', '-subject', '-startdate', '-enddate') + $prov0)).StdOut
    $serial = if ($txt -match '(?m)^serial=(\S+)') { $Matches[1] } else { '' }
    $info = [ordered]@{
        kind = $Kind.ToLowerInvariant(); ca = $caId; stem = $stem; serial = $serial; notAfter = $r.NotAfter; days = $r.Days
        commonName = $o.CommonName; keyAlgorithm = $r.Actual.Algorithm; signatureDigest = $r.Md; sha1 = $r.Sha1; sha256 = $r.Sha256
        quadrant = $spec.Quadrant; track = $spec.Track; fips = [bool]$spec.Fips
        timestampPolicyOid = [string]$spec.TimestampPolicyOid
        files = @(Get-ChildItem -LiteralPath $dir -File | ForEach-Object { $_.Name } | Sort-Object)
        createdUtc = [DateTime]::UtcNow.ToString('o'); generator = "PkiRevocation / pki_setup $($script:PkiGeneratorVersion)"
    }
    Write-Utf8NoBom -Path (Join-Path $dir "$Kind-info.json".ToLowerInvariant()) -Content (($info | ConvertTo-Json -Depth 5) + "`n")
    if ($Kind -eq 'Ocsp') { Write-PkiLog "OCSP responder certificate $caId : $($r.Actual.Algorithm), $($r.Days) days, until $($r.NotAfter)  ->  $dir" 'OK' }
    else { Write-PkiLog "Time stamping certificate $caId : $($r.Actual.Algorithm), $($r.Days) days, until $($r.NotAfter), policy $($spec.TimestampPolicyOid)  ->  $dir" 'OK' }
    if ($RevokeOld -and $oldSerial) {
        $ser = $oldSerial
        [void](Revoke-PkiCertificate -Serial $ser -CaId $caId -Reason 'superseded')
    }
    return @{ Status = 'created'; Dir = $dir; Stem = $stem; Spec = $spec; Result = $r }
}

function New-PkiRevocationServiceSet {
    <#
    .SYNOPSIS
        What pki_setup.ps1 makes after the CAs: an OCSP responder certificate for every Classic intermediate (or the ones in -CaId)
        and ONE time stamping certificate. -Replace renews them.
    #>
    param([string[]]$CaId = @(), [switch]$Replace, [switch]$SkipOcsp, [switch]$SkipTsa, [int]$OcspDays = 0, [int]$OcspKeyBits = 0, [string]$TsaLevel = 'EV')
    $made = [System.Collections.Generic.List[string]]::new()
    if (-not $SkipOcsp) {
        $cas = @(Get-PkiRevocationCas -Id $CaId -IssuingOnly -ClassicOnly)
        if ($cas.Count -eq 0) { Write-PkiLog 'No Classic intermediate CA: no OCSP responder certificate made (the OCSP server kit serves Classic CAs).' 'WARN' }
        foreach ($ca in $cas) {
            $r = New-PkiServiceCertificate -Kind Ocsp -Ca $ca -Days $OcspDays -KeyBits $OcspKeyBits -Replace:$Replace
            if ($r.Status -eq 'created') { [void]$made.Add("ocsp:$($ca.Id)") }
        }
    }
    if (-not $SkipTsa) {
        $ts = Get-PkiTimestampSettings
        $tsId = "q$($ts.Quadrant)-$($TsaLevel.ToLowerInvariant())"
        $have = @($script:Pki.Catalog | Where-Object { $_.Id -eq $tsId -and $null -ne $_.Actual })
        if ($have.Count -eq 0) { Write-PkiLog "No time stamping certificate: the CA $tsId (Quadrant $($ts.Quadrant)) is not in this PKI. Build it, or choose another with -TimestampQuadrant." 'WARN' }
        else {
            $r = New-PkiServiceCertificate -Kind Tsa -Level $TsaLevel -Replace:$Replace
            if ($r.Status -eq 'created') { [void]$made.Add("tsa:$($r.Spec.Ca.Id)") }
        }
    }
    return @($made)
}

# ------------------------------------------------------------
# Sign a CSR made on the server (the key never leaves the server)
# ------------------------------------------------------------
function Invoke-PkiSignServiceCsr {
    <#
    .SYNOPSIS
        Signs the CSR of an OCSP responder or a time stamp server with the CA, as a leaf with the right purpose, policies and
        CRL / OCSP locations. Output: <OutFolder>\<csr name>.crt and -fullchain.crt (LF).
    #>
    param(
        [Parameter(Mandatory)][string]$Csr, [Parameter(Mandatory)][ValidateSet('Ocsp', 'Tsa')][string]$Kind,
        [Parameter(Mandatory)][hashtable]$Ca, [int]$Days = 0, [string]$OutFolder
    )
    $c = $script:Pki
    if ($Ca.Kind -ne 'intermediate') { throw 'The CSR is signed by an intermediate CA (q1-ev ...).' }
    if (-not (Test-Path -LiteralPath $Csr -PathType Leaf)) { throw "CSR not found: $Csr" }
    $csrFull = (Resolve-Path -LiteralPath $Csr).Path
    $cfg0 = Get-PkiProviderConfigPath -Fips $false; $prov0 = Get-PkiProviderArgs -Fips $false
    $ver = Invoke-OpenSSL -AllowFailure -ConfigPath $cfg0 -Arguments (@('req', '-in', $csrFull, '-noout', '-verify') + $prov0)
    if ($ver.ExitCode -ne 0) { throw 'The signature of the CSR is not valid (it was changed, or it is not a CSR).' }
    $txt = (Invoke-OpenSSL -ConfigPath $cfg0 -Arguments (@('req', '-in', $csrFull, '-noout', '-text') + $prov0)).StdOut
    $family = if ($txt -match 'rsaEncryption') { 'rsa' } elseif ($txt -match 'id-ecPublicKey') { 'ecdsa' } else { throw 'Only RSA or ECDSA keys are signed here (the OCSP / time stamp services of the server kit use RSA or ECDSA).' }
    if ($family -eq 'rsa' -and $txt -match 'Public-Key: \((\d+) bit\)' -and [int]$Matches[1] -lt 2048) { throw "RSA key below 2048 bits ($($Matches[1]))." }

    $eku = if ($Kind -eq 'Ocsp') { 'OcspSigning' } else { 'TimeStamping' }
    $info = Get-PkiLeafEkuInfo -Eku @($eku) -Family $family
    $level = $Ca.Validation
    $policies = Get-PkiLeafPolicies -Level $level
    if ($Kind -eq 'Tsa') {
        $oid = [string](Get-PkiTimestampSettings).PolicyOid
        if ($oid -and -not ($policies | Where-Object { $_.Oid -eq $oid })) { $policies = @($policies) + @([ordered]@{ Label = 'TSA'; Oid = $oid; Cps = '' }) }
    }
    if ($Days -le 0) { $Days = if ($Kind -eq 'Tsa') { [int](Get-PkiTimestampSettings).Days } else { [int]$c.OcspDays } }
    $room = Get-PkiIssuerRemainingDays -IssuerId $Ca.Id
    if ($null -ne $room -and $Days -gt $room) { $Days = $room }

    $name = [System.IO.Path]::GetFileNameWithoutExtension($csrFull)
    if (-not $OutFolder) { $OutFolder = Join-Path (Split-Path -Parent $csrFull) 'signed' }
    [void][System.IO.Directory]::CreateDirectory($OutFolder)
    $ext = Join-Path $OutFolder "$name.ext.tmp.cnf"; $issuerCnf = Join-Path $OutFolder "$name.issuer.tmp.cnf"
    $crt = Join-Path $OutFolder "$name.crt"
    $L = [System.Collections.Generic.List[string]]::new()
    foreach ($h in (Get-PkiProviderConfigHeader -Fips ([bool]$Ca.Fips))) { [void]$L.Add($h) }
    $refs = Add-PkiPolicySections -Lines $L -Policies $policies -Prefix 'lp'
    $loc = Add-PkiLocationSections -Lines $L -IssuerSlug $Ca.Slug -Prefix 'll'
    [void]$L.Add('[ ext ]'); [void]$L.Add('basicConstraints = critical,CA:false'); [void]$L.Add("keyUsage = $($info.KeyUsage)")
    [void]$L.Add("extendedKeyUsage = $($info.Ekus)")
    foreach ($x in @($info.Extra)) { if ($x) { [void]$L.Add($x) } }
    [void]$L.Add('subjectKeyIdentifier = hash'); [void]$L.Add('authorityKeyIdentifier = keyid,issuer'); [void]$L.Add("certificatePolicies = $refs")
    if ($loc.Crl) { [void]$L.Add('crlDistributionPoints = @ll_crl') }
    if ($loc.Aia) { [void]$L.Add('authorityInfoAccess = @ll_aia') }
    Write-Utf8NoBom -Path $ext -Content (($L -join "`n") + "`n")
    $cp = Get-PkiCaPaths -Ca $Ca
    $issuerText = [System.IO.File]::ReadAllText($cp.Cnf)
    if ($issuerText -match '(?m)^\[ policy_any \]\s*$' -and $issuerText -notmatch '(?m)^organizationIdentifier\s*=') { $issuerText = $issuerText -replace '(?m)^(\[ policy_any \]\s*)$', "`$1`norganizationIdentifier = optional" }
    Write-Utf8NoBom -Path $issuerCnf -Content $issuerText
    $md = Resolve-PkiLeafHash -Ca $Ca -Hash ''
    try {
        $caArgs = @('ca', '-batch', '-notext', '-utf8', '-preserveDN', '-config', $issuerCnf, '-in', $csrFull, '-out', $crt, '-extfile', $ext, '-extensions', 'ext', '-days', [string]$Days, '-md', $md.Md)
        $caArgs += (Get-PkiSigOpts -Family $Ca.Actual.Family -Md $md.Md)
        $caArgs += (Get-PkiProviderArgs -Fips ([bool]$Ca.Fips))
        [void](Invoke-OpenSSL -Arguments $caArgs -ConfigPath $issuerCnf)
    }
    finally { Remove-Item -LiteralPath $ext, $issuerCnf -Force -ErrorAction SilentlyContinue }
    [void](ConvertTo-PkiLfFile -Path $crt)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append(([System.IO.File]::ReadAllText($crt)).TrimEnd() + "`n")
    foreach ($anc in @($Ca) + @(Get-PkiCaAncestors -Ca $Ca)) {
        if ($anc.Kind -eq 'root' -and $null -eq $c.ExternalRoot) { continue }
        [void]$sb.Append((([System.IO.File]::ReadAllText((Get-PkiCaPaths -Ca $anc).Crt)) -replace "`r", '').TrimEnd() + "`n")
    }
    Write-Utf8NoBom -Path (Join-Path $OutFolder "$name-fullchain.crt") -Content $sb.ToString()
    Write-PkiLog "Signed $Kind CSR by $($Ca.Id): $crt  ($Days days)" 'OK'
    return $crt
}

# ------------------------------------------------------------
# Information
# ------------------------------------------------------------
function Get-PkiCrlInfo {
    param([Parameter(Mandatory)][hashtable]$Ca)
    $p = Get-PkiCaPaths -Ca $Ca
    $r = [ordered]@{ ca = $Ca.Id; slug = $Ca.Slug; exists = $false; number = ''; lastUpdate = $null; nextUpdate = $null; daysLeft = $null; revoked = 0; issued = 0 }
    $idx = @(Get-PkiCaIndexEntries -Ca $Ca)
    $r.issued = $idx.Count; $r.revoked = @($idx | Where-Object { $_.Status -eq 'R' }).Count
    $file = if (Test-Path -LiteralPath $p.CrlPem) { $p.CrlPem } else { $null }
    if ($null -eq $file) { return $r }
    $r.exists = $true
    $cfg = Get-PkiProviderConfigPath -Fips ([bool]$Ca.Fips)
    $o = (Invoke-OpenSSL -ConfigPath $cfg -Arguments (@('crl', '-in', $file, '-noout', '-lastupdate', '-nextupdate', '-crlnumber') + (Get-PkiProviderArgs -Fips ([bool]$Ca.Fips)))).StdOut
    if ($o -match '(?m)^lastUpdate=(.+)$') { $d = ConvertFrom-PkiOpenSslDate $Matches[1]; if ($d) { $r.lastUpdate = $d.ToString('yyyy-MM-dd HH:mm') + 'Z' } }
    if ($o -match '(?m)^nextUpdate=(.+)$') { $d = ConvertFrom-PkiOpenSslDate $Matches[1]; if ($d) { $r.nextUpdate = $d.ToString('yyyy-MM-dd HH:mm') + 'Z'; $r.daysLeft = [int][Math]::Floor(($d - [DateTime]::UtcNow).TotalDays) } }
    if ($o -match '(?m)^(?:crl_number|crlNumber)=(\S+)') { $r.number = $Matches[1] }
    return $r
}

function Get-PkiRevocationUrls {
    param([Parameter(Mandatory)][hashtable]$Ca)
    $c = $script:Pki
    $f = { param($u) $u -replace '\{ca\}', $Ca.Slug }
    return [ordered]@{
        crl = @($c.CrlUrls | ForEach-Object { & $f $_ }); ocsp = @($c.OcspUrls | ForEach-Object { & $f $_ }); caIssuers = @($c.CaIssuerUrls | ForEach-Object { & $f $_ })
    }
}

function Get-PkiServiceCertInfo {
    param([Parameter(Mandatory)][string]$Dir, [Parameter(Mandatory)][string]$Stem)
    $crt = Join-Path $Dir "$Stem.crt"
    if (-not (Test-Path -LiteralPath $crt)) { return $null }
    $cfg0 = Get-PkiProviderConfigPath -Fips $false
    $t = (Invoke-OpenSSL -ConfigPath $cfg0 -Arguments (@('x509', '-in', $crt, '-noout', '-serial', '-subject', '-enddate') + (Get-PkiProviderArgs -Fips $false))).StdOut
    $end = if ($t -match '(?m)^notAfter=(.+)$') { ConvertFrom-PkiOpenSslDate $Matches[1] } else { $null }
    return [ordered]@{
        file = $crt; key = (Test-Path -LiteralPath (Join-Path $Dir "$Stem.key")); serial = $(if ($t -match '(?m)^serial=(\S+)') { $Matches[1] } else { '' })
        subject = $(if ($t -match '(?m)^subject=(.+)$') { $Matches[1].Trim() } else { '' })
        notAfter = $(if ($end) { $end.ToString('yyyy-MM-dd') } else { '' }); daysLeft = $(if ($end) { [int][Math]::Floor(($end - [DateTime]::UtcNow).TotalDays) } else { $null })
    }
}

function Get-PkiRevocationStatus {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($ca in (Get-PkiRevocationCas)) {
        $crl = Get-PkiCrlInfo -Ca $ca
        $oc = $null
        if ($ca.Kind -eq 'intermediate') { $oc = Get-PkiServiceCertInfo -Dir (Join-Path (Get-PkiOcspRoot) $ca.Id) -Stem "$($ca.Id)-ocsp" }
        [void]$rows.Add([ordered]@{ ca = $ca.Id; kind = $ca.Kind; slug = $ca.Slug; crl = $crl; ocspResponder = $oc; urls = (Get-PkiRevocationUrls -Ca $ca) })
    }
    $tsa = @()
    $tr = Get-PkiTsaRoot
    if (Test-Path -LiteralPath $tr) {
        foreach ($d in (Get-ChildItem -LiteralPath $tr -Directory)) { $i = Get-PkiServiceCertInfo -Dir $d.FullName -Stem "$($d.Name)-tsa"; if ($i) { $i['ca'] = $d.Name; $tsa += $i } }
    }
    $ts = Get-PkiTimestampSettings
    return [ordered]@{ generated = [DateTime]::UtcNow.ToString('o'); pki = $script:Pki.PkiRoot; crlDays = [int]$script:Pki.CrlDays; ocspDays = [int]$script:Pki.OcspDays
        timestamp = [ordered]@{ quadrant = $ts.Quadrant; policyOid = $ts.PolicyOid; days = $ts.Days; certificates = @($tsa) }; cas = @($rows) }
}

function Show-PkiRevocationStatus {
    param([Parameter(Mandatory)]$Status)
    Write-Host ''
    Write-Host ('{0,-13} {1,-12} {2,-17} {3,-9} {4,-8} {5}' -f 'CA', 'CRL NUMBER', 'NEXT UPDATE', 'DAYS', 'REVOKED', 'OCSP RESPONDER') -ForegroundColor Cyan
    foreach ($r in $Status.cas) {
        $crl = $r.crl
        $oc = if ($r.kind -ne 'intermediate') { '-' } elseif ($null -eq $r.ocspResponder) { 'none' } else { "until $($r.ocspResponder.notAfter) ($($r.ocspResponder.daysLeft) d)" }
        $left = if ($null -ne $crl.daysLeft) { $crl.daysLeft } else { '-' }
        $col = if ($null -ne $crl.daysLeft -and $crl.daysLeft -lt 14) { 'Yellow' } else { 'Gray' }
        Write-Host ('{0,-13} {1,-12} {2,-17} {3,-9} {4,-8} {5}' -f $r.ca, $crl.number, $crl.nextUpdate, $left, "$($crl.revoked)/$($crl.issued)", $oc) -ForegroundColor $col
    }
    foreach ($t in $Status.timestamp.certificates) { Write-Host ("Time stamping: {0}  until {1} ({2} d)  policy {3}" -f $t.ca, $t.notAfter, $t.daysLeft, $Status.timestamp.policyOid) -ForegroundColor Gray }
    if (@($Status.timestamp.certificates).Count -eq 0) { Write-Host 'Time stamping: no certificate yet (PkiRevocation.ps1 -Action NewTsa)' -ForegroundColor DarkYellow }
    Write-Host ''
}

function Write-PkiRevocationInfo {
    <#
    .SYNOPSIS
        pki\revocation-info.json and pki\REVOCATION-INFO.txt: CRL dates and numbers, URLs, OCSP responders, time stamping (LF).
    #>
    $st = Get-PkiRevocationStatus
    $c = $script:Pki
    $json = Join-Path $c.PkiRoot 'revocation-info.json'
    Write-Utf8NoBom -Path $json -Content (($st | ConvertTo-Json -Depth 8) + "`n")
    $buf = [System.Text.StringBuilder]::new()
    $w = { param($x) [void]$buf.Append($x + "`n") }
    & $w "REVOCATION INFORMATION  -  $($c.PkiRoot)"
    & $w "Written $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm'))Z by $($script:PkiGeneratorVersion)"
    & $w ('=' * 110)
    & $w 'URLs in the certificates ({ca} = the file name of the issuing CA):'
    foreach ($u in $c.CrlUrls) { & $w "  CRL        $u" }
    foreach ($u in $c.OcspUrls) { & $w "  OCSP       $u" }
    foreach ($u in $c.CaIssuerUrls) { & $w "  CA issuer  $u" }
    & $w ''
    & $w ('{0,-13} {1,-9} {2,-19} {3,-17} {4,-7} {5}' -f 'CA', 'CRL NO.', 'LAST UPDATE', 'NEXT UPDATE', 'DAYS', 'REVOKED/ISSUED')
    foreach ($r in $st.cas) { $k = $r.crl; & $w ('{0,-13} {1,-9} {2,-19} {3,-17} {4,-7} {5}' -f $r.ca, $k.number, $k.lastUpdate, $k.nextUpdate, $k.daysLeft, "$($k.revoked)/$($k.issued)") }
    & $w ''
    & $w "OCSP RESPONDER CERTIFICATES  (folder pki\ocsp\<ca>\ ; served by the PKI server kit, see PKI-SERVER-MANUAL.txt)"
    foreach ($r in $st.cas) { if ($r.kind -eq 'intermediate') { $o = $r.ocspResponder; & $w $(if ($null -eq $o) { "  $($r.ca): none  (PkiRevocation.ps1 -Action NewOcsp -Ca $($r.ca))" } else { "  $($r.ca): serial $($o.serial)  until $($o.notAfter) ($($o.daysLeft) days)" }) } }
    & $w ''
    & $w "TIME STAMPING  (folder pki\tsa\<ca>\)   Quadrant $($st.timestamp.quadrant) (1 = Classic non-FIPS)   policy OID $($st.timestamp.policyOid)"
    foreach ($t in $st.timestamp.certificates) { & $w "  $($t.ca): serial $($t.serial)  until $($t.notAfter) ($($t.daysLeft) days)" }
    & $w ''
    & $w 'RENEW / EDIT'
    & $w '  New CRL         .\PkiRevocation.ps1 -Action NewCrl [-Ca q1-ev] [-CrlDays 90]'
    & $w '  Revoke          .\PkiRevocation.ps1 -Action Revoke -Certificate <file.crt> [-Reason keyCompromise]'
    & $w '  New OCSP cert   .\PkiRevocation.ps1 -Action NewOcsp [-Ca q1-ev] -Replace [-OcspDays 180] [-OcspKeyBits 3072] [-CommonName ...]'
    & $w '  New TSA cert    .\PkiRevocation.ps1 -Action NewTsa -Replace [-TimestampPolicyOid 1.3.6.1.4.1.67096.1.4] [-TimestampDays 3650]'
    & $w '  Then            .\New-PkiServerPackage.ps1  and  sudo ./pki-server.sh update   on the server'
    Write-Utf8NoBom -Path (Join-Path $c.PkiRoot 'REVOCATION-INFO.txt') -Content $buf.ToString()
    Write-PkiLog "Revocation information: $json" 'OK'
    return $st
}
