# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# Module 19: signs the CSR of ANOTHER private CA ("external CA") with one of our CAs.
#   Default signer : our Classic non-FIPS Quadrant Root q1-root (-SignWith QuadrantRoot, -Quadrant 1)
#   Alternative    : our DV / OV / EV intermediate (-SignWith Intermediate, needs pathLen >= 1) or any CA id (-Ca q2-ev)
# Output (one NEW folder per request, never overwritten):
#   external-ca\<name>_<yyyyMMdd-HHmmss>\<name>.csr  <name>.crt  <name>-fullchain.crt  <name>-chain.crt  root.crt  ca-info.json  README.txt
# The certificate is issued with "openssl ca" from the signer's database: it is in the signer's index.txt and can be revoked
# (PkiRevocation.ps1 -Action Revoke) and shows in the CRL.
# Depends on: 00, 01, 02, 03, 04, 12, 14, 18
# ============================================================

function Get-PkiExternalCaSigner {
    # Resolves the signing CA from -Ca, or from -SignWith / -Quadrant / -Level.
    param([string]$CaId, [string]$SignWith = 'QuadrantRoot', [int]$Quadrant = 1, [string]$Level = 'OV')
    $all = @($script:Pki.Catalog | Where-Object { $null -ne $_.Actual })
    $id = if ($CaId) { $CaId } elseif ($SignWith -eq 'QuadrantRoot') { "q$Quadrant-root" } else { "q$Quadrant-$($Level.ToLowerInvariant())" }
    $ca = @($all | Where-Object { $_.Id -eq $id })[0]
    if ($null -eq $ca) { throw "The signing CA '$id' does not exist in this PKI. Built: $((@($all | ForEach-Object { $_.Id }) -join ', ')). (-Quadrant, -Level, -SignWith or -Ca <id>)" }
    if ($ca.Kind -notin 'intermediate', 'quadrant') { throw "'$id' is a $($ca.Kind) CA. Sign with an intermediate (q1-ov ...) or a Quadrant Root (q1-root ...): the Enterprise and Track Roots stay offline and sign only our own CAs." }
    return $ca
}

function Get-PkiCertPathLen {
    # pathLenConstraint of a CA certificate file; -1 = none.
    param([Parameter(Mandatory)][string]$CertFile, [Parameter(Mandatory)][hashtable]$Ca)
    $cfg = Get-PkiProviderConfigPath -Fips ([bool]$Ca.Fips)
    $o = (Invoke-OpenSSL -ConfigPath $cfg -Arguments (@('x509', '-in', $CertFile, '-noout', '-ext', 'basicConstraints') + (Get-PkiProviderArgs -Fips ([bool]$Ca.Fips)))).StdOut
    if ($o -match 'pathlen:\s*(\d+)') { return [int]$Matches[1] }
    return -1
}

function Invoke-PkiSignExternalCa {
    <#
    .SYNOPSIS
        Signs the CSR of another private CA with one of our CAs and writes the result into its own folder.
    #>
    param(
        [Parameter(Mandatory)][string]$Csr, [Parameter(Mandatory)][hashtable]$Signer,
        [string]$Name, [string]$Level = 'OV', [int]$Days = 1825, [int]$PathLen = 0,
        [string[]]$PermitDns = @(), [string[]]$PermitEmail = @(), [string]$OutRoot, [switch]$Force
    )
    $c = $script:Pki
    if (-not (Test-Path -LiteralPath $Csr -PathType Leaf)) { throw "CSR not found: $Csr" }
    $csrFull = (Resolve-Path -LiteralPath $Csr).Path
    $cfg0 = Get-PkiProviderConfigPath -Fips $false; $prov0 = Get-PkiProviderArgs -Fips $false

    # --- the request ---
    $ver = Invoke-OpenSSL -AllowFailure -ConfigPath $cfg0 -Arguments (@('req', '-in', $csrFull, '-noout', '-verify') + $prov0)
    if ($ver.ExitCode -ne 0) { throw 'The signature of the CSR is not valid (it was changed, or it is not a PKCS#10 request).' }
    $txt = (Invoke-OpenSSL -ConfigPath $cfg0 -Arguments (@('req', '-in', $csrFull, '-noout', '-text') + $prov0)).StdOut
    $subject = ''
    if ($txt -match '(?m)^\s*Subject:\s*(?<s>.+)$') { $subject = $Matches['s'].Trim() }
    if (-not $subject) { throw 'The CSR has no subject: a CA needs a distinguished name.' }
    $keyDesc = ''
    if ($txt -match 'rsaEncryption') {
        $bits = if ($txt -match 'Public-Key: \((\d+) bit\)') { [int]$Matches[1] } else { 0 }
        if ($bits -lt 4096) { throw "The CA key of the request is RSA $bits bit: an external CA key needs RSA 4096 or more (equal-strength minimums: ECDSA P-384, ML-DSA-65)." }
        $keyDesc = "RSA-$bits"
    }
    elseif ($txt -match 'id-ecPublicKey') {
        if ($txt -notmatch 'P-384|P-521|secp384r1|secp521r1') { throw 'An external ECDSA CA key needs P-384 or P-521 (P-256 is weaker than RSA 4096).' }
        $keyDesc = if ($txt -match 'P-521|secp521r1') { 'ECDSA-P521' } else { 'ECDSA-P384' }
    }
    elseif ($txt -match '(?i)ML-?DSA-?(\d+)') {
        if ([int]$Matches[1] -lt 65) { throw "ML-DSA-$($Matches[1]) is below the minimum: an external CA key needs ML-DSA-65 or ML-DSA-87 (equal strength to RSA 4096 / P-384)." }
        $keyDesc = "ML-DSA-$($Matches[1])"
    }
    else { throw 'Unsupported key type in the request (RSA, ECDSA P-384 / P-521 or ML-DSA).' }
    # the request itself must be signed with SHA-256 or stronger (ML-DSA signs without a digest)
    if ($keyDesc -notlike 'ML-DSA*') {
        $sigAlg = if ($txt -match '(?m)^\s*Signature Algorithm:\s*(?<a>\S+)') { $Matches['a'] } else { '' }
        if ($sigAlg -match '(?i)md5|sha1(?!\d)|sha-1|md2|md4') { throw "The CSR is signed with ${sigAlg}: SHA-256 or stronger is required (openssl req -new -sha384 ...)." }
    }
    # never sign a request that carries the name of one of OUR CAs
    $norm = { param($v) (($v -replace '\s*=\s*', '=' -replace '\s*,\s*', ',').Trim().ToLowerInvariant()) }
    foreach ($ours in @($c.Catalog | Where-Object { $_.Actual })) {
        $p0 = Get-PkiCaPaths -Ca $ours
        if (-not (Test-Path -LiteralPath $p0.Crt)) { continue }
        $os = (Invoke-OpenSSL -ConfigPath $cfg0 -Arguments (@('x509', '-in', $p0.Crt, '-noout', '-subject') + $prov0)).StdOut -replace '^subject\s*=\s*', ''
        if ((& $norm $os) -eq (& $norm $subject)) { throw "The request uses the name of our own CA $($ours.Id). Refused." }
    }

    # --- the signer ---
    $sp = Get-PkiCaPaths -Ca $Signer
    $signerPath = Get-PkiCertPathLen -CertFile $sp.Crt -Ca $Signer
    if ($signerPath -eq 0) {
        $msg = "$($Signer.Id) has pathLenConstraint 0: it may issue end-entity certificates only. A CA certificate below it is rejected by OpenSSL, Windows and browsers (path length constraint exceeded)."
        if (-not $Force) {
            throw ($msg + " Use -SignWith QuadrantRoot, the default (its pathLenConstraint is 1: the other CA becomes a sibling of our intermediates), or build the PKI with -IntermediatePathLen 1, or -Force to issue it anyway (lab / the other CA is only a trust anchor for you).")
        }
        Write-PkiLog "$msg -Force: issued anyway." 'WARN'
    }
    $maxPath = if ($signerPath -lt 0) { 3 } else { [Math]::Max(0, $signerPath - 1) }
    if ($PathLen -gt $maxPath) { Write-PkiLog "PathLen $PathLen is more than $($Signer.Id) allows: lowered to $maxPath." 'WARN'; $PathLen = $maxPath }

    $room = Get-PkiIssuerRemainingDays -IssuerId $Signer.Id
    if ($null -ne $room -and $Days -gt $room) { Write-PkiLog "Validity limited by the signer: $Days -> $room days." 'WARN'; $Days = $room }

    $familyKnown = $Signer.Actual.Family
    $levelUp = $Level.ToUpperInvariant()
    $policies = Get-PkiLeafPolicies -Level $levelUp

    # --- the output folder ---
    if (-not $Name) { $Name = if ($subject -match 'CN\s*=\s*(?<cn>[^,/]+)') { $Matches['cn'].Trim() } else { 'external-ca' } }
    $safe = (($Name -replace '[^A-Za-z0-9._-]+', '-').Trim('-.')); if (-not $safe) { $safe = 'external-ca' }
    if (-not $OutRoot) { $OutRoot = Join-Path (Split-Path -Parent $c.PkiRoot) 'external-ca' }
    $dir = Join-Path $OutRoot ("{0}_{1}" -f $safe, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    [void][System.IO.Directory]::CreateDirectory($dir)
    $csrOut = Join-Path $dir "$safe.csr"; $crt = Join-Path $dir "$safe.crt"
    Write-Utf8NoBom -Path $csrOut -Content ((([System.IO.File]::ReadAllText($csrFull)) -replace "`r", '').TrimEnd() + "`n")

    # --- extensions and signing ---
    $ext = Join-Path $dir 'ext.tmp.cnf'; $issuerCnf = Join-Path $dir 'issuer.tmp.cnf'
    $L = [System.Collections.Generic.List[string]]::new()
    foreach ($h in (Get-PkiProviderConfigHeader -Fips ([bool]$Signer.Fips))) { [void]$L.Add($h) }
    $refs = Add-PkiPolicySections -Lines $L -Policies $policies -Prefix 'lp'
    $loc = Add-PkiLocationSections -Lines $L -IssuerSlug $Signer.Slug -Prefix 'll'
    $nc = @()
    foreach ($d in $PermitDns) { if ($d) { $nc += "permitted;DNS:$d" } }
    foreach ($m in $PermitEmail) { if ($m) { $nc += "permitted;email:$m" } }
    [void]$L.Add('[ ext ]')
    [void]$L.Add("basicConstraints = critical,CA:true,pathlen:$PathLen")
    [void]$L.Add('keyUsage = critical,keyCertSign,cRLSign')
    [void]$L.Add('subjectKeyIdentifier = hash'); [void]$L.Add('authorityKeyIdentifier = keyid,issuer')
    [void]$L.Add("certificatePolicies = $refs")
    if ($nc.Count -gt 0) { [void]$L.Add('nameConstraints = critical,' + ($nc -join ',')) }
    if ($loc.Crl) { [void]$L.Add('crlDistributionPoints = @ll_crl') }
    if ($loc.Aia) { [void]$L.Add('authorityInfoAccess = @ll_aia') }
    Write-Utf8NoBom -Path $ext -Content (($L -join "`n") + "`n")
    $issuerText = [System.IO.File]::ReadAllText($sp.Cnf)
    if ($issuerText -match '(?m)^\[ policy_any \]\s*$' -and $issuerText -notmatch '(?m)^organizationIdentifier\s*=') { $issuerText = $issuerText -replace '(?m)^(\[ policy_any \]\s*)$', "`$1`norganizationIdentifier = optional" }
    Write-Utf8NoBom -Path $issuerCnf -Content $issuerText
    $md = if ($Signer.Kind -eq 'quadrant') { Get-PkiIssueMd -Kind 'quadrant' -Family $Signer.Actual.Family } else { Get-PkiIssueMd -Kind 'intermediate' -Family $Signer.Actual.Family }
    try {
        $caArgs = @('ca', '-batch', '-notext', '-utf8', '-preserveDN', '-config', $issuerCnf, '-in', $csrFull, '-out', $crt, '-extfile', $ext, '-extensions', 'ext', '-days', [string]$Days)
        if ($md -ne 'default') { $caArgs += @('-md', $md) }
        $caArgs += (Get-PkiSigOpts -Family $Signer.Actual.Family -Md $md)
        $caArgs += (Get-PkiProviderArgs -Fips ([bool]$Signer.Fips))
        [void](Invoke-OpenSSL -Arguments $caArgs -ConfigPath $issuerCnf)
    }
    catch { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue; throw }
    finally { Remove-Item -LiteralPath $ext, $issuerCnf -Force -ErrorAction SilentlyContinue }
    [void](ConvertTo-PkiLfFile -Path $crt)

    # --- chain files (LF) ---
    $sbFull = [System.Text.StringBuilder]::new(); $sbChain = [System.Text.StringBuilder]::new()
    [void]$sbFull.Append(([System.IO.File]::ReadAllText($crt)).TrimEnd() + "`n")
    $rootPem = ''
    foreach ($anc in @($Signer) + @(Get-PkiCaAncestors -Ca $Signer)) {
        $pem = (([System.IO.File]::ReadAllText((Get-PkiCaPaths -Ca $anc).Crt)) -replace "`r", '').TrimEnd() + "`n"
        if ($anc.Kind -eq 'root') { $rootPem = $pem; if ($null -eq $c.ExternalRoot) { continue } }
        [void]$sbFull.Append($pem); [void]$sbChain.Append($pem)
    }
    Write-Utf8NoBom -Path (Join-Path $dir "$safe-fullchain.crt") -Content $sbFull.ToString()
    Write-Utf8NoBom -Path (Join-Path $dir "$safe-chain.crt") -Content $sbChain.ToString()
    if ($rootPem) { Write-Utf8NoBom -Path (Join-Path $dir 'root.crt') -Content $rootPem }
    # all our CAs of the chain + the root: the trust bundle he verifies with
    $bundle = $sbChain.ToString() + $rootPem
    Write-Utf8NoBom -Path (Join-Path $dir 'our-ca-bundle.crt') -Content $bundle

    # --- verify ---
    $chainOk = $false
    $vr = Invoke-OpenSSL -AllowFailure -ConfigPath $cfg0 -Arguments (@('verify') + $prov0 + @('-CAfile', (Join-Path $dir 'our-ca-bundle.crt'), '-x509_strict', $crt))
    $chainOk = ($vr.ExitCode -eq 0)
    $ct = (Invoke-OpenSSL -ConfigPath $cfg0 -Arguments (@('x509', '-in', $crt, '-noout', '-serial', '-fingerprint', '-sha256', '-enddate') + $prov0)).StdOut
    $serial = if ($ct -match 'serial=(\S+)') { $Matches[1] } else { '' }
    $fp = if ($ct -match '(?i)sha256 Fingerprint=(\S+)') { $Matches[1] } else { '' }
    $end = if ($ct -match 'notAfter=(.+)') { $Matches[1].Trim() } else { '' }
    $strictOk = ($signerPath -ne 0)
    $info = [ordered]@{
        name = $safe; subject = $subject; keyAlgorithm = $keyDesc; signer = $Signer.Id; signerKind = $Signer.Kind; signerCommonName = $Signer["CommonName"]
        policyLevel = $levelUp; policies = @($policies | ForEach-Object { $_.Oid }); pathLen = $PathLen; days = $Days; notAfter = $end; serial = $serial; sha256 = $fp
        signatureDigest = $md; nameConstraintsPermitted = @($PermitDns) + @($PermitEmail)
        openSslVerify = $chainOk; validForStrictPathLen = $strictOk
        files = @(Get-ChildItem -LiteralPath $dir -File | ForEach-Object { $_.Name } | Sort-Object)
        createdUtc = [DateTime]::UtcNow.ToString('o'); generator = "SignExternalCa / pki_setup $($script:PkiGeneratorVersion)"
    }
    Write-Utf8NoBom -Path (Join-Path $dir 'ca-info.json') -Content (($info | ConvertTo-Json -Depth 5) + "`n")
    $readme = @"
SIGNED CA CERTIFICATE FOR A PRIVATE CA        $safe
=====================================================================
Signed by    : $($Signer.Id)   $($Signer["CommonName"])   ($($Signer.Kind))
Subject      : $subject
Key          : $keyDesc          Valid until: $end   ($Days days)
Serial       : $serial
SHA-256      : $fp
Constraints  : CA:TRUE, pathLenConstraint $PathLen$(if ($nc.Count -gt 0) { ', name constraints (permitted): ' + (($nc | ForEach-Object { $_ -replace '^permitted;', '' }) -join ', ') })
Policy level : $levelUp     Signature digest: $md
OpenSSL strict verify against our chain: $(if ($chainOk) { 'OK' } else { 'FAILED' })        Valid below a pathLen-0 signer: $(if ($strictOk) { 'yes' } else { 'NO (issued with -Force)' })

FILES
  $safe.csr             his request (unchanged)
  $safe.crt             HIS CA CERTIFICATE signed by us   (install it in his CA together with his private key)
  $safe-fullchain.crt   his certificate + our chain ($($Signer.Id) ... up to, not including, our Enterprise Root): use as the CA chain of his certificates
  $safe-chain.crt       our chain only
  root.crt              OUR Enterprise Root: clients must trust it (it is the trust anchor of everything he issues)
  our-ca-bundle.crt     our chain + root, for "openssl verify -CAfile"
  ca-info.json          the facts above for scripts

HIS SIDE
  Every certificate he issues is valid only when the client trusts OUR Enterprise Root (root.crt). His leaf certificates should be delivered with
  <leaf> + $safe-fullchain.crt.   Check:  openssl verify -CAfile our-ca-bundle.crt -untrusted $safe-chain.crt <his leaf.crt>

OUR SIDE
  The certificate is in the index.txt of $($Signer.Id): revoke it with  .\PkiRevocation.ps1 -Action Revoke -Certificate <this .crt>  (the CRL of $($Signer.Id) lists it).
  He does NOT receive any private key of ours; we do not hold his.
"@
    Write-Utf8NoBom -Path (Join-Path $dir 'README.txt') -Content ($readme.Replace("`r", '') + "`n")
    Write-PkiLog "Signed $keyDesc CA '$safe' with $($Signer.Id): $dir" 'OK'
    if (-not $chainOk) { Write-PkiLog 'openssl verify (strict) against our chain failed - see README.txt.' 'WARN' }
    return [pscustomobject]@{ Dir = $dir; Certificate = $crt; Info = $info }
}
