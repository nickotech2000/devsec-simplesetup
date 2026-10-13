# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# Module 22: signs the CSR of ANOTHER department / person (a LEAF certificate) with one of our INTERMEDIATE CAs, after checking the
#            request against the specification of this PKI, and the shared CSR checker used by SignExternalCa.ps1 (CA requests).
#
#   Read-PkiCsr            reads a PKCS#10 request with OpenSSL: subject (in order), key, signature digest, requested extensions
#   Test-PkiCsrSpec        checks it against the spec of a profile (Leaf / Ca, level DV / OV / EV, track, purpose): returns FINDINGS
#   Write-PkiCsrFindings   prints the findings in colour: red ERROR, yellow WARN, green OK, cyan INFO - each with the reason and the fix
#   Invoke-PkiSignCsr      leaf signing: default level DV, issuer q<N>-<level>, extensions decided by US (the request only gives subject,
#                          key and the names); the certificate is issued with "openssl ca" (index.txt: it can be revoked)
#
# THE SPEC (the same rules are in devkit/lib/pki-csr.py, used by SignCsr.sh)
#   Signature  valid, SHA-256 or stronger (ML-DSA signs without a digest)
#   Key        Classic quadrants (1, 2): RSA 2048 / 3072 / 4096 / 8192, ECDSA P-256 / P-384 / P-521.   Quantum (3, 4): ML-DSA-44 / 65 / 87.
#              Code signing: RSA >= 4096, ECDSA >= P-384, ML-DSA >= 65.   Never: RSA < 2048, other curves, Ed25519, DSA, RSA-PSS keys.
#   Subject    DV  CN only (anything else in the request is dropped with a warning)
#              OV  required C (2 letters), O, CN.  Recommended ST, L.  Allowed: OU, street, postalCode, name, emailAddress, telephoneNumber
#              EV  OV + required ST, L, serialNumber, businessCategory (one of 4), jurisdictionC.  Recommended jurisdictionST, postalCode
#              Code signing: C, O, CN (CN = O recommended) - nothing else is needed
#   Names      TLS: DNS and IP. EV: no wildcard, no IP, no internal name, no e-mail. S/MIME: e-mail only. Code signing / TSA / OCSP: no SAN.
#   Validity   DV 5 years, OV 3 years, EV 397 days at most (everything EV); never longer than the issuer
#   Ignored    keyUsage, extendedKeyUsage, basicConstraints, policies of the request: WE decide them (-Purpose, -Level). CA:TRUE is REFUSED.
# Depends on: 00-04, 12, 13 (Get-PkiIssuerRemainingDays), 14, 18
# ============================================================

$script:PkiCsrSubjectAttrs = [ordered]@{
    DV = @('CN')
    OV = @('C', 'ST', 'L', 'street', 'postalCode', 'O', 'OU', 'CN', 'name', 'emailAddress', 'telephoneNumber', 'serialNumber')     # serialNumber = the company ID (5.2.2)
    EV = @('C', 'ST', 'L', 'street', 'postalCode', 'O', 'OU', 'CN', 'name', 'emailAddress', 'telephoneNumber',
           'businessCategory', 'serialNumber', 'jurisdictionC', 'jurisdictionST', 'jurisdictionL', 'organizationIdentifier')
}
# A request made by New-PkiCsr.ps1 / new-pki-csr.sh may carry this DNS name in its subjectAltName: it means "add the development SAN list" (like
# -AddDevelopmentSAN). The marker itself is never put in a certificate. (5.2.2)
$script:PkiCsrDevSanMarker = 'add-development-san.pki-marker.invalid'
$script:PkiCsrBusinessCategories = @('Private Organization', 'Government Entity', 'Business Entity', 'Non-Commercial Entity')
$script:PkiCsrInternalTlds = @('internal', 'local', 'localhost', 'lan', 'corp', 'home', 'intranet', 'private', 'test', 'invalid', 'developer', 'api', 'ldap')

function New-PkiFinding {
    param([Parameter(Mandatory)][ValidateSet('ERROR', 'WARN', 'OK', 'INFO')][string]$Severity, [Parameter(Mandatory)][string]$Code,
          [string]$Field = '', [Parameter(Mandatory)][string]$Message, [string]$Fix = '')
    return [pscustomobject]@{ Severity = $Severity; Code = $Code; Field = $Field; Message = $Message; Fix = $Fix }
}

function Write-PkiCsrFindings {
    <#
    .SYNOPSIS
        Prints findings: [ERROR] red, [WARN] yellow, [ OK ] green, [INFO] cyan. Every ERROR / WARN shows what is wrong (Message) and how to fix it (Fix).
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings, [switch]$NoColor, [switch]$HideOk)
    $col = @{ ERROR = 'Red'; WARN = 'Yellow'; OK = 'Green'; INFO = 'Cyan' }
    $tag = @{ ERROR = '[ERROR]'; WARN = '[WARN] '; OK = '[ OK ]'; INFO = '[INFO]' }
    $say = { param($t, $c) if ($NoColor -or $env:NO_COLOR) { Write-Host $t } else { Write-Host $t -ForegroundColor $c } }
    foreach ($f in @($Findings)) {
        if ($HideOk -and $f.Severity -eq 'OK') { continue }
        $field = if ($f.Field) { ('{0,-22}' -f $f.Field) } else { (' ' * 22) }
        $codeTxt = if ($f.Severity -in 'ERROR', 'WARN') { "  [$($f.Code)]" } else { '' }
        & $say ("  {0} {1} {2}{3}" -f $tag[$f.Severity], $field, $f.Message, $codeTxt) $col[$f.Severity]
        if ($f.Fix -and $f.Severity -in 'ERROR', 'WARN') { & $say ("           {0}  fix: {1}" -f (' ' * 22), $f.Fix) 'DarkGray' }
    }
    $e = @($Findings | Where-Object { $_.Severity -eq 'ERROR' }).Count; $w = @($Findings | Where-Object { $_.Severity -eq 'WARN' }).Count
    $sum = "  Result: $e error(s), $w warning(s)."
    if ($e -gt 0) { & $say ($sum + ' The request does NOT follow the specification of this PKI: nothing was signed.') 'Red' }
    elseif ($w -gt 0) { & $say ($sum + ' The request can be signed; read the warnings.') 'Yellow' }
    else { & $say ($sum + ' The request follows the specification.') 'Green' }
}

function Read-PkiCsr {
    <#
    .SYNOPSIS
        Reads a PKCS#10 request with OpenSSL. Returns Subject (ordered @(name, value) pairs, OpenSSL short names), key facts, the digest of the
        request signature, the requested names and whether the request asks for CA:TRUE. Throws only when the file is not a request at all.
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "CSR not found: $Path" }
    $full = (Resolve-Path -LiteralPath $Path).Path
    $cfg = Get-PkiProviderConfigPath -Fips $false; $prov = Get-PkiProviderArgs -Fips $false
    $v = Invoke-OpenSSL -AllowFailure -ConfigPath $cfg -Arguments (@('req', '-in', $full, '-noout', '-verify') + $prov)
    $t = Invoke-OpenSSL -AllowFailure -ConfigPath $cfg -Arguments (@('req', '-in', $full, '-noout', '-text') + $prov)
    if ($t.StdOut -notmatch 'Certificate Request') { throw "'$Path' is not a PKCS#10 certificate request (PEM). OpenSSL says: $(($t.StdErr -split "`n")[0])" }
    $text = $t.StdOut
    $sj = Invoke-OpenSSL -AllowFailure -ConfigPath $cfg -Arguments (@('req', '-in', $full, '-noout', '-subject', '-nameopt', 'multiline,utf8,sname') + $prov)
    $pairs = [System.Collections.Generic.List[object]]::new()
    foreach ($line in ($sj.StdOut -split "`r?`n")) {
        if ($line -match '^\s+(?<k>\S+)\s*=\s?(?<v>.*)$') { [void]$pairs.Add(@($Matches['k'], $Matches['v'].TrimEnd())) }
    }
    # key
    $alg = 'OTHER'; $bits = 0; $curve = ''; $ml = 0; $algText = ''
    if ($text -match '(?m)Public Key Algorithm:\s*(?<a>.+)$') { $algText = $Matches['a'].Trim() }
    if ($algText -match '^rsaEncryption$') { $alg = 'RSA'; if ($text -match 'Public-Key: \((?<b>\d+) bit\)') { $bits = [int]$Matches['b'] } }
    elseif ($algText -match 'id-ecPublicKey|^EC$') {
        $alg = 'ECDSA'
        $oid = if ($text -match 'ASN1 OID:\s*(?<o>\S+)') { $Matches['o'] } else { '' }
        $curve = switch -Regex ($oid) { '^(prime256v1|secp256r1)$' { 'P-256' } '^secp384r1$' { 'P-384' } '^secp521r1$' { 'P-521' } default { if ($oid) { $oid } else { 'unknown' } } }
    }
    elseif ($algText -match '(?i)^ML-?DSA-?(?<n>\d+)') { $alg = 'MLDSA'; $ml = [int]$Matches['n'] }
    elseif ($algText -match '(?i)ED25519|ED448|DSA|RSASSA-PSS|X25519|SLH|ML-KEM') { $alg = $algText.ToUpperInvariant() }
    $sig = if ($text -match '(?m)Signature Algorithm:\s*(?<s>\S+)') { $Matches['s'] } else { '' }
    # requested extensions
    $san = [ordered]@{ Dns = [System.Collections.Generic.List[string]]::new(); Ip = [System.Collections.Generic.List[string]]::new(); Email = [System.Collections.Generic.List[string]]::new(); Other = [System.Collections.Generic.List[string]]::new() }
    $reqExt = [System.Collections.Generic.List[string]]::new()
    $ca = $false
    $policyOids = [System.Collections.Generic.List[string]]::new()
    if ($text -match '(?s)Requested Extensions:(?<x>.*?)(\r?\n\s*Signature Algorithm:)') {
        $block = $Matches['x']
        $lines = $block -split "`r?`n"
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $ln = $lines[$i]
            if ($ln -match '^\s{12}(?<n>\S.*?):\s*(critical)?\s*$' -or $ln -match '^\s+(?<n>X509v3 [^:]+|[A-Za-z0-9. ]+):\s*(critical)?\s*$') {
                $name = $Matches['n'].Trim(); [void]$reqExt.Add($name)
                $val = if ($i + 1 -lt $lines.Count) { $lines[$i + 1].Trim() } else { '' }
                if ($name -match 'Subject Alternative Name') {
                    foreach ($tok in ($val -split ',\s*(?=(?:DNS|IP Address|email|URI|othername|DirName|Registered ID)[:])')) {
                        $tk = $tok.Trim()
                        if ($tk -match '^DNS:(?<v>.+)$') { [void]$san.Dns.Add($Matches['v']) }
                        elseif ($tk -match '^IP Address:(?<v>.+)$') { [void]$san.Ip.Add($Matches['v']) }
                        elseif ($tk -match '^email:(?<v>.+)$') { [void]$san.Email.Add($Matches['v']) }
                        elseif ($tk) { [void]$san.Other.Add($tk) }
                    }
                }
                if ($name -match 'Basic Constraints' -and $val -match 'CA:TRUE') { $ca = $true }
                if ($name -match 'Certificate Policies') {
                    for ($j = $i + 1; $j -lt $lines.Count; $j++) { if ($lines[$j] -match '^\s+Policy:\s*(?<o>\S+)') { [void]$policyOids.Add($Matches['o']) } elseif ($lines[$j] -match '^\s{12}\S') { break } }
                }
            }
        }
    }
    # the development-SAN marker (5.2.2): taken out of the names
    $devSan = $false
    foreach ($d in @($san.Dns)) { if ($d -ieq $script:PkiCsrDevSanMarker) { $devSan = $true } }
    if ($devSan) { for ($k = $san.Dns.Count - 1; $k -ge 0; $k--) { if ($san.Dns[$k] -ieq $script:PkiCsrDevSanMarker) { $san.Dns.RemoveAt($k) } } }
    return [pscustomobject]@{
        DevSanMarker = $devSan; PolicyOids = @($policyOids)
        Path = $full; VerifyOk = ($v.ExitCode -eq 0); Subject = $pairs; SubjectText = (($pairs | ForEach-Object { '{0}={1}' -f $_[0], $_[1] }) -join ', ')
        KeyAlg = $alg; KeyBits = $bits; Curve = $curve; MlDsa = $ml; KeyText = $algText; SigAlg = $sig
        San = $san; RequestedExtensions = @($reqExt); RequestsCa = $ca; Text = $text
    }
}

function Get-PkiKeyDescription {
    param([Parameter(Mandatory)]$Csr)
    switch ($Csr.KeyAlg) { 'RSA' { "RSA-$($Csr.KeyBits)" } 'ECDSA' { "ECDSA-$($Csr.Curve -replace '-', '')" } 'MLDSA' { "ML-DSA-$($Csr.MlDsa)" } default { $Csr.KeyText } }
}

function Test-PkiCsrKey {
    # key and digest rules. -Track Classic|Quantum; -MinStrong = code signing / CA strength.
    param([Parameter(Mandatory)]$Csr, [Parameter(Mandatory)][ValidateSet('Classic', 'Quantum')][string]$Track, [switch]$CodeSigning, [switch]$CaKey, [Parameter(Mandatory)]$Findings)
    $F = $Findings
    $desc = Get-PkiKeyDescription -Csr $Csr
    if (-not $Csr.VerifyOk) { [void]$F.Add((New-PkiFinding ERROR 'KEY-SIGNATURE' 'signature' 'The signature of the request is not valid (the file was changed, or it is not signed with its own key).' 'Make the request again: openssl req -new -key <his.key> -out <his.csr>')) }
    else { [void]$F.Add((New-PkiFinding OK 'KEY-SIGNATURE' 'signature' 'The signature of the request is valid (proof that he holds the private key).')) }
    $strong = ($CodeSigning -or $CaKey)
    $why = if ($CaKey) { 'a CA key' } elseif ($CodeSigning) { 'a code signing key' } else { 'a leaf key' }
    $ok = $false
    switch ($Csr.KeyAlg) {
        'RSA' {
            if ($Track -eq 'Quantum') { [void]$F.Add((New-PkiFinding ERROR 'KEY-QUANTUM-REQUIRED' 'public key' "The key is $desc, but Quadrant 3 / 4 (Quantum) issues ML-DSA keys only." 'Make an ML-DSA key (openssl genpkey -algorithm ML-DSA-65) or ask for the Classic track (no -Quantum).')) }
            elseif ($Csr.KeyBits -lt 2048) { [void]$F.Add((New-PkiFinding ERROR 'KEY-RSA-SMALL' 'public key' "RSA $($Csr.KeyBits) bit is too small: the minimum is 2048." 'openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 (4096 for code signing and CA keys)')) }
            elseif ($Csr.KeyBits -notin 2048, 3072, 4096, 8192) { [void]$F.Add((New-PkiFinding ERROR 'KEY-RSA-ODD' 'public key' "RSA $($Csr.KeyBits) bit is not a size of this PKI (2048, 3072, 4096 or 8192)." 'Use rsa_keygen_bits:2048, 3072 or 4096.')) }
            elseif ($CaKey -and $Csr.KeyBits -lt 4096) { [void]$F.Add((New-PkiFinding ERROR 'KEY-CA-RSA' 'public key' "RSA $($Csr.KeyBits) bit is too small for ${why}: 4096 or more (equal strength: ECDSA P-384)." 'openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096')) }
            elseif ($CodeSigning -and $Csr.KeyBits -lt 4096) { [void]$F.Add((New-PkiFinding ERROR 'KEY-CS-RSA' 'public key' "RSA $($Csr.KeyBits) bit is too small for ${why}: this PKI needs 4096 or more (the generator raises it too)." 'openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096')) }
            else { $ok = $true }
        }
        'ECDSA' {
            if ($Track -eq 'Quantum') { [void]$F.Add((New-PkiFinding ERROR 'KEY-QUANTUM-REQUIRED' 'public key' "The key is $desc, but Quadrant 3 / 4 (Quantum) issues ML-DSA keys only." 'Make an ML-DSA key (openssl genpkey -algorithm ML-DSA-65) or ask for the Classic track (no -Quantum).')) }
            elseif ($Csr.Curve -notin 'P-256', 'P-384', 'P-521') { [void]$F.Add((New-PkiFinding ERROR 'KEY-CURVE' 'public key' "The curve '$($Csr.Curve)' is not accepted: P-256, P-384 or P-521 only." 'openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve')) }
            elseif ($strong -and $Csr.Curve -eq 'P-256') { [void]$F.Add((New-PkiFinding ERROR $(if ($CaKey) { 'KEY-CA-CURVE' } else { 'KEY-CS-CURVE' }) 'public key' "ECDSA P-256 is too weak for ${why}: P-384 or P-521." 'Use ec_paramgen_curve:P-384')) }
            else { $ok = $true }
        }
        'MLDSA' {
            if ($Track -eq 'Classic') { [void]$F.Add((New-PkiFinding ERROR 'KEY-CLASSIC-REQUIRED' 'public key' "The key is $desc (quantum), but this is a Classic request (Quadrant 1 / 2: RSA or ECDSA)." 'Ask for the Quantum track (-Quantum) or send an RSA / ECDSA request.')) }
            elseif ($Csr.MlDsa -notin 44, 65, 87) { [void]$F.Add((New-PkiFinding ERROR 'KEY-MLDSA' 'public key' "ML-DSA-$($Csr.MlDsa) is not a parameter set of this PKI (44, 65 or 87)." '')) }
            elseif ($strong -and $Csr.MlDsa -lt 65) { [void]$F.Add((New-PkiFinding ERROR 'KEY-CS-MLDSA' 'public key' "ML-DSA-44 is too weak for ${why}: ML-DSA-65 or 87." 'openssl genpkey -algorithm ML-DSA-65')) }
            else { $ok = $true }
        }
        default { [void]$F.Add((New-PkiFinding ERROR 'KEY-ALG' 'public key' "The key type '$($Csr.KeyText)' is not accepted (RSA, ECDSA P-256 / P-384 / P-521, ML-DSA)." 'Make a new key with openssl genpkey (RSA 2048+, EC P-256+, or ML-DSA).')) }
    }
    if ($ok) { [void]$F.Add((New-PkiFinding OK 'KEY-OK' 'public key' "Key $desc is accepted for $why on the $Track track.")) }
    if ($Csr.KeyAlg -ne 'MLDSA' -and $Csr.SigAlg -match '(?i)md[245]|sha-?1(?!\d)|sha-?224|ripemd|whirlpool') {
        [void]$F.Add((New-PkiFinding ERROR 'KEY-DIGEST' 'request signature' "The request is signed with $($Csr.SigAlg): SHA-256 or stronger is required." 'openssl req -new -sha256 (or -sha384) ...'))
    }
    elseif ($Csr.SigAlg) { [void]$F.Add((New-PkiFinding OK 'KEY-DIGEST' 'request signature' "Request signature algorithm $($Csr.SigAlg).")) }
}

function Get-PkiCsrAutoLevel {
    <#
    .SYNOPSIS
        The level a request asks for by what it carries (5.2.2): EV when it has the EV information (businessCategory, serialNumber and jurisdictionC),
        OV when it has a company (C and O), else DV. Returns @{ Level; Reason }.
    #>
    param([Parameter(Mandatory)]$Csr)
    $has = { param($k) @($Csr.Subject | Where-Object { $_[0] -ceq $k -and -not [string]::IsNullOrWhiteSpace($_[1]) }).Count -gt 0 }
    if ((& $has 'businessCategory') -and (& $has 'serialNumber') -and (& $has 'jurisdictionC')) { return @{ Level = 'EV'; Reason = 'the request carries the EV information (businessCategory, serialNumber, jurisdictionC)' } }
    if ((& $has 'O') -and (& $has 'C')) { return @{ Level = 'OV'; Reason = 'the request carries a company (C and O) but no complete EV information' } }
    return @{ Level = 'DV'; Reason = 'the request carries a common name only' }
}

function Test-PkiCsrSubject {
    <#
    .SYNOPSIS
        Subject rules by level. Profile Leaf (DV CN only, OV, EV) or Ca (a CA of another department: DV CN; OV C, O, OU, CN; EV the EV fields too).
    #>
    param([Parameter(Mandatory)]$Csr, [Parameter(Mandatory)][ValidateSet('DV', 'OV', 'EV')][string]$Level, [ValidateSet('Leaf', 'Ca')][string]$Profile = 'Leaf',
          [switch]$CodeSigning, [Parameter(Mandatory)]$Findings)
    $F = $Findings
    $pairs = @($Csr.Subject)
    if ($pairs.Count -eq 0) { [void]$F.Add((New-PkiFinding ERROR 'SUBJ-EMPTY' 'subject' 'The request has no subject.' 'Give the subject with -subj "/C=EE/O=.../CN=..." when you make the request.')); return }
    $get = { param($k) @($pairs | Where-Object { $_[0] -ceq $k } | ForEach-Object { $_[1] }) }
    $allowed = @($script:PkiCsrSubjectAttrs[$Level])
    if ($CodeSigning -and $Level -ne 'DV') { $allowed = @('C', 'ST', 'L', 'O', 'OU', 'CN') + $(if ($Level -eq 'EV') { @('businessCategory', 'serialNumber', 'jurisdictionC', 'jurisdictionST', 'jurisdictionL', 'organizationIdentifier', 'street', 'postalCode') } else { @() }) }
    # attributes: duplicates and unknown ones
    foreach ($g in ($pairs | Group-Object { $_[0] })) {
        if ($g.Count -gt 1 -and $g.Name -ne 'OU') { [void]$F.Add((New-PkiFinding ERROR "SUBJ-DUP-$($g.Name)" $g.Name "The attribute $($g.Name) occurs $($g.Count) times in the subject: once only." "Keep one $($g.Name).")) }
    }
    if ($Level -eq 'DV') {
        $extra = @($pairs | Where-Object { $_[0] -cne 'CN' } | ForEach-Object { $_[0] } | Select-Object -Unique)
        if ($extra.Count -gt 0) { [void]$F.Add((New-PkiFinding WARN 'SUBJ-DV-DROP' 'subject' "A DV certificate carries the CN only: $($extra -join ', ') will NOT be in the certificate." 'Ask for -OV or -EV if the organization must be in the certificate.')) }
    }
    else {
        foreach ($a in @($pairs | ForEach-Object { $_[0] } | Select-Object -Unique)) {
            if ($allowed -cnotcontains $a) {
                $hint = if ($a -match '^\d') { 'an OID the PKI does not know' } elseif ($a -in 'jurisdictionC', 'jurisdictionST', 'jurisdictionL', 'businessCategory', 'serialNumber', 'organizationIdentifier') { "it belongs to EV certificates only (this is $Level)" } else { "not in the subject of an $Level$(if ($CodeSigning) { ' code signing' }) certificate" }
                [void]$F.Add((New-PkiFinding ERROR "SUBJ-ATTR-$a" $a "The subject attribute '$a' is not allowed: $hint. Allowed for ${Level}: $($allowed -join ', ')." "Remove $a from the request subject."))
            }
        }
    }
    # CN
    $cn = @(& $get 'CN')
    if ($cn.Count -eq 0) { [void]$F.Add((New-PkiFinding ERROR 'SUBJ-REQ-CN' 'CN' 'The subject has no CN (common name).' 'Add /CN=<name> to the subject.')) }
    elseif ($cn[0].Length -gt 64) { [void]$F.Add((New-PkiFinding ERROR 'SUBJ-LEN-CN' 'CN' "The CN is $($cn[0].Length) characters; the maximum is 64." 'Shorten the CN (put long names in O).')) }
    elseif ($cn[0] -match '[/\\]') { [void]$F.Add((New-PkiFinding ERROR 'SUBJ-CN-CHAR' 'CN' "The CN contains '/' or '\': not accepted." 'Use plain characters.')) }
    elseif ($cn[0].Trim() -ne $cn[0]) { [void]$F.Add((New-PkiFinding WARN 'SUBJ-CN-SPACE' 'CN' 'The CN has a space at the start or the end.' 'Remove it.')) }
    else { [void]$F.Add((New-PkiFinding OK 'SUBJ-CN' 'CN' "CN = $($cn[0])")) }
    if ($Level -eq 'DV') { return }
    # required and recommended
    $req = [System.Collections.Generic.List[string]]::new(); $rec = [System.Collections.Generic.List[string]]::new()
    if ($Profile -eq 'Ca') {
        foreach ($a in 'C', 'O', 'OU') { [void]$req.Add($a) }
        if ($Level -eq 'EV') { foreach ($a in 'ST', 'L', 'serialNumber', 'businessCategory', 'jurisdictionC') { [void]$req.Add($a) }; foreach ($a in 'jurisdictionST', 'postalCode') { [void]$rec.Add($a) } }
        else { foreach ($a in 'ST', 'L') { [void]$rec.Add($a) } }
    }
    else {
        foreach ($a in 'C', 'O') { [void]$req.Add($a) }
        if ($Level -eq 'EV' -and -not $CodeSigning) { foreach ($a in 'ST', 'L', 'serialNumber', 'businessCategory', 'jurisdictionC') { [void]$req.Add($a) }; foreach ($a in 'jurisdictionST', 'postalCode') { [void]$rec.Add($a) } }
        elseif ($Level -eq 'EV') { foreach ($a in 'ST', 'L', 'serialNumber', 'businessCategory', 'jurisdictionC') { [void]$req.Add($a) } }
        else { foreach ($a in 'ST', 'L') { [void]$rec.Add($a) } }
    }
    $example = @{ C = 'C=EE'; O = 'O=Your Company OU'; OU = 'OU=IT Department'; ST = 'ST=Harju'; L = 'L=Tallinn'; serialNumber = 'serialNumber=17344131'
                  businessCategory = 'businessCategory=Private Organization'; jurisdictionC = 'jurisdictionC=EE'; jurisdictionST = 'jurisdictionST=Harju'; postalCode = 'postalCode=15199' }
    foreach ($a in $req) {
        $v = @(& $get $a)
        if ($v.Count -eq 0 -or [string]::IsNullOrWhiteSpace($v[0])) { [void]$F.Add((New-PkiFinding ERROR "SUBJ-REQ-$a" $a "The subject has no $a, required for $(if ($Profile -eq 'Ca') { 'a CA of level ' })$Level$(if ($CodeSigning) { ' code signing' })." "Add /$($example[$a]) to the subject (the value is yours).")) }
    }
    foreach ($a in $rec) {
        $v = @(& $get $a)
        if ($v.Count -eq 0 -or [string]::IsNullOrWhiteSpace($v[0])) { [void]$F.Add((New-PkiFinding WARN "SUBJ-REC-$a" $a "The subject has no $a (recommended for $Level)." "Add /$($example[$a]) (the value is yours).")) }
    }
    # formats
    foreach ($a in 'C', 'jurisdictionC') {
        $v = @(& $get $a)
        if ($v.Count -gt 0 -and $v[0] -cnotmatch '^[A-Z]{2}$') { [void]$F.Add((New-PkiFinding ERROR "SUBJ-FMT-$a" $a "$a '$($v[0])' is not a 2-letter upper-case ISO 3166 country code." "Use e.g. $a=EE.")) }
    }
    $bc = @(& $get 'businessCategory')
    if ($bc.Count -gt 0 -and $script:PkiCsrBusinessCategories -cnotcontains $bc[0]) { [void]$F.Add((New-PkiFinding ERROR 'SUBJ-FMT-businessCategory' 'businessCategory' "businessCategory '$($bc[0])' is not one of: $($script:PkiCsrBusinessCategories -join ', ')." 'Use one of those four values exactly.')) }
    foreach ($a in 'O', 'OU', 'ST', 'L') {
        foreach ($v in @(& $get $a)) { if ($v.Length -gt $(if ($a -in 'O', 'OU') { 64 } else { 128 })) { [void]$F.Add((New-PkiFinding ERROR "SUBJ-LEN-$a" $a "$a is $($v.Length) characters; the maximum is $(if ($a -in 'O', 'OU') { 64 } else { 128 }).")) } }
    }
    if ($CodeSigning) {
        $o = @(& $get 'O'); if ($o.Count -gt 0 -and $cn.Count -gt 0 -and $o[0] -cne $cn[0]) { [void]$F.Add((New-PkiFinding WARN 'SUBJ-CS-CN' 'CN' 'For a code signing certificate of this PKI the CN is the company name, equal to O.' 'Use CN = O.')) }
    }
    foreach ($a in (@($req) + @($rec))) { if ($F.Where({ $_.Field -ceq $a }).Count -eq 0 -and @(& $get $a).Count -gt 0) { [void]$F.Add((New-PkiFinding OK "SUBJ-$a" $a "$a = $((@(& $get $a))[0])")) } }
}

function Test-PkiCsrNames {
    <#
    .SYNOPSIS
        The names (SAN) of a LEAF request by purpose and level. Returns the names that go into the certificate: @{ Dns; Ip; Email }.
    #>
    param([Parameter(Mandatory)]$Csr, [Parameter(Mandatory)][ValidateSet('DV', 'OV', 'EV')][string]$Level, [Parameter(Mandatory)][string[]]$Eku, [Parameter(Mandatory)]$Findings)
    $F = $Findings
    $web = ($Eku -contains 'ServerAuth') -or (($Eku -contains 'ClientAuth') -and ($Eku -notcontains 'EmailProtection'))
    $mail = ($Eku -contains 'EmailProtection')
    $dns = [System.Collections.Generic.List[string]]::new(); $ip = [System.Collections.Generic.List[string]]::new(); $em = [System.Collections.Generic.List[string]]::new()
    $s = $Csr.San
    $cn = @($Csr.Subject | Where-Object { $_[0] -ceq 'CN' } | ForEach-Object { $_[1] }) | Select-Object -First 1
    if (-not $web -and -not $mail) {
        $n = $s.Dns.Count + $s.Ip.Count + $s.Email.Count + $s.Other.Count
        if ($n -gt 0) { [void]$F.Add((New-PkiFinding WARN 'SAN-DROPPED' 'subjectAltName' "A $($Eku -join '+') certificate carries no names: the $n name(s) of the request are NOT put in the certificate." 'Nothing to do; or ask for a TLS / S/MIME purpose if names are needed.')) }
        return @{ Dns = @(); Ip = @(); Email = @() }
    }
    if ($s.Other.Count -gt 0) { [void]$F.Add((New-PkiFinding WARN 'SAN-OTHER' 'subjectAltName' "Name types of the request that this PKI does not issue are dropped: $($s.Other -join '; ') (DNS, IP and e-mail only)." '')) }
    foreach ($d in $s.Dns) { if ($web) { [void]$dns.Add($d) } }
    foreach ($a in $s.Ip) { if ($web) { [void]$ip.Add($a) } }
    foreach ($m in $s.Email) { if ($mail) { [void]$em.Add($m) } }
    if ($web -and $s.Email.Count -gt 0) { [void]$F.Add((New-PkiFinding WARN 'SAN-DROPPED' 'subjectAltName' "E-mail name(s) $($s.Email -join ', ') are not put in a TLS certificate." 'Ask for -Purpose EmailProtection for an S/MIME certificate.')) }
    if ($mail -and ($s.Dns.Count + $s.Ip.Count) -gt 0) { [void]$F.Add((New-PkiFinding WARN 'SAN-DROPPED' 'subjectAltName' 'DNS and IP names are not put in an S/MIME certificate (e-mail names only).' '')) }
    if ($web -and $dns.Count -eq 0 -and $ip.Count -eq 0 -and -not $Csr.DevSanMarker) {      # with the development-SAN marker the development list supplies the names
        if ($cn -and (Test-PkiDnsName -Name $cn) -and $cn -notmatch '\s') {
            [void]$dns.Add($cn)
            [void]$F.Add((New-PkiFinding WARN 'SAN-DERIVED' 'subjectAltName' "The request has no subjectAltName; the CN '$cn' is used as the DNS name (browsers and TLS libraries only look at the SAN)." 'Put the names in the request: -addext "subjectAltName=DNS:www.example.com,DNS:example.com"'))
        }
        else { [void]$F.Add((New-PkiFinding ERROR 'SAN-NONE' 'subjectAltName' 'A TLS certificate needs at least one DNS name or IP address, and the request has none (the CN is not a host name either).' 'Make the request with -addext "subjectAltName=DNS:www.example.com".')) }
    }
    if ($mail -and $em.Count -eq 0 -and -not $Csr.DevSanMarker) {
        if ($cn -and $cn -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
            [void]$em.Add($cn); [void]$F.Add((New-PkiFinding WARN 'SAN-DERIVED' 'subjectAltName' "No e-mail name in the request; the CN '$cn' is used." 'Put it in the request: -addext "subjectAltName=email:name@example.com"'))
        }
        else { [void]$F.Add((New-PkiFinding ERROR 'SAN-NONE' 'subjectAltName' 'An S/MIME certificate needs at least one e-mail address (SAN email:), and the request has none.' 'Make the request with -addext "subjectAltName=email:name@example.com".')) }
    }
    foreach ($d in $dns) {
        if (-not (Test-PkiDnsName -Name $d)) { [void]$F.Add((New-PkiFinding ERROR 'SAN-DNS-INVALID' 'DNS' "'$d' is not a valid DNS name." 'Letters, digits, hyphens and dots; a wildcard only as *.name.')); continue }
        if ($Level -eq 'EV') {
            if ($d.StartsWith('*.') -or $d.Contains('*')) { [void]$F.Add((New-PkiFinding ERROR 'SAN-EV-WILDCARD' 'DNS' "'$d': an EV certificate may not contain a wildcard name." "Name every host: remove '$d' or ask for -OV.")) }
            $labels = $d.TrimEnd('.').Split('.')
            if ($labels.Count -lt 2 -or $script:PkiCsrInternalTlds -contains $labels[-1].ToLowerInvariant()) { [void]$F.Add((New-PkiFinding ERROR 'SAN-EV-INTERNAL' 'DNS' "'$d' is an internal name (no public domain): not allowed in an EV certificate." 'Use a public domain name, or ask for -OV / -DV.')) }
        }
        elseif ($d.StartsWith('*.')) { [void]$F.Add((New-PkiFinding WARN 'SAN-WILDCARD' 'DNS' "Wildcard name '$d': allowed in this private PKI (a public CA would refuse it for EV)." '')) }
    }
    foreach ($a in $ip) {
        $t = $null
        if (-not [System.Net.IPAddress]::TryParse($a, [ref]$t)) { [void]$F.Add((New-PkiFinding ERROR 'SAN-IP-INVALID' 'IP' "'$a' is not a valid IP address.")) }
        elseif ($Level -eq 'EV') { [void]$F.Add((New-PkiFinding ERROR 'SAN-EV-IP' 'IP' "IP address '$a': an EV certificate may not contain an IP address." 'Use a DNS name, or ask for -OV / -DV.')) }
    }
    foreach ($m in $em) {
        if ($m -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { [void]$F.Add((New-PkiFinding ERROR 'SAN-EMAIL-INVALID' 'email' "'$m' is not a valid e-mail address.")) }
        elseif ($Level -eq 'EV' -and -not $mail) { [void]$F.Add((New-PkiFinding ERROR 'SAN-EV-EMAIL' 'email' 'An EV TLS certificate may not contain an e-mail address.')) }
    }
    if ($Level -eq 'DV' -and $web -and $cn -and $dns.Count + $ip.Count -gt 0 -and -not ($dns | Where-Object { $_ -ieq $cn }) -and -not ($ip | Where-Object { $_ -eq $cn })) {
        [void]$F.Add((New-PkiFinding WARN 'SUBJ-CN-NOT-SAN' 'CN' "The CN '$cn' is not one of the names in the SAN ($(@($dns) + @($ip) -join ', ')); a DV certificate is identified by its names." 'Make the CN the first DNS name.'))
    }
    $okn = @($dns) + @($ip) + @($em)
    if ($okn.Count -gt 0 -and @($F.Where({ $_.Severity -eq 'ERROR' -and $_.Code -like 'SAN-*' })).Count -eq 0) { [void]$F.Add((New-PkiFinding OK 'SAN-OK' 'subjectAltName' "Names accepted: $($okn -join ', ')")) }
    return @{ Dns = @($dns); Ip = @($ip); Email = @($em) }
}

function Test-PkiCsrExtensions {
    param([Parameter(Mandatory)]$Csr, [Parameter(Mandatory)]$Findings)
    $F = $Findings
    if ($Csr.RequestsCa) { [void]$F.Add((New-PkiFinding ERROR 'EXT-CA' 'basicConstraints' 'The request asks for CA:TRUE. A leaf request may not be a CA.' 'A CA of another department goes through SignExternalCa.ps1 (the original PKI owner signs it with a Quadrant Root).')) }
    $ign = @($Csr.RequestedExtensions | Where-Object { $_ -match 'Key Usage|Extended Key|Authority|Subject Key|CRL|Authority Information|Name Constraints' })
    if (@($Csr.PolicyOids).Count -gt 0) {
        $okp = @($Csr.PolicyOids | Where-Object { $_ -match '^1\.3\.6\.1\.4\.1\.\d+(\.\d+)*$' }); $badp = @($Csr.PolicyOids | Where-Object { $_ -notmatch '^1\.3\.6\.1\.4\.1\.\d+(\.\d+)*$' })
        if ($okp.Count -gt 0) { [void]$F.Add((New-PkiFinding INFO 'EXT-PEN-POLICY' 'certificatePolicies' "Company policy OID(s) of the request are added to the certificate (IANA private enterprise arc 1.3.6.1.4.1): $($okp -join ', ')")) }
        if ($badp.Count -gt 0) { [void]$F.Add((New-PkiFinding WARN 'EXT-POLICY-DROPPED' 'certificatePolicies' "Policy OID(s) outside 1.3.6.1.4.1.<PEN> are ignored: $($badp -join ', ')." 'Only an IANA private enterprise number arc is accepted from a request.')) }
    }
    if ($ign.Count -gt 0) { [void]$F.Add((New-PkiFinding INFO 'EXT-IGNORED' 'extensions' "The request asks for: $($ign -join ', '). This PKI decides key usage, extended key usage, policies and revocation URLs itself; they are ignored.")) }
}

function Get-PkiCsrEku {
    param([Parameter(Mandatory)][string]$Purpose)
    return @(Resolve-PkiPurposeEku -Purpose @($Purpose))
}

function Test-PkiCsrSpec {
    <#
    .SYNOPSIS
        Checks a request against the specification of this PKI. Returns @{ Findings; Names; Errors; Warnings; Csr }.
    #>
    param(
        [Parameter(Mandatory)]$Csr, [ValidateSet('Leaf', 'Ca')][string]$Profile = 'Leaf', [ValidateSet('DV', 'OV', 'EV')][string]$Level = 'DV',
        [ValidateSet('Classic', 'Quantum')][string]$Track = 'Classic', [string]$Purpose = 'ServerAuth', [int]$Days = 0
    )
    $F = [System.Collections.Generic.List[object]]::new()
    if ($Profile -eq 'Ca' -and $Csr.DevSanMarker) { [void]$F.Add((New-PkiFinding ERROR 'CA-DEV-SAN' 'subjectAltName' 'A request for a CA certificate asks for the development names (marker in its SAN). A CA certificate never has development names.' 'Make the CA request again with New-PkiCsr.ps1 -CertificateType IntermediateCA (no names).')) }
    if ($Profile -eq 'Leaf') {
        $eku = Get-PkiCsrEku -Purpose $Purpose
        $cs = ($eku -contains 'CodeSigning')
        Test-PkiCsrKey -Csr $Csr -Track $Track -CodeSigning:$cs -Findings $F
        Test-PkiCsrSubject -Csr $Csr -Level $Level -Profile Leaf -CodeSigning:$cs -Findings $F
        $names = Test-PkiCsrNames -Csr $Csr -Level $Level -Eku $eku -Findings $F
        Test-PkiCsrExtensions -Csr $Csr -Findings $F
        if ($Level -eq 'EV' -and $Days -gt 397) { [void]$F.Add((New-PkiFinding ERROR 'VAL-EV' 'validity' "An EV certificate may not be valid longer than 397 days (asked $Days)." 'Use -Days 397 or less.')) }
    }
    else {
        $names = @{ Dns = @(); Ip = @(); Email = @() }
        Test-PkiCsrKey -Csr $Csr -Track $Track -CaKey -Findings $F
        Test-PkiCsrSubject -Csr $Csr -Level $Level -Profile Ca -Findings $F
        if ($Level -eq 'EV' -and $Days -gt 397) { [void]$F.Add((New-PkiFinding ERROR 'VAL-EV' 'validity' "An EV certificate may not be valid longer than 397 days (asked $Days)." 'Use -Days 397 or less.')) }
    }
    return @{ Findings = $F; Names = $names; Errors = @($F | Where-Object { $_.Severity -eq 'ERROR' }).Count; Warnings = @($F | Where-Object { $_.Severity -eq 'WARN' }).Count; Csr = $Csr }
}

function Get-PkiSignCsrDays {
    param([Parameter(Mandatory)][string]$Level, [Parameter(Mandatory)][string[]]$Eku, [int]$Days = 0)
    $c = $script:Pki
    $d = $Days
    if ($d -le 0 -and ($Eku -contains 'TimeStamping')) { $d = [int](Get-PkiTimestampSettings).Days }
    if ($d -le 0 -and ($Eku -contains 'OcspSigning')) { $d = [int]$c.OcspDays }
    if ($d -le 0) { $d = Get-PkiLeafDays -Level $Level }
    if ($Level -eq 'EV' -and $d -gt 397 -and $Days -le 0) { $d = 397 }
    return $d
}

function Get-PkiCsrKind {
    <#
    .SYNOPSIS
        What kind of request this is (5.2.6): IntermediateCA when it asks for CA:TRUE (basicConstraints); Leaf when it carries names (subjectAltName, or the
        development-names marker); Unclear when it has neither (a name-only request, or a hand-made CA request without CA:TRUE).
    #>
    param([Parameter(Mandatory)]$Csr)
    if ($Csr.RequestsCa) { return @{ Kind = 'IntermediateCA'; Reason = 'the request asks for CA:TRUE (basicConstraints)' } }
    $n = @($Csr.San.Dns).Count + @($Csr.San.Ip).Count + @($Csr.San.Email).Count
    if ($n -gt 0 -or $Csr.DevSanMarker) { return @{ Kind = 'Leaf'; Reason = 'the request carries names (subjectAltName) and no CA:TRUE' } }
    return @{ Kind = 'Unclear'; Reason = 'the request has neither CA:TRUE nor names' }
}

function Test-PkiCsrKind {
    <#
    .SYNOPSIS
        Checks that the request is of the kind THIS script signs. -Expected Leaf (SignCsr) or IntermediateCA (SignExternalCa); -Declared Auto|Leaf|IntermediateCA is the
        parameter -CsrType. Returns @{ Ok; Kind; Level (INFO|ERROR); Text; Fix }.
    #>
    param([Parameter(Mandatory)]$Csr, [ValidateSet('Leaf', 'IntermediateCA')][string]$Expected, [string]$Declared = 'Auto')
    $k = Get-PkiCsrKind -Csr $Csr
    $me = if ($Expected -eq 'Leaf') { 'SignCsr.ps1 (SignCsr.sh)' } else { 'SignExternalCa.ps1' }
    $other = if ($Expected -eq 'Leaf') { 'SignExternalCa.ps1 -Csr <file>   (a CA of your department; original PKI only)' } else { 'SignCsr.ps1 -Csr <file>   (SignCsr.sh --csr <file> in the DevKit)' }
    if ($Declared -ne 'Auto' -and $Declared -ne $Expected) {
        return @{ Ok = $false; Kind = $k.Kind; Level = 'ERROR'; Text = "-CsrType $Declared was given, but $me signs only $Expected requests."; Fix = "Use: $other" }
    }
    if ($k.Kind -ne 'Unclear' -and $k.Kind -ne $Expected) {
        return @{ Ok = $false; Kind = $k.Kind; Level = 'ERROR'; Text = "This request is of kind $($k.Kind) ($($k.Reason)); $me signs $Expected requests only."; Fix = "Use: $other" }
    }
    if ($k.Kind -eq 'Unclear') { return @{ Ok = $true; Kind = $k.Kind; Level = 'INFO'; Text = "Request kind: not clear ($($k.Reason)); treated as $Expected$(if ($Declared -eq $Expected) { ' as you said with -CsrType' } else { ' (-CsrType decides it yourself)' })."; Fix = '' } }
    return @{ Ok = $true; Kind = $k.Kind; Level = 'INFO'; Text = "Request kind: $($k.Kind) ($($k.Reason))."; Fix = '' }
}

function Write-PkiCsrKindLine {
    param([Parameter(Mandatory)]$Kind, [switch]$NoColor)
    $col = if ($Kind.Level -eq 'ERROR') { 'Red' } else { 'Cyan' }
    Write-Host ("  [{0}] request kind             {1}" -f $(if ($Kind.Level -eq 'ERROR') { 'ERROR' } else { 'INFO' }), $Kind.Text) -ForegroundColor $col
    if ($Kind.Fix) { Write-Host ("                                   fix: {0}" -f $Kind.Fix) -ForegroundColor $col }
}

function Invoke-PkiSignCsr {
    <#
    .SYNOPSIS
        Checks the request (Test-PkiCsrSpec), and when it follows the spec signs it with q<N>-<level> and writes the result into a NEW folder:
        csr-signed\<name>_<yyyyMMdd-HHmmss>\  <name>.csr <name>.crt <name>.cer <name>.p7b -fullchain.crt -chain.crt root.crt our-ca-bundle.crt sign-info.json README.txt
        Returns @{ Signed = $true|$false; Findings; Dir; Certificate }.
    #>
    param(
        [Parameter(Mandatory)][string]$Csr, [ValidateSet('DV', 'OV', 'EV')][string]$Level = 'DV', [ValidateSet(1, 2, 3, 4)][int]$Quadrant = 1,
        [string]$Purpose = 'ServerAuth', [int]$Days = 0, [string]$Name, [string]$OutRoot, [switch]$NoCrl, [switch]$NoOcsp,
        [switch]$Strict, [switch]$CheckOnly, [switch]$NoColor, [string[]]$Policy = @(), [switch]$AddDevelopmentSan, [string]$LevelReason = '', [string]$CsrType = 'Auto'
    )
    $c = $script:Pki
    if ([bool]$c.ClassicOnly -and $Quadrant -ge 3) { throw 'Quadrant 3 / 4 is the Quantum track (ML-DSA): this computer is Windows Server 2022, which can issue the CLASSIC track only. Leave out -Quantum.' }
    $track = if ($Quadrant -in 3, 4) { 'Quantum' } else { 'Classic' }
    $info = Read-PkiCsr -Path $Csr
    Write-Host ''
    Write-Host "REQUEST  $($info.Path)"
    Write-Host "  subject : $($info.SubjectText)"
    Write-Host "  key     : $(Get-PkiKeyDescription -Csr $info)    signature: $($info.SigAlg)"
    Write-Host "  asked   : $Level$(if ($LevelReason) { " (chosen from the request: $LevelReason)" }), Quadrant $Quadrant ($track$(if ($Quadrant -in 2, 4) { ' FIPS' } else { ' non-FIPS' })), purpose $Purpose"
    Write-Host ''
    $kind = Test-PkiCsrKind -Csr $info -Expected Leaf -Declared $CsrType
    Write-PkiCsrKindLine -Kind $kind -NoColor:$NoColor
    if (-not $kind.Ok) {
        Write-Host ''; Write-Host '  Result: the request is not a leaf request: nothing was signed.'
        return [pscustomobject]@{ Signed = $false; Findings = @(); Errors = 1; Warnings = 0; Dir = $null; Certificate = $null }
    }
    Write-Host ''
    $daysAsked = $Days
    $r = Test-PkiCsrSpec -Csr $info -Profile Leaf -Level $Level -Track $track -Purpose $Purpose -Days $daysAsked
    Write-PkiCsrFindings -Findings $r.Findings -NoColor:$NoColor
    Write-Host ''
    $wantDev = ($AddDevelopmentSan -or $info.DevSanMarker)
    if ($wantDev -and $r.Errors -eq 0) {
        $eku0 = Get-PkiCsrEku -Purpose $Purpose
        if (($eku0 -contains 'ServerAuth') -or ($eku0 -contains 'ClientAuth') -or ($eku0 -contains 'EmailProtection')) {
            $mail0 = ($eku0 -contains 'EmailProtection') -and ($eku0 -notcontains 'ServerAuth')
            $merged = Add-PkiDevelopmentSan -San ([ordered]@{ Dns = @($r.Names.Dns); Ip = @($r.Names.Ip); Email = @($r.Names.Email); Given = $true }) -EmailOnly:$mail0
            $r.Names = @{ Dns = @($merged.Dns); Ip = @($merged.Ip); Email = @($merged.Email) }
            Write-Host "  [INFO] subjectAltName          development names added ($(if ($info.DevSanMarker) { 'the request carries the marker' } else { '-AddDevelopmentSAN' })): $($merged.Added.Dns) DNS, $($merged.Added.Ip) IP, $($merged.Added.Email) e-mail."
            if ($Level -eq 'EV') { Write-Host '  [WARN] subjectAltName          development names (IP addresses, wildcards, internal names) are not EV-conformant: for development only.' -ForegroundColor Yellow }
        }
        else { Write-Host "  [WARN] subjectAltName          a $Purpose certificate carries no names: the development names are not added." -ForegroundColor Yellow }
    }
    $blocked = ($r.Errors -gt 0) -or ($Strict -and $r.Warnings -gt 0)
    if ($Strict -and $r.Errors -eq 0 -and $r.Warnings -gt 0) { Write-PkiLog '-Strict: the warnings count as errors.' 'ERROR' }
    if ($blocked) { return [pscustomobject]@{ Signed = $false; Findings = $r.Findings; Errors = $r.Errors; Warnings = $r.Warnings; Dir = $null; Certificate = $null } }
    if ($CheckOnly) { Write-PkiLog 'Check only (-Check): nothing was signed.' 'INFO'; return [pscustomobject]@{ Signed = $false; Findings = $r.Findings; Errors = 0; Warnings = $r.Warnings; Dir = $null; Certificate = $null } }

    # ---- the issuer ----
    $ca = Get-PkiCa -Id ("q$Quadrant-" + $Level.ToLowerInvariant())
    if ($null -eq $ca.Actual) { throw "The issuing CA q$Quadrant-$($Level.ToLowerInvariant()) is not part of this PKI (built: $((@($c.Catalog | Where-Object { $_.Actual -and $_.Kind -eq 'intermediate' } | ForEach-Object { $_.Id }) -join ', ')))." }
    $cp = Get-PkiCaPaths -Ca $ca
    if (-not (Test-Path -LiteralPath $cp.Key)) { throw "The private key of $($ca.Id) is not here ($($cp.Key)): this folder can not sign. (A DevKit made without keys, or the key is on the PKI server.)" }
    $fips = [bool]$ca.Fips
    $eku = Get-PkiCsrEku -Purpose $Purpose
    $family = switch ($info.KeyAlg) { 'RSA' { 'rsa' } 'ECDSA' { 'ecdsa' } default { 'pqc' } }
    $ekuInfo = Get-PkiLeafEkuInfo -Eku $eku -Family $family
    $penPol = @($info.PolicyOids | Where-Object { $_ -match '^1\.3\.6\.1\.4\.1\.\d+(\.\d+)*$' })      # the company policy of the request (IANA PEN arc), 5.2.2
    $policies = Get-PkiLeafPolicies -Level $Level -PolicyText (@($Policy) + $penPol)
    if ($eku -contains 'TimeStamping') {
        $tsOid = [string](Get-PkiTimestampSettings).PolicyOid
        if ($tsOid -and -not ($policies | Where-Object { $_.Oid -eq $tsOid })) { $policies = @($policies) + @([ordered]@{ Label = 'TSA'; Oid = $tsOid; Cps = '' }) }
    }
    $days = Get-PkiSignCsrDays -Level $Level -Eku $eku -Days $daysAsked
    $room = Get-PkiIssuerRemainingDays -IssuerId $ca.Id
    if ($null -ne $room -and $days -gt $room) { Write-PkiLog "Validity limited by the issuer $($ca.Id): $days -> $room days." 'WARN'; $days = $room }
    if ($days -lt 1) { throw "The issuer $($ca.Id) has expired or ends within a day." }
    $md = Get-PkiIssueMd -Kind 'intermediate' -Family $ca.Actual.Family
    $names = $r.Names

    # ---- the output folder ----
    $cnValue = @($info.Subject | Where-Object { $_[0] -ceq 'CN' } | ForEach-Object { $_[1] }) | Select-Object -First 1
    if (-not $Name) { $Name = if ($cnValue) { $cnValue } else { 'csr' } }
    $safe = (($Name -replace '^\*\.', 'wildcard.' -replace '[^A-Za-z0-9._-]+', '-').Trim('-.')); if (-not $safe) { $safe = 'csr' }
    if (-not $OutRoot) { $OutRoot = Join-Path $c.ScriptRoot 'csr-signed' }
    $dir = Join-Path $OutRoot ("{0}_{1}" -f $safe, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    [void][System.IO.Directory]::CreateDirectory($dir)
    $csrOut = Join-Path $dir "$safe.csr"; $crt = Join-Path $dir "$safe.crt"
    Write-Utf8NoBom -Path $csrOut -Content ((([System.IO.File]::ReadAllText($info.Path)) -replace "`r", '').TrimEnd() + "`n")

    # ---- extensions ----
    $ext = Join-Path $dir 'ext.tmp.cnf'; $issuerCnf = Join-Path $dir 'issuer.tmp.cnf'
    $L = [System.Collections.Generic.List[string]]::new()
    foreach ($h in (Get-PkiProviderConfigHeader -Fips $fips)) { [void]$L.Add($h) }
    $refs = Add-PkiPolicySections -Lines $L -Policies $policies -Prefix 'lp'
    $loc = Add-PkiLocationSections -Lines $L -IssuerSlug $ca.Slug -Prefix 'll' -NoCrl:$NoCrl -NoOcsp:$NoOcsp
    $nSan = @($names.Dns).Count + @($names.Ip).Count + @($names.Email).Count
    if ($nSan -gt 0) {
        [void]$L.Add('[ san ]')
        $i = 0; foreach ($d in $names.Dns) { $i++; [void]$L.Add("DNS.$i = $(ConvertTo-PkiConfValue $d)") }
        $i = 0; foreach ($a in $names.Ip) { $i++; [void]$L.Add("IP.$i = $a") }
        $i = 0; foreach ($m in $names.Email) { $i++; [void]$L.Add("email.$i = $(ConvertTo-PkiConfValue $m)") }
        [void]$L.Add('')
    }
    [void]$L.Add('[ ext ]')
    [void]$L.Add('basicConstraints = critical,CA:false')
    [void]$L.Add("keyUsage = $($ekuInfo.KeyUsage)")
    [void]$L.Add("extendedKeyUsage = $($ekuInfo.Ekus)")
    foreach ($x in @($ekuInfo.Extra)) { if ($x) { [void]$L.Add($x) } }
    [void]$L.Add('subjectKeyIdentifier = hash'); [void]$L.Add('authorityKeyIdentifier = keyid,issuer')
    if ($nSan -gt 0) { [void]$L.Add('subjectAltName = @san') }
    [void]$L.Add("certificatePolicies = $refs")
    if ($loc.Crl) { [void]$L.Add('crlDistributionPoints = @ll_crl') }
    if ($loc.Aia) { [void]$L.Add('authorityInfoAccess = @ll_aia') }
    Write-Utf8NoBom -Path $ext -Content (($L -join "`n") + "`n")
    $issuerText = [System.IO.File]::ReadAllText($cp.Cnf)
    if ($issuerText -match '(?m)^\[ policy_any \]\s*$' -and $issuerText -notmatch '(?m)^organizationIdentifier\s*=') { $issuerText = $issuerText -replace '(?m)^(\[ policy_any \]\s*)$', "`$1`norganizationIdentifier = optional" }
    Write-Utf8NoBom -Path $issuerCnf -Content $issuerText
    if ($issuerText -match '(?m)^new_certs_dir\s*=\s*(.+?)\s*$') { $ncd = $Matches[1] -replace '\$dir', (Split-Path -Parent $cp.Cnf); if (-not (Test-Path -LiteralPath $ncd)) { [void](New-Item -ItemType Directory -Path $ncd -Force) } }   # an empty folder is lost in a zip

    # ---- sign ----
    try {
        $caArgs = @('ca', '-batch', '-notext', '-utf8', '-preserveDN', '-config', $issuerCnf, '-in', $csrOut, '-out', $crt, '-extfile', $ext, '-extensions', 'ext', '-days', [string]$days, '-md', $md)
        if ($Level -eq 'DV') { $caArgs += @('-subj', "/CN=$cnValue") }       # DV: the CN only, whatever else the request carried
        $caArgs += (Get-PkiSigOpts -Family $ca.Actual.Family -Md $md)
        $caArgs += (Get-PkiProviderArgs -Fips $fips)
        [void](Invoke-OpenSSL -Arguments $caArgs -ConfigPath $issuerCnf)
    }
    catch { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue; throw }
    finally { Remove-Item -LiteralPath $ext, $issuerCnf -Force -ErrorAction SilentlyContinue }
    Assert-PkiFile -Path $crt
    [void](ConvertTo-PkiLfFile -Path $crt)

    # ---- chain files ----
    $sbFull = [System.Text.StringBuilder]::new(); $sbChain = [System.Text.StringBuilder]::new(); $rootPem = ''
    [void]$sbFull.Append(([System.IO.File]::ReadAllText($crt)).TrimEnd() + "`n")
    foreach ($anc in @($ca) + @(Get-PkiCaAncestors -Ca $ca)) {
        $pem = (([System.IO.File]::ReadAllText((Get-PkiCaPaths -Ca $anc).Crt)) -replace "`r", '').TrimEnd() + "`n"
        if ($anc.Kind -eq 'root') { $rootPem = $pem; if ($null -eq $c.ExternalRoot) { continue } }
        [void]$sbFull.Append($pem); [void]$sbChain.Append($pem)
    }
    Write-Utf8NoBom -Path (Join-Path $dir "$safe-fullchain.crt") -Content $sbFull.ToString()
    Write-Utf8NoBom -Path (Join-Path $dir "$safe-chain.crt") -Content $sbChain.ToString()
    if ($rootPem) { Write-Utf8NoBom -Path (Join-Path $dir 'root.crt') -Content $rootPem }
    Write-Utf8NoBom -Path (Join-Path $dir 'our-ca-bundle.crt') -Content ($sbChain.ToString() + $rootPem)
    $cfg0 = Get-PkiProviderConfigPath -Fips $false; $prov0 = Get-PkiProviderArgs -Fips $false
    # DER (.cer) and PKCS#7 (.p7b) for Windows: double-click to install
    [void](Invoke-OpenSSL -AllowFailure -ConfigPath $cfg0 -Arguments (@('x509', '-in', $crt, '-outform', 'DER', '-out', (Join-Path $dir "$safe.cer")) + $prov0))
    [void](Invoke-OpenSSL -AllowFailure -ConfigPath $cfg0 -Arguments (@('crl2pkcs7', '-nocrl', '-certfile', (Join-Path $dir "$safe-fullchain.crt"), '-out', (Join-Path $dir "$safe.p7b")) + $prov0))

    # ---- verify ----
    $vr = Invoke-OpenSSL -AllowFailure -ConfigPath $cfg0 -Arguments (@('verify') + $prov0 + @('-CAfile', (Join-Path $dir 'our-ca-bundle.crt'), '-x509_strict', $crt))
    $chainOk = ($vr.ExitCode -eq 0)
    $ct = (Invoke-OpenSSL -ConfigPath $cfg0 -Arguments (@('x509', '-in', $crt, '-noout', '-serial', '-fingerprint', '-sha256', '-enddate', '-subject', '-nameopt', 'RFC2253') + $prov0)).StdOut
    $serial = if ($ct -match 'serial=(\S+)') { $Matches[1] } else { '' }
    $fp = if ($ct -match '(?i)sha256 Fingerprint=(\S+)') { $Matches[1] } else { '' }
    $end = if ($ct -match 'notAfter=(.+)') { $Matches[1].Trim() } else { '' }
    $finalSubject = if ($ct -match '(?m)^subject=(.+)$') { $Matches[1].Trim() } else { '' }
    $keyDesc = Get-PkiKeyDescription -Csr $info
    $infoJ = [ordered]@{
        name = $safe; level = $Level; quadrant = $Quadrant; track = $track; fips = $fips; purpose = $Purpose; issuer = $ca.Id; issuerCommonName = $ca["CommonName"]; pkiRelease = [int]$c.Release; pkiVariant = $(if ($c.NoCaRevocationInfo) { 'NoCR' } else { 'normal' })
        subject = $finalSubject; key = $keyDesc; san = $names; days = $days; notAfter = $end; serial = $serial; sha256 = $fp; signatureDigest = $md
        policies = @($policies | ForEach-Object { $_.Oid }); crlDistributionPoint = [bool]$loc.Crl; ocspUrl = [bool](-not $NoOcsp -and $c.OcspUrls.Count -gt 0)
        openSslVerify = $chainOk; warnings = @($r.Findings | Where-Object { $_.Severity -eq 'WARN' } | ForEach-Object { $_.Message })
        files = @(Get-ChildItem -LiteralPath $dir -File | ForEach-Object { $_.Name } | Sort-Object); createdUtc = [DateTime]::UtcNow.ToString('o')
        generator = "SignCsr / pki_setup $($script:PkiGeneratorVersion)"
    }
    Write-Utf8NoBom -Path (Join-Path $dir 'sign-info.json') -Content (($infoJ | ConvertTo-Json -Depth 6) + "`n")
    $readme = @"
SIGNED CERTIFICATE                    $safe
=====================================================================
Issuer       : $($ca.Id)   $($ca["CommonName"])
Level        : $Level   Quadrant $Quadrant ($track$(if ($fips) { ' FIPS' } else { ' non-FIPS' }))   Purpose: $Purpose
Subject      : $finalSubject
Names (SAN)  : $((@($names.Dns) + @($names.Ip) + @($names.Email)) -join ', ')
Key          : $keyDesc (YOUR key: we never saw the private key)
Valid until  : $end   ($days days)          Serial: $serial
SHA-256      : $fp
Revocation   : $(if ($loc.Crl) { 'CRL distribution point' } else { 'no CRL distribution point' }), $(if ($infoJ.ocspUrl) { 'OCSP URL' } else { 'no OCSP URL' })
Verification : openssl verify against our chain: $(if ($chainOk) { 'OK' } else { 'FAILED' })

FILES
  $safe.crt            your certificate (PEM)         $safe.cer   the same, DER (Windows: double click)
  $safe-fullchain.crt  your certificate + our CA chain (use this as the server certificate file)
  $safe-chain.crt      our CA chain only              $safe.p7b   certificate + chain for Windows
  root.crt             our Enterprise Root: clients must trust it (it is the trust anchor)
  our-ca-bundle.crt    our chain + root, for  openssl verify -CAfile
  $safe.csr            your request (unchanged)       sign-info.json   the facts for scripts
HIS SIDE
  Put your private key (the one you made the request with) and $safe-fullchain.crt in your server / application.
  Check:  openssl verify -CAfile our-ca-bundle.crt $safe.crt
"@
    Write-Utf8NoBom -Path (Join-Path $dir 'README.txt') -Content ($readme.Replace("`r", '') + "`n")
    $logLine = "{0}`t{1}`t{2}`t{3}`t{4}`t{5}`t{6}`n" -f [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'), $serial, $ca.Id, $Level, $Purpose, $safe, $end
    $tsv = Join-Path $OutRoot 'signed-csr.tsv'
    if (-not (Test-Path -LiteralPath $tsv)) { [System.IO.File]::WriteAllText($tsv, "# utc`tserial`tissuer`tlevel`tpurpose`tname`tnotAfter`n", [System.Text.UTF8Encoding]::new($false)) }
    [System.IO.File]::AppendAllText($tsv, $logLine, [System.Text.UTF8Encoding]::new($false))
    Write-PkiLog "Signed $keyDesc request '$safe' with $($ca.Id) ($Level, $days days): $dir" 'OK'
    if (-not $chainOk) { Write-PkiLog 'openssl verify (strict) against our chain failed - see README.txt.' 'WARN' }
    return [pscustomobject]@{ Signed = $true; Findings = $r.Findings; Errors = 0; Warnings = $r.Warnings; Dir = $dir; Certificate = $crt; Info = $infoJ }
}
