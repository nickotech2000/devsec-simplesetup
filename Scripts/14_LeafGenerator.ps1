# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 14_LeafGenerator.ps1  -  the leaf certificate generator
#
# ONE generator for every leaf certificate:
#     GenerateLeafCertificate.ps1   any level, any quadrant, any key, any format (Phase B)
#     pki_setup.ps1                 the default EV leaves (05_LeafCertificates.ps1 calls it)
#
#   Level      DV | OV | EV             -> intermediate q<N>-dv | -ov | -ev
#   Quadrant   Classic / Quantum, FIPS / non-FIPS   -> quadrant 1 2 3 4 (named Q1 Q2 in each track)
#   Subject    DV: CN only.  OV: CN, O, OU, L, ST, C, postalCode, street + contact.
#              EV: OV + serialNumber, businessCategory, jurisdiction*, optional D-U-N-S.
#   Key rules  RSA >= 2048, ECDSA >= P-256, hash >= SHA-256 (anything lower is REJECTED).
#              Code signing is forced to RSA >= 4096 / ECDSA >= P-384 / ML-DSA >= 65.
#   Validity   EV 397 days (the maximum, also for time stamping and OCSP), OV 3 years, DV 5 years, or -Days; never beyond the issuer.
#   Formats    PEM, DER, CER, CERT, P7B, RFC 7468, PFX (always .crt .key -fullchain.crt -chain.crt)
#   Purposes   ServerAuth, ClientAuth, ServerClientAuth (both EKUs in ONE certificate), CodeSigning, EmailProtection,
#              TimeStamping, OcspSigning. A SET makes one certificate per purpose in one go (Invoke-PkiLeafSet), each in
#              every format: TLS therefore comes in THREE variants (server only, client only, server + client).
#   Dev SAN    -AddDevelopmentSAN merges the [ development_san ] list (or the built-in copy) into the SAN of TLS certificates.
#   Output     a folder per leaf; if it exists a NEW folder with date and time is created.
#
# Provides : Get-PkiCodeSigningDn, Get-PkiDevelopmentSan, Add-PkiDevelopmentSan, Expand-PkiIpRange, Resolve-PkiPurposeEku, New-PkiLeafSpec, New-PkiLeafSetSpecs, Invoke-PkiLeafSet, New-PkiLeafCertificate, Resolve-PkiLeafKey, Get-PkiLeafSan, Get-PkiLeafDn,
#            Get-PkiLeafPolicies, Write-PkiLeafFormats, ConvertTo-PkiRfc7468, Test-PkiLeafResult,
#            Add-PkiLeafIndex, Show-PkiLeafIndex, Get-PkiOpenSslReadiness, Assert-PkiLeafOpenSslReady
# Requires : 00-04, 06 (Get-PkiCertText, Assert-PkiSignatureDigest), 11 (Add-PkiCheck, Invoke-PkiPqcSelfTest),
#            12_ExistingPki when working on an existing PKI
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:PkiEkuMap = [ordered]@{
    ServerAuth      = 'serverAuth'
    ClientAuth      = 'clientAuth'
    CodeSigning     = 'codeSigning'
    EmailProtection = 'emailProtection'
    TimeStamping    = 'timeStamping'
    OcspSigning     = 'OCSPSigning'
    # Microsoft Office / document purposes (GenerateOffice365LeafCertificate.ps1; not in the purpose sets of GenerateLeafCertificate.ps1)
    DocumentSigning    = '1.3.6.1.4.1.311.10.3.12'     # szOID_KP_DOCUMENT_SIGNING (Microsoft Office document signature)
    DocumentEncryption = '1.3.6.1.4.1.311.80.1'        # szOID_KP_DOCUMENT_ENCRYPTION
    DocumentSigningAdobe = '1.2.840.113583.1.1.5'      # Adobe Authentic Documents Trust (Acrobat / Reader: certified and approval PDF signatures)
}
# a custom purpose is a dotted OID (5.3.7): -Purpose 1.3.6.1.4.1.99999.1
$script:PkiOidPattern = '^[0-2](\.(0|[1-9][0-9]*)){2,}$'
function Test-PkiPurposeName {
    param([string]$Name)
    return ($script:PkiPurposeProfiles.Contains($Name) -or $script:PkiEkuMap.Contains($Name) -or ($Name -match $script:PkiOidPattern))
}
# The purposes of a SET (one certificate each). Order = order of generation.
$script:PkiPurposeProfiles = [ordered]@{
    ServerAuth      = @{ Token = 'server';    Label = 'TLS server';    Web = $true }
    ClientAuth      = @{ Token = 'client';    Label = 'TLS client';    Web = $true }
    ServerClientAuth = @{ Token = 'server-client'; Label = 'TLS server + client'; Web = $true; Eku = @('ServerAuth', 'ClientAuth') }
    CodeSigning     = @{ Token = 'codesign';  Label = 'Code signing';  Web = $false; CnRole = 'Code Signing' }
    EmailProtection = @{ Token = 'email';     Label = 'S/MIME + TLS client'; Web = $false; Eku = @('EmailProtection', 'ClientAuth') }
    TimeStamping    = @{ Token = 'timestamp'; Label = 'Time stamping'; Web = $false; CnRole = 'Time Stamping' }
    OcspSigning     = @{ Token = 'ocsp';      Label = 'OCSP signing';  Web = $false; CnRole = 'OCSP Responder' }
    # Document signing (5.3.7): chosen with -Purpose, NOT part of the default set (one certificate per purpose)
    DocumentSigning      = @{ Token = 'docsign';       Label = 'Document signing (Microsoft Office 365 / Office, LibreOffice)'; Web = $false; NotInSet = $true }
    DocumentSigningAdobe = @{ Token = 'docsign-adobe'; Label = 'Document signing (Adobe Acrobat / Reader PDF)'; Web = $false; NotInSet = $true }
}
# hashes below SHA-256 are rejected
$script:PkiRejectedHashes = @('md2', 'md4', 'md5', 'sha1', 'sha-1', 'sha224', 'sha-224', 'ripemd160', 'whirlpool', 'mdc2')

function Test-PkiDnsName {
    param([string]$Name)
    $n = $Name
    if ($n.StartsWith('*.')) { $n = $n.Substring(2) }
    return ($n -match '^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')
}

# ------------------------------------------------------------
# Subject alternative names
#   Given on the command line (any of the three) -> exactly these.
#   Nothing given -> [ leaf_san ] of agantra_pki.cnf (and -Domain of pki_setup.ps1).
# ------------------------------------------------------------
function Get-PkiLeafSan {
    param([string[]]$Dns = @(), [string[]]$Ip = @(), [string[]]$Email = @())
    $given = (@($Dns).Count + @($Ip).Count + @($Email).Count) -gt 0
    $dnsL = [System.Collections.Generic.List[string]]::new()
    $ipL = [System.Collections.Generic.List[string]]::new()
    $mailL = [System.Collections.Generic.List[string]]::new()

    if ($given) {
        foreach ($d in @($Dns)) { $t = $d.Trim(); if ($t -and -not ($dnsL | Where-Object { $_ -ieq $t })) { [void]$dnsL.Add($t) } }
        foreach ($a in @($Ip)) { $t = $a.Trim(); if ($t -and $ipL -notcontains $t) { [void]$ipL.Add($t) } }
        foreach ($m in @($Email)) { $t = $m.Trim(); if ($t -and -not ($mailL | Where-Object { $_ -ieq $t })) { [void]$mailL.Add($t) } }
    }
    else {
        $ini = $script:Pki.Ini
        foreach ($e in (Get-PkiIniEntries -Ini $ini -Section 'leaf_san')) {
            if ($e.Value -eq '') { continue }
            if ($e.Key -match '^(?i)DNS(\.\d+)?$') { [void]$dnsL.Add($e.Value) }
            elseif ($e.Key -match '^(?i)IP(\.\d+)?$') { [void]$ipL.Add($e.Value) }
            elseif ($e.Key -match '^(?i)email(\.\d+)?$') { [void]$mailL.Add($e.Value) }
        }
        $domain = $script:Pki.Domain
        if (-not [string]::IsNullOrWhiteSpace($domain)) {
            $old = @($dnsL)
            $dnsL.Clear()
            [void]$dnsL.Add($domain)
            if (-not $domain.StartsWith('*.') -and -not $domain.StartsWith('www.')) { [void]$dnsL.Add("www.$domain") }
            foreach ($d in $old) { if ($dnsL -notcontains $d -and $d -in @('localhost')) { [void]$dnsL.Add($d) } }
        }
    }
    foreach ($d in $dnsL) {
        if (-not (Test-PkiDnsName -Name $d)) { throw "Invalid DNS name in the SAN: '$d'" }
        if ($d.StartsWith('*.')) { Write-PkiLog "Wildcard SAN '$d' is allowed in this private PKI (a public certificate may not contain it)." 'WARN' }
    }
    foreach ($a in $ipL) {
        $tmp = $null
        if (-not [System.Net.IPAddress]::TryParse($a, [ref]$tmp)) { throw "Invalid IP address in the SAN: '$a'" }
    }
    foreach ($m in $mailL) { if ($m -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { throw "Invalid e-mail address in the SAN: '$m'" } }
    return [ordered]@{ Dns = @($dnsL); Ip = @($ipL); Email = @($mailL); Given = $given }
}

# ------------------------------------------------------------
# Purposes: a profile name can stand for several EKUs (ServerClientAuth = ServerAuth + ClientAuth)
# ------------------------------------------------------------
function Resolve-PkiPurposeEku {
    param([Parameter(Mandatory)][string[]]$Purpose)
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $Purpose) {
        $names = if ($script:PkiPurposeProfiles.Contains($p) -and $script:PkiPurposeProfiles[$p].Contains('Eku')) { @($script:PkiPurposeProfiles[$p]['Eku']) } else { @($p) }
        foreach ($n in $names) { if ($out -notcontains $n) { [void]$out.Add($n) } }
    }
    return @($out)
}

# ------------------------------------------------------------
# Development SAN (-AddDevelopmentSAN)
#   The list is [ development_san ] of agantra_pki.cnf (DNS.n, IP.n, IPRange.n = first-last, email.n); when that section
#   is missing or empty the built-in copy below is used. It is for DEVELOPMENT: wildcards, IP addresses, internal names
#   and e-mail addresses in one certificate are not allowed by the EV rules of a public CA, and they are deliberately
#   NOT checked here, also for an EV leaf.
# ------------------------------------------------------------
$script:PkiDevelopmentSanDefault = [ordered]@{
    Dns = @(
        'nextmantra.com', 'www.nextmantra.com', '*.nextmantra.com', 'localhost', 'local.dev',
        '*.nextmantra.internal', '*.nextmantra.developer', 'nextmantra.internal', 'nextmantra.developer', 'nextmantra.api', '*.nextmantra.api',
        'agantra.internal', '*.agantra.internal', 'agantra.developer', '*.agantra.developer', 'agantra.api', '*.agantra.api',
        'nextmantra.ldap', '*.nextmantra.ldap', 'agantra.ldap', '*.agantra.ldap')
    Ip = @('127.0.0.1', '::1', '10.10.2.2', '192.168.0.1-192.168.0.200', '172.16.0.1-172.16.0.200', '192.168.1.1-192.168.1.100', '192.168.2.1-192.168.2.100')    # a "first-last" entry is a range
    Email = @('nicko@nextmantra.com', 'robby@nextmantra.com', 'info@nextmantra.com', 'airlangga@nextmantra.com')
}
$script:PkiDevelopmentSanCache = $null

function Expand-PkiIpRange {
    # "192.168.0.1-192.168.0.200" -> 200 addresses. IPv4 only, at most 1024 addresses.
    param([Parameter(Mandatory)][string]$Range)
    $parts = @($Range -split '\s*-\s*')
    if ($parts.Count -ne 2) { throw "Invalid IP range '$Range': write first-last, for example 192.168.0.1-192.168.0.200." }
    $a = $null; $b = $null
    if (-not [System.Net.IPAddress]::TryParse($parts[0].Trim(), [ref]$a) -or -not [System.Net.IPAddress]::TryParse($parts[1].Trim(), [ref]$b) -or
        $a.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or $b.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Invalid IP range '$Range': both ends must be IPv4 addresses."
    }
    $toInt = { param($ip) $x = $ip.GetAddressBytes(); ([long]$x[0] * 16777216) + ([long]$x[1] * 65536) + ([long]$x[2] * 256) + [long]$x[3] }
    $first = & $toInt $a; $last = & $toInt $b
    if ($last -lt $first) { throw "Invalid IP range '$Range': the last address is below the first." }
    if (($last - $first) -ge 1024) { throw "IP range '$Range' has more than 1024 addresses: make it smaller (a certificate with thousands of addresses is not useful)." }
    for ($n = $first; $n -le $last; $n++) { '{0}.{1}.{2}.{3}' -f (($n -shr 24) -band 255), (($n -shr 16) -band 255), (($n -shr 8) -band 255), ($n -band 255) }
}

function Get-PkiDevelopmentSan {
    # -> [ordered]@{ Dns; Ip; Email; Source }   (cached for the run)
    if ($null -ne $script:PkiDevelopmentSanCache) { return $script:PkiDevelopmentSanCache }
    $dnsL = [System.Collections.Generic.List[string]]::new(); $ipL = [System.Collections.Generic.List[string]]::new(); $mailL = [System.Collections.Generic.List[string]]::new()
    $entries = @()
    try { if ($null -ne $script:Pki -and $null -ne $script:Pki.Ini) { $entries = @(Get-PkiIniEntries -Ini $script:Pki.Ini -Section 'development_san') } } catch { $entries = @() }
    $source = 'agantra_pki.cnf [ development_san ]'
    $addIp = { param($v) foreach ($x in $(if ($v -match '^\s*[0-9.]+\s*-\s*[0-9.]+\s*$') { Expand-PkiIpRange -Range $v } else { @($v.Trim()) })) { if ($ipL -notcontains $x) { [void]$ipL.Add($x) } } }
    $used = 0
    foreach ($e in $entries) {
        if ($null -eq $e -or [string]::IsNullOrWhiteSpace([string]$e.Value)) { continue }
        $used++
        if ($e.Key -match '^(?i)DNS(\.\d+)?$') { [void]$dnsL.Add($e.Value.Trim()) }
        elseif ($e.Key -match '^(?i)(IP|IPRange)(\.\d+)?$') { & $addIp $e.Value }
        elseif ($e.Key -match '^(?i)email(\.\d+)?$') { [void]$mailL.Add($e.Value.Trim()) }
        else { throw "[ development_san ] in the configuration: unknown key '$($e.Key)'. Use DNS.n, IP.n, IPRange.n or email.n." }
    }
    if ($used -eq 0) {
        $source = 'built-in list'
        $d = $script:PkiDevelopmentSanDefault
        foreach ($x in $d.Dns) { [void]$dnsL.Add($x) }
        foreach ($x in $d.Ip) { & $addIp $x }
        foreach ($x in $d.Email) { [void]$mailL.Add($x) }
    }
    $script:PkiDevelopmentSanCache = [ordered]@{ Dns = @($dnsL); Ip = @($ipL); Email = @($mailL); Source = $source }
    return $script:PkiDevelopmentSanCache
}

function Add-PkiDevelopmentSan {
    # Merges the development list into a SAN (duplicates removed, the names already there stay first). -EmailOnly: only the e-mail addresses.
    param([Parameter(Mandatory)]$San, [switch]$EmailOnly)
    $dev = Get-PkiDevelopmentSan
    $dnsL = [System.Collections.Generic.List[string]]::new(); $ipL = [System.Collections.Generic.List[string]]::new(); $mailL = [System.Collections.Generic.List[string]]::new()
    foreach ($x in $San.Dns) { [void]$dnsL.Add($x) }
    foreach ($x in $San.Ip) { [void]$ipL.Add($x) }
    foreach ($x in $San.Email) { [void]$mailL.Add($x) }
    $before = @($dnsL.Count, $ipL.Count, $mailL.Count)
    if (-not $EmailOnly) {
        foreach ($d in $dev.Dns) {
            if (-not (Test-PkiDnsName -Name $d)) { throw "Invalid DNS name in the development SAN: '$d'" }
            if (-not ($dnsL | Where-Object { $_ -ieq $d })) { [void]$dnsL.Add($d) }
        }
        $have = @{}; foreach ($x in $ipL) { $t = $null; if ([System.Net.IPAddress]::TryParse($x, [ref]$t)) { $have[$t.ToString()] = $true } }
        foreach ($a in $dev.Ip) {
            $t = $null
            if (-not [System.Net.IPAddress]::TryParse($a, [ref]$t)) { throw "Invalid IP address in the development SAN: '$a'" }
            $k = $t.ToString(); if (-not $have.ContainsKey($k)) { $have[$k] = $true; [void]$ipL.Add($a) }
        }
    }
    foreach ($m in $dev.Email) {
        if ($m -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { throw "Invalid e-mail address in the development SAN: '$m'" }
        if (-not ($mailL | Where-Object { $_ -ieq $m })) { [void]$mailL.Add($m) }
    }
    return [ordered]@{ Dns = @($dnsL); Ip = @($ipL); Email = @($mailL); Given = $San.Given
                       Added = [ordered]@{ Dns = $dnsL.Count - $before[0]; Ip = $ipL.Count - $before[1]; Email = $mailL.Count - $before[2] } }
}

# ------------------------------------------------------------
# Subject
# ------------------------------------------------------------
function Get-PkiLeafSubjectValue {
    # command line (only when passed) > [ subject_ev ] (EV only) > [ subject_ov ] > default
    param([string]$ParamName, [string]$IniKey, [string]$Default = '', [string]$Level = 'EV')
    $c = $script:Pki
    if (-not [string]::IsNullOrWhiteSpace($ParamName) -and $c.Bound.Contains($ParamName)) { return [string]$c.Bound[$ParamName] }
    $v = ''
    if ($IniKey -ne '') {
        if ($Level -eq 'EV') { $v = Get-PkiIniValue -Ini $c.Ini -Section 'subject_ev' -Key $IniKey -Default '' }
        if ($v -eq '') { $v = Get-PkiIniValue -Ini $c.Ini -Section 'subject_ov' -Key $IniKey -Default '' }
    }
    if ($v -eq '') { return $Default }
    return $v
}

function Get-PkiLeafDn {
    <#
    .SYNOPSIS
        Subject of a leaf, by level.
          DV  CN only
          OV  C ST L street postalCode O OU CN name emailAddress telephoneNumber
          EV  OV + businessCategory jurisdictionC/ST/L serialNumber (+ organizationIdentifier = DUNS+<number>)
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('DV', 'OV', 'EV')][string]$Level,
        [Parameter(Mandatory)]$San, [string[]]$Eku = @('ServerAuth', 'ClientAuth'), [string]$CommonName = ''
    )
    $c = $script:Pki
    $org = ConvertTo-PkiAscii (Get-PkiLeafSubjectValue 'Organization' 'O' 'Agantra Inovatif OU' $Level)
    $hasMail = (@($Eku) -contains 'EmailProtection')
    # an S/MIME certificate also carries clientAuth (mail clients, VPN and 802.1X use it) but it is not a web certificate: no DNS names
    $hasWeb = (@($Eku) -contains 'ServerAuth') -or ((@($Eku) -contains 'ClientAuth') -and -not $hasMail)
    $namesGiven = $San.Given -or $c.Bound.Contains('Domain')

    # common name
    $cn = $CommonName
    if ([string]::IsNullOrWhiteSpace($cn)) {
        if ($Level -eq 'DV') {
            if ($hasWeb -and $San.Dns.Count -gt 0) { $cn = $San.Dns[0] }
            elseif ($hasWeb -and $San.Ip.Count -gt 0) { $cn = $San.Ip[0] }
            elseif ($hasMail -and $San.Email.Count -gt 0) { $cn = $San.Email[0] }
            else { $cn = $org }
        }
        else {
            $cnIni = Get-PkiIniValue -Ini $c.Ini -Section 'subject_ov' -Key 'CN' -Default ''
            $first = if ($San.Dns.Count -gt 0) { $San.Dns[0] } elseif ($San.Ip.Count -gt 0) { $San.Ip[0] } elseif ($hasMail -and $San.Email.Count -gt 0) { $San.Email[0] } else { $org }
            $cn = if ($namesGiven) { $first } elseif ($cnIni -ne '') { $cnIni } else { $first }
        }
    }
    $pairs = [System.Collections.Generic.List[object]]::new()
    $add = { param($k, $v) if (-not [string]::IsNullOrWhiteSpace($v)) { [void]$pairs.Add(@($k, (ConvertTo-PkiAscii $v))) } }

    if ($Level -eq 'DV') { & $add 'CN' $cn; return ,$pairs }      # the comma: a one-pair list must not be unrolled

    if ($Level -eq 'EV') {
        & $add 'businessCategory' (Get-PkiLeafSubjectValue 'BusinessCategory' 'businessCategory' 'Private Organization' $Level)
        & $add 'jurisdictionCountryName' (Get-PkiLeafSubjectValue 'JurisdictionCountry' 'jurisdictionCountryName' 'EE' $Level)
        & $add 'jurisdictionStateOrProvinceName' (Get-PkiLeafSubjectValue 'JurisdictionState' 'jurisdictionStateOrProvinceName' 'Tallinn' $Level)
        & $add 'jurisdictionLocalityName' (Get-PkiLeafSubjectValue 'JurisdictionLocality' 'jurisdictionLocalityName' '' $Level)
        & $add 'serialNumber' (Get-PkiLeafSubjectValue 'Serial' 'serialNumber' '17344131' $Level)
    }
    & $add 'C' (Get-PkiLeafSubjectValue 'Country' 'C' 'EE' $Level)
    & $add 'ST' (Get-PkiLeafSubjectValue 'State' 'ST' 'Tallinn' $Level)
    & $add 'L' (Get-PkiLeafSubjectValue 'Locality' 'L' 'Tallinn' $Level)
    & $add 'street' (Get-PkiLeafSubjectValue 'Street' 'street' '' $Level)
    & $add 'postalCode' (Get-PkiLeafSubjectValue 'PostalCode' 'postalCode' '15199' $Level)
    & $add 'O' $org
    if ($Level -eq 'EV') {
        $duns = Get-PkiLeafSubjectValue 'Duns' 'DUNS' '' $Level
        if (-not [string]::IsNullOrWhiteSpace($duns)) { & $add 'organizationIdentifier' ("DUNS+" + ($duns -replace '[^0-9]', '')) }
    }
    & $add 'OU' (Get-PkiLeafSubjectValue 'OrganizationalUnit' 'OU' '' $Level)
    & $add 'CN' $cn
    # contact fields: the leaf has its own defaults, not the CA's contact
    $cName = if ($c.Bound.Contains('ContactName')) { [string]$c.Bound['ContactName'] } else { Get-PkiIniValue -Ini $c.Ini -Section 'subject_ov' -Key 'ContactName' -Default 'BizDevSecOps Administrator' }
    $cMail = if ($c.Bound.Contains('ContactEmail')) { [string]$c.Bound['ContactEmail'] } else { Get-PkiIniValue -Ini $c.Ini -Section 'subject_ov' -Key 'ContactEmail' -Default 'info@nextmantra.com' }
    $cTel  = if ($c.Bound.Contains('ContactPhone')) { [string]$c.Bound['ContactPhone'] } else { Get-PkiIniValue -Ini $c.Ini -Section 'subject_ov' -Key 'ContactPhone' -Default '(+372)53194019' }
    & $add 'name' $cName
    & $add 'emailAddress' $cMail
    & $add 'telephoneNumber' $cTel
    return ,$pairs
}

# ------------------------------------------------------------
# Subject of a CODE SIGNING certificate:  C, ST, L, O, CN   with CN = O = the company
#   -CodeSigningCompany "Name"   CN = O = Name
#   empty                        CN = O = the Organization (-Organization / cnf, default Agantra Inovatif OU)
#   C, ST, L                     -Country / -State / -Locality, else the cnf, else EE / Tallinn / Tallinn
#   Nothing else (no OU, street, contact fields, no EV-only fields): the subject of a code signing certificate stays short.
# ------------------------------------------------------------
function Get-PkiCodeSigningDn {
    param([string]$Company = '', [Parameter(Mandatory)][ValidateSet('DV', 'OV', 'EV')][string]$Level)
    $org = ConvertTo-PkiAscii (Get-PkiLeafSubjectValue 'Organization' 'O' 'Agantra Inovatif OU' $Level)
    $name = if ([string]::IsNullOrWhiteSpace($Company)) { $org } else { ConvertTo-PkiAscii $Company.Trim() }
    if ($name.Length -gt 64) { throw "The code signing company name is longer than 64 characters (CN and O may not be): '$name'" }
    $pairs = [System.Collections.Generic.List[object]]::new()
    $add = { param($k, $v) if (-not [string]::IsNullOrWhiteSpace($v)) { [void]$pairs.Add(@($k, (ConvertTo-PkiAscii $v))) } }
    & $add 'C'  (Get-PkiLeafSubjectValue 'Country' 'C' 'EE' $Level)
    & $add 'ST' (Get-PkiLeafSubjectValue 'State' 'ST' 'Tallinn' $Level)
    & $add 'L'  (Get-PkiLeafSubjectValue 'Locality' 'L' 'Tallinn' $Level)
    & $add 'O'  $name
    & $add 'CN' $name
    return ,$pairs
}

# ------------------------------------------------------------
# Policies: the level OID, the cnf / PEN policies of that level, and -Policy "OID|CPS" given for this leaf
# ------------------------------------------------------------
function Get-PkiLeafPolicies {
    param([Parameter(Mandatory)][ValidateSet('DV', 'OV', 'EV')][string]$Level, [string[]]$PolicyText = @())
    $c = $script:Pki
    $list = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $levelPolicy = [ordered]@{ Label = $Level; Oid = $script:PkiPolicyOid[$Level]; Cps = (Get-PkiCpsUrl -Level $Level) }
    [void]$seen.Add($levelPolicy.Oid); [void]$list.Add($levelPolicy)
    foreach ($p in (Get-PkiExtraPolicies -Level $Level)) { if ($seen.Add($p.Oid)) { [void]$list.Add($p) } }
    $i = 0
    foreach ($t in @($PolicyText)) {
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        $i++
        $p = ConvertTo-PkiPolicy -Text $t -Label "leaf-$i"
        if ($seen.Add($p.Oid)) { [void]$list.Add($p) }
    }
    return $list
}

# ------------------------------------------------------------
# Key policy.  Rejected: RSA < 2048, ECC < P-256, hash < SHA-256.
# Code signing is FORCED up: RSA >= 4096, ECDSA >= P-384, ML-DSA >= 65, hash >= SHA-256.
# ------------------------------------------------------------
function Resolve-PkiLeafKey {
    param(
        [Parameter(Mandatory)][int]$Quadrant, [string]$KeyType, [int]$KeyBits = 0, [string]$Curve, [string]$PqcAlgorithm,
        [string[]]$Eku = @('ServerAuth', 'ClientAuth')
    )
    $codeSigning = @($Eku) -contains 'CodeSigning'
    $quantum = $Quadrant -in 3, 4
    $notes = [System.Collections.Generic.List[string]]::new()

    if ([string]::IsNullOrWhiteSpace($KeyType)) {
        $KeyType = if ($quantum) { 'MLDSA' } elseif ($Quadrant -eq 2) { 'ECDSA' } else { 'RSA' }
    }
    $KeyType = $KeyType.ToUpperInvariant()
    if ($quantum -and $KeyType -ne 'MLDSA') { throw "Quadrants 3 and 4 (Quantum) issue ML-DSA leaves only; -KeyType $KeyType needs the Classic track (drop -Quantum)." }
    if (-not $quantum -and $KeyType -eq 'MLDSA') { throw '-KeyType MLDSA needs the Quantum track: add -Quantum.' }

    switch ($KeyType) {
        'RSA' {
            $bits = if ($KeyBits -gt 0) { $KeyBits } else { 2048 }
            if ($bits -lt 2048) { throw "RSA key size $bits is rejected: the minimum for a leaf is 2048." }
            if ($bits -notin 2048, 3072, 4096, 8192) { throw "RSA key size must be 2048, 3072, 4096 or 8192 (got $bits)." }
            if ($codeSigning -and $bits -lt 4096) { [void]$notes.Add("code signing: RSA $bits raised to 4096"); $bits = 4096 }
            return [ordered]@{ Family = 'rsa'; Bits = $bits; Curve = $null; PqcAlg = $null; Algorithm = "RSA-$bits"; Tag = "rsa$bits"; Notes = $notes }
        }
        'ECDSA' {
            $cv = if ($Curve) { $Curve.ToUpperInvariant() } else { 'P-256' }
            if ($cv -notin 'P-256', 'P-384', 'P-521') { throw "ECDSA curve must be P-256, P-384 or P-521 (got $cv); smaller curves are rejected." }
            if ($KeyBits -gt 0) { [void]$notes.Add("-KeyBits is for RSA; the ECDSA curve is $cv") }
            if ($codeSigning -and $cv -eq 'P-256') { [void]$notes.Add('code signing: ECDSA P-256 raised to P-384'); $cv = 'P-384' }
            return [ordered]@{ Family = 'ecdsa'; Bits = 0; Curve = $cv; PqcAlg = $null; Algorithm = "ECDSA-$($cv -replace '-','')"; Tag = "ecdsa-$($cv.ToLowerInvariant() -replace '-','')"; Notes = $notes }
        }
        'MLDSA' {
            $alg = if ($PqcAlgorithm) { $PqcAlgorithm } else { $script:Pki.PqcLeafAlgorithm }
            if ($alg -notmatch '^(?i)ml-?dsa-?(44|65|87)$') { throw "ML-DSA parameter set must be mldsa44, mldsa65 or mldsa87 (got $alg)." }
            $n = [int]$Matches[1]
            if ($codeSigning -and $n -lt 65) { [void]$notes.Add('code signing: ML-DSA-44 raised to ML-DSA-65'); $n = 65 }
            return [ordered]@{ Family = 'pqc'; Bits = 0; Curve = $null; PqcAlg = "mldsa$n"; Algorithm = "ML-DSA-$n"; Tag = "mldsa$n"; Notes = $notes }
        }
        default { throw "Unknown key type '$KeyType' (RSA, ECDSA or MLDSA)." }
    }
}

function Resolve-PkiLeafHash {
    # Digest of the leaf signature. The ISSUER decides (SHA-256 RSA, SHA-384 EC, none for ML-DSA); -Hash may raise it.
    param([Parameter(Mandatory)][hashtable]$Ca, [string]$Hash)
    $issuerMd = Get-PkiIssueMd -Kind 'intermediate' -Family $Ca.Actual.Family
    $notes = [System.Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrWhiteSpace($Hash)) { return [ordered]@{ Md = $issuerMd; Notes = $notes } }
    $h = $Hash.Trim().ToLowerInvariant()
    if ($h -in $script:PkiRejectedHashes) { throw "Hash '$Hash' is rejected: a leaf signature needs SHA-256 or stronger." }
    if ($h -notin 'sha256', 'sha384', 'sha512') { throw "Hash must be sha256, sha384 or sha512 (got '$Hash')." }
    if ($Ca.Actual.Family -eq 'pqc') { [void]$notes.Add("-Hash $h ignored: the issuer is ML-DSA and signs without a digest"); return [ordered]@{ Md = 'default'; Notes = $notes } }
    return [ordered]@{ Md = $h; Notes = $notes }
}

function Get-PkiLeafEkuInfo {
    # EKU names -> openssl names, key usage, extra extensions
    param([Parameter(Mandatory)][string[]]$Eku, [Parameter(Mandatory)][string]$Family)
    $names = foreach ($e in $Eku) {
        if ($script:PkiEkuMap.Contains($e)) { $script:PkiEkuMap[$e] }
        elseif ($e -match $script:PkiOidPattern) { $e }
        else { throw "Unknown purpose '$e'. Use: $($script:PkiEkuMap.Keys -join ', ') or a dotted OID such as 1.3.6.1.4.1.99999.1." }
    }
    $critical = $false
    $extra = [System.Collections.Generic.List[string]]::new()
    if ($Eku -contains 'TimeStamping') {
        if (@($Eku).Count -gt 1) { throw 'TimeStamping must be the ONLY purpose of its certificate (RFC 3161: the extended key usage is critical and alone).' }
        $critical = $true
    }
    if ($Eku -contains 'OcspSigning') {
        if (@($Eku).Count -gt 1) { throw 'OcspSigning must be the only purpose of its certificate.' }
        [void]$extra.Add('1.3.6.1.5.5.7.48.1.5 = ASN1:NULL')      # id-pkix-ocsp-nocheck: clients do not check the responder certificate
    }
    $ku = [System.Collections.Generic.List[string]]::new()
    [void]$ku.Add('digitalSignature')
    if ($Eku -contains 'EmailProtection' -or $Eku -contains 'DocumentSigning' -or $Eku -contains 'DocumentSigningAdobe') { [void]$ku.Add('nonRepudiation') }     # a signature that binds the signer (contentCommitment)
    if ($Family -eq 'ecdsa' -and $Eku -contains 'EmailProtection') { [void]$ku.Add('keyAgreement') }     # S/MIME encryption with ECDH
    if ($Family -eq 'rsa' -and ($Eku -contains 'ServerAuth' -or $Eku -contains 'EmailProtection')) { [void]$ku.Add('keyEncipherment') }
    $ekus = ($names -join ',')
    if ($critical) { $ekus = 'critical,' + $ekus }
    return [ordered]@{ Ekus = $ekus; KeyUsage = 'critical,' + ($ku -join ','); Extra = @($extra) }
}

# ------------------------------------------------------------
# Spec: everything decided BEFORE a file is written
# ------------------------------------------------------------
function New-PkiLeafSpec {
    <#
    .PARAMETER Options
        Level (DV|OV|EV), Quadrant (1-4), DnsName, IpAddress, EmailAddress, CommonName, Eku, KeyType, KeyBits,
        Curve, PqcAlgorithm, Hash, Days, Policy, Format, StemOverride
    #>
    param([Parameter(Mandatory)][hashtable]$Options)
    $c = $script:Pki
    $get = { param($k, $d) if ($Options.ContainsKey($k) -and $null -ne $Options[$k] -and "$($Options[$k])" -ne '') { $Options[$k] } else { $d } }

    $level = ([string](& $get 'Level' 'EV')).ToUpperInvariant()
    $q = [int](& $get 'Quadrant' 1)
    # TIME STAMPING is Classic non-FIPS (Quadrant 1) unless -TimestampQuadrant / [ timestamp ] Quadrant says otherwise (a quantum or FIPS TSA is prepared, not default)
    $tsaSet = $null
    if (@(& $get 'Eku' @()) -contains 'TimeStamping') {
        $tsaSet = Get-PkiTimestampSettings
        $baseQ = $q; $q = [int]$tsaSet.Quadrant
        $sameTrack = (($q -in 3, 4) -eq ($baseQ -in 3, 4))
        if ($q -ne $baseQ) { Write-PkiLog "Time stamping: Quadrant $q ($(if ($q -in 3, 4) { 'Quantum' } else { 'Classic' })$(if ($q -in 2, 4) { ' FIPS' } else { ' non-FIPS' })) instead of the Quadrant $baseQ of the other purposes (-TimestampQuadrant changes it)." }
        if (-not $sameTrack) { foreach ($k in 'KeyType', 'KeyBits', 'Curve', 'PqcAlgorithm', 'Hash') { if ($Options.ContainsKey($k)) { $Options = $Options.Clone(); $Options.Remove($k) } } }
    }
    if ([bool]$c.ClassicOnly -and $q -ge 3) { throw "Quadrant $q is the Quantum track (ML-DSA): this computer is Windows Server 2022, which can issue the CLASSIC track only (Quadrant 1 and 2; FIPS and non-FIPS; DV / OV / EV). Leave out -Quantum." }
    $ca = Get-PkiCa -Id ("q$q-" + $level.ToLowerInvariant())
    if ($null -eq $ca.Actual) { throw "CA '$($ca.Id)' is not loaded (Import-PkiExisting first).$(if ($null -ne $tsaSet) { " The time stamping certificate needs Quadrant $q (Classic non-FIPS is the default): build it, or choose another with -TimestampQuadrant." })" }
    $fips = [bool]$ca.Fips
    $track = if ($q -in 3, 4) { 'Quantum' } else { 'Classic' }
    $eku = @(& $get 'Eku' @('ServerAuth', 'ClientAuth'))
    $notes = [System.Collections.Generic.List[string]]::new()

    # names
    $dnsIn = @(& $get 'DnsName' @()); $ipIn = @(& $get 'IpAddress' @()); $mailIn = @(& $get 'EmailAddress' @())
    $webPurpose = ($eku -contains 'ServerAuth') -or (($eku -contains 'ClientAuth') -and ($eku -notcontains 'EmailProtection'))
    if (($dnsIn.Count + $ipIn.Count + $mailIn.Count) -eq 0 -and -not $webPurpose) {
        # code signing / S/MIME only: the default web names of [ leaf_san ] do not belong in such a certificate
        $san = [ordered]@{ Dns = @(); Ip = @(); Email = @(); Given = $false }
    }
    else { $san = Get-PkiLeafSan -Dns $dnsIn -Ip $ipIn -Email $mailIn }
    $devSan = $false
    if ($Options.ContainsKey('AddDevelopmentSan') -and [bool]$Options['AddDevelopmentSan']) {
        if ($webPurpose) { $san = Add-PkiDevelopmentSan -San $san; $devSan = $true }
        elseif ($eku -contains 'EmailProtection') { $san = Add-PkiDevelopmentSan -San $san -EmailOnly; $devSan = $true }
    }
    $evSanOverride = ($devSan -and $level -eq 'EV' -and $webPurpose)
    if ($eku -contains 'ServerAuth' -and ($san.Dns.Count + $san.Ip.Count) -eq 0) { throw 'ServerAuth needs at least one DNS name or IP address (-DnsName / -IpAddress).' }
    if ($eku -contains 'EmailProtection' -and $san.Email.Count -eq 0) { throw 'EmailProtection needs at least one e-mail address (-EmailAddress).' }
    if ($eku -contains 'CodeSigning' -and $level -eq 'DV') { Write-PkiLog 'A code signing certificate is normally OV or EV; DV carries no organization in its subject.' 'WARN' }
    if ($eku -contains 'CodeSigning' -and ($eku -contains 'ServerAuth' -or $eku -contains 'ClientAuth' -or $eku -contains 'EmailProtection')) { Write-PkiLog 'Code signing is combined with another purpose in ONE certificate: separate certificates are the usual practice (use the set: no -Purpose).' 'WARN' }

    # key and hash.  -AddDevelopmentSAN + e-mail (S/MIME): the algorithm of the person certificates (ECDSA P-384, SHA-512) unless the caller chose one
    $kt0 = [string](& $get 'KeyType' ''); $cv0 = [string](& $get 'Curve' ''); $hs0 = [string](& $get 'Hash' '')
    if ($Options.ContainsKey('AddDevelopmentSan') -and [bool]$Options['AddDevelopmentSan'] -and $eku -contains 'EmailProtection' -and $q -in 1, 2) {
        $dflt = [System.Collections.Generic.List[string]]::new()
        if ($kt0 -eq '') { $kt0 = 'ECDSA'; [void]$dflt.Add('ECDSA') }
        if ($kt0.ToUpperInvariant() -eq 'ECDSA' -and $cv0 -eq '') { $cv0 = 'P-384'; [void]$dflt.Add('P-384') }
        if ($hs0 -eq '') { $hs0 = 'sha512'; [void]$dflt.Add('SHA-512') }
        if ($dflt.Count -gt 0) { [void]$notes.Add("development e-mail certificate: default algorithm of the person certificates ($($dflt -join ', '))") }
    }
    $key = Resolve-PkiLeafKey -Quadrant $q -KeyType $kt0 -KeyBits ([int](& $get 'KeyBits' 0)) -Curve $cv0 -PqcAlgorithm (& $get 'PqcAlgorithm' '') -Eku $eku
    foreach ($n in $key.Notes) { [void]$notes.Add($n) }
    $h = Resolve-PkiLeafHash -Ca $ca -Hash $hs0
    foreach ($n in $h.Notes) { [void]$notes.Add($n) }
    $ekuInfo = Get-PkiLeafEkuInfo -Eku $eku -Family $key.Family
    # a person certificate (GeneratePersonLeafCertificate.ps1) fixes its own key usage, subject, extra extensions and config sections
    $kuFixed = $false
    if ($Options.ContainsKey('KeyUsage') -and $Options['KeyUsage']) { $ekuInfo = [ordered]@{ Ekus = $ekuInfo.Ekus; KeyUsage = [string]$Options['KeyUsage']; Extra = @($ekuInfo.Extra) }; $kuFixed = $true }

    # subject, policies
    $dn = if ($Options.ContainsKey('PersonDn') -and $Options['PersonDn']) { $Options['PersonDn'] }
          elseif ($eku -contains 'CodeSigning') { Get-PkiCodeSigningDn -Company ([string](& $get 'CodeSigningCompany' '')) -Level $level }
          else { Get-PkiLeafDn -Level $level -San $san -Eku $eku -CommonName ([string](& $get 'CommonName' '')) }
    $policies = Get-PkiLeafPolicies -Level $level -PolicyText @(& $get 'Policy' @())
    $tsaOid = ''
    if ($null -ne $tsaSet) {
        $tsaOid = [string]$tsaSet.PolicyOid
        if ($tsaOid -eq '') { [void]$notes.Add('no time stamp policy OID: set -TimestampPolicyOid (or [ timestamp ] PolicyOid, or the IANA PEN) - the time stamp server needs one') }
        elseif (-not ($policies | Where-Object { $_.Oid -eq $tsaOid })) { $policies = @($policies) + @([ordered]@{ Label = 'TSA'; Oid = $tsaOid; Cps = '' }) }
    }

    # validity
    $days = [int](& $get 'Days' 0)
    # a time stamp must stay verifiable long after it was made: the TSA certificate lives longer than a TLS certificate (private PKI); an EV certificate is capped at 397 days below
    if ($days -le 0 -and $null -ne $tsaSet) { $days = [int]$tsaSet.Days }
    if ($days -le 0 -and ($eku -contains 'OcspSigning')) { $days = [int]$c.OcspDays }
    if ($days -le 0) { $days = Get-PkiLeafDays -Level $level }
    if ($level -eq 'EV' -and $days -gt 397) {
        if ($null -ne $tsaSet -or ($eku -contains 'OcspSigning')) {
            if ([int](& $get 'Days' 0) -gt 0) { [void]$notes.Add("EV: validity limited to 397 days (asked $days)") }     # a default is capped silently
            $days = 397
        }
        else { throw "An EV certificate may not be valid longer than 397 days (asked $days)." }
    }
    $room = Get-PkiIssuerRemainingDays -IssuerId $ca.Id
    if ($null -ne $room -and $days -gt $room) { [void]$notes.Add("validity limited by the issuer: $days -> $room days"); $days = $room }
    if ($days -lt 1) { throw "The issuer $($ca.Id) has expired or ends within a day: no leaf can be issued." }

    # formats
    $fm = @(& $get 'Format' @('PFX')) | ForEach-Object { $_.ToUpperInvariant() } | Select-Object -Unique
    if ($fm -contains 'ALL') { $fm = @('PEM', 'DER', 'CER', 'CERT', 'P7B', 'RFC7468', 'PFX') }

    # names of folder and files
    $cnValue = @($dn | Where-Object { $_[0] -eq 'CN' } | ForEach-Object { $_[1] }) | Select-Object -First 1
    $primary = if ($san.Dns.Count -gt 0) { $san.Dns[0] } elseif ($san.Ip.Count -gt 0) { $san.Ip[0] } elseif ($san.Email.Count -gt 0) { $san.Email[0] } elseif ($cnValue) { $cnValue } else { 'leaf' }
    $nq = [int](Get-PkiNamingQuadrant -Ca $ca)      # the number in NAMES: 1 = non-FIPS, 2 = FIPS, in both tracks (file names of the leaf)
    $purposeAbbr = ($eku | ForEach-Object { if ($script:PkiPurposeProfiles.Contains($_)) { $script:PkiPurposeProfiles[$_].Token } elseif ($_ -match $script:PkiOidPattern) { 'oid-' + ($_ -replace '\.', '-') } else { $_.ToLowerInvariant() } }) -join '-'
    $purposeLong = ($eku | ForEach-Object { if ($_ -match $script:PkiOidPattern) { 'oid-' + ($_ -replace '\.', '-') } else { $_.ToLowerInvariant() } }) -join '-'
    if ($eku -contains 'EmailProtection') { $purposeAbbr = 'email'; $purposeLong = 'emailprotection' }     # S/MIME (+ clientAuth): the short names stay
    # Friendly name of the PFX (shown in certlm.msc / the Windows import): "<Primary EKU> for <CN> Sign by : <Intermediate CA CN>"
    $ekuLabels = @{ ServerAuth = 'Server Authentication'; ClientAuth = 'Client Authentication'; CodeSigning = 'Code Signing'; EmailProtection = 'Secure Email'; TimeStamping = 'Time Stamping'; OcspSigning = 'OCSP Signing'; DocumentSigning = 'Document Signing'; DocumentSigningAdobe = 'Document Signing (Adobe)' }
    $firstEku = [string](@($eku) | Select-Object -First 1)
    $ekuText = if ($ekuLabels.ContainsKey($firstEku)) { $ekuLabels[$firstEku] } elseif ($firstEku -match $script:PkiOidPattern) { "Custom EKU $firstEku" } elseif ($firstEku) { $firstEku } else { 'Certificate' }
    $friendly = "$ekuText for $(if ($cnValue) { $cnValue } else { $primary }) Sign by : $(Get-PkiCaCommonName -Ca $ca)"
    $now = Get-Date
    $tokens = @{
        Name = (ConvertTo-PkiSafeName $(if ($Options.ContainsKey('NameOverride') -and $Options['NameOverride']) { [string]$Options['NameOverride'] } else { $primary })); Level = $level.ToLowerInvariant(); Quadrant = "q$nq"; Tag = "q$nq-$($key.Tag)"
        Algorithm = $key.Algorithm; Track = $track.ToLowerInvariant(); Fips = $(if ($fips) { 'fips' } else { 'nonfips' })
        Purpose = $purposeAbbr; PurposeName = $purposeLong; Date = $now.ToString('yyyyMMdd'); Time = $now.ToString('HHmmss')
    }
    $names = Get-PkiLeafNames -Tokens $tokens
    $setMode = ($Options.ContainsKey('SetMode') -and [bool]$Options['SetMode'])
    $stem = if ($Options.ContainsKey('StemOverride') -and $Options['StemOverride']) { [string]$Options['StemOverride'] } elseif ($setMode) { $names.PurposeStem } else { $names.Stem }

    return @{
        Level = $level; Quadrant = $q; Track = $track; Fips = $fips; Ca = $ca
        Family = $key.Family; Bits = $key.Bits; Curve = $key.Curve; PqcAlg = $key.PqcAlg; KeyAlgorithm = $key.Algorithm; Tag = $tokens.Tag
        Md = $h.Md; Eku = $eku; EkuOpenSsl = $ekuInfo.Ekus; KeyUsage = $ekuInfo.KeyUsage; KeyUsageFixed = $kuFixed
        ExtraExt = (@($ekuInfo.Extra) + @(& $get 'ExtraExt' @())); ExtraConfig = @(& $get 'ExtraConfig' @())
        San = $san; DnPairs = $dn; Policies = $policies; Days = $days
        Primary = $primary; FriendlyName = $friendly; Folder = $names.Folder; PurposeFolder = $names.PurposeFolder; SetMode = $setMode; Stem = $stem; OutputFolder = $names.OutputFolder; UniqueSuffix = $names.UniqueSuffix
        Formats = @($fm); Notes = $notes; Tokens = $tokens
        NoCrl = [bool](& $get 'NoCrl' $false); NoOcsp = [bool](& $get 'NoOcsp' $false)
        DevSan = $devSan; EvSanOverride = $evSanOverride; TimestampPolicyOid = $tsaOid
        OutDir = $null; Extras = $true
    }
}

# ------------------------------------------------------------
# RFC 7468 textual encoding (strict: only the BEGIN/END lines and 64-character base64 lines, LF)
# ------------------------------------------------------------
function ConvertTo-PkiRfc7468 {
    param([Parameter(Mandatory)][byte[]]$Der, [string]$Label = 'CERTIFICATE')
    $b64 = [Convert]::ToBase64String($Der)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("-----BEGIN $Label-----`n")
    for ($i = 0; $i -lt $b64.Length; $i += 64) { [void]$sb.Append($b64.Substring($i, [Math]::Min(64, $b64.Length - $i)) + "`n") }
    [void]$sb.Append("-----END $Label-----`n")
    return $sb.ToString()
}

# ------------------------------------------------------------
# Output formats (default provider: certificates carry no secret)
# ------------------------------------------------------------
function Write-PkiLeafFormats {
    param([Parameter(Mandatory)][hashtable]$Spec, [Parameter(Mandatory)][hashtable]$R)
    $dir = $Spec.OutDir; $stem = $Spec.Stem
    $cnf = Get-PkiProviderConfigPath -Fips $false
    $prov = Get-PkiProviderArgs -Fips $false
    $fm = $Spec.Formats
    $made = [System.Collections.Generic.List[string]]::new()
    $der = Join-Path $dir "$stem.der"

    if ($fm -contains 'PEM') { Copy-Item -LiteralPath $R.Crt -Destination (Join-Path $dir "$stem.pem") -Force; [void]$made.Add("$stem.pem") }
    if ($fm -contains 'CERT') { Copy-Item -LiteralPath $R.Crt -Destination (Join-Path $dir "$stem.cert") -Force; [void]$made.Add("$stem.cert") }
    if ($fm -contains 'DER' -or $fm -contains 'CER') {
        [void](Invoke-OpenSSL -ConfigPath $cnf -Arguments (@('x509', '-in', $R.Crt, '-outform', 'DER', '-out', $der) + $prov))
        if ($fm -contains 'DER') { [void]$made.Add("$stem.der") }
        if ($fm -contains 'CER') { Copy-Item -LiteralPath $der -Destination (Join-Path $dir "$stem.cer") -Force; [void]$made.Add("$stem.cer") }
        if ($fm -notcontains 'DER') { Remove-Item -LiteralPath $der -Force }
    }
    if ($fm -contains 'P7B') {
        [void](Invoke-OpenSSL -ConfigPath $cnf -Arguments (@('crl2pkcs7', '-nocrl', '-certfile', $R.Full, '-out', (Join-Path $dir "$stem.p7b")) + $prov))
        [void]$made.Add("$stem.p7b")
    }
    if ($fm -contains 'RFC7468') {
        $bytes = [byte[]](ConvertFrom-PkiPemToDer -Path $R.Crt)
        Write-Utf8NoBom -Path (Join-Path $dir "$stem.rfc7468.pem") -Content (ConvertTo-PkiRfc7468 -Der $bytes -Label 'CERTIFICATE')
        [void]$made.Add("$stem.rfc7468.pem")
    }
    return $made
}

# ------------------------------------------------------------
# The generator
# ------------------------------------------------------------
function New-PkiLeafCertificate {
    param([Parameter(Mandatory)][hashtable]$Spec)

    $c = $script:Pki
    $ca = $Spec.Ca
    $cp = Get-PkiCaPaths -Ca $ca
    $fips = [bool]$Spec.Fips
    $dir = $Spec.OutDir
    $stem = $Spec.Stem
    if ([string]::IsNullOrWhiteSpace($dir) -or -not (Test-Path -LiteralPath $dir -PathType Container)) { throw "Leaf output folder does not exist: $dir" }

    $key = Join-Path $dir "$stem.key"; $csr = Join-Path $dir "$stem.csr"; $crt = Join-Path $dir "$stem.crt"
    $cnf = Join-Path $dir "$stem.cnf"; $full = Join-Path $dir "$stem-fullchain.crt"; $chainF = Join-Path $dir "$stem-chain.crt"
    $pfx = Join-Path $dir "$stem.pfx"; $pfxFips = Join-Path $dir "$stem-fips.pfx"
    $issuerCnf = Join-Path $dir "$stem.issuer.tmp.cnf"

    Write-PkiLog "Leaf $stem  ($($Spec.Level), quadrant $($Spec.Quadrant) $($Spec.Track)$(if ($fips) { ' FIPS' }), issuer $($ca.Id))"
    foreach ($n in $Spec.Notes) { Write-PkiLog "  note       : $n" 'WARN' }

    # ---- key ----
    $actual = New-PkiPrivateKey -KeyPath $key -Family $Spec.Family -Bits $Spec.Bits -Curve $Spec.Curve -Fips $fips -Label $stem -PqcAlgorithm $Spec.PqcAlg -FallbackBits $c.FallbackRsaBits
    Write-PkiLog "  key        : $($actual.Algorithm)$(if ($actual.Fallback) { '  (FALLBACK, not quantum-safe)' })"
    [void](ConvertTo-PkiLfFile -Path $key)
    # key pair: the public key next to the private key (PEM = SubjectPublicKeyInfo, and DER)
    $pubPem = Join-Path $dir "$stem.pub"; $pubDer = Join-Path $dir "$stem.pub.der"
    $kProv = Get-PkiProviderArgs -Fips $fips; $kCnf = Get-PkiProviderConfigPath -Fips $fips
    $pubText = (Invoke-OpenSSL -ConfigPath $kCnf -Arguments (@('pkey', '-in', $key, '-pubout') + $kProv)).StdOut
    Write-Utf8NoBom -Path $pubPem -Content (($pubText -replace "`r", '').TrimEnd() + "`n")
    [void](Invoke-OpenSSL -ConfigPath $kCnf -Arguments (@('pkey', '-in', $key, '-pubout', '-outform', 'DER', '-out', $pubDer) + $kProv))

    # ---- configuration: [ req ] [ dn ] [ ext ] ----
    $san = $Spec.San
    $L = [System.Collections.Generic.List[string]]::new()
    foreach ($h in (Get-PkiProviderConfigHeader -Fips $fips)) { [void]$L.Add($h) }
    [void]$L.Add('[ req ]'); [void]$L.Add('prompt = no'); [void]$L.Add('utf8 = yes')
    [void]$L.Add('string_mask = utf8only'); [void]$L.Add('distinguished_name = dn'); [void]$L.Add('')
    [void]$L.Add('[ dn ]')
    foreach ($pair in $Spec.DnPairs) { [void]$L.Add("$($pair[0]) = $(ConvertTo-PkiConfValue $pair[1])") }
    [void]$L.Add('')
    $policyRefs = Add-PkiPolicySections -Lines $L -Policies $Spec.Policies -Prefix 'lp'
    $loc = Add-PkiLocationSections -Lines $L -IssuerSlug $ca.Slug -Prefix 'll' -NoCrl:([bool]$Spec['NoCrl']) -NoOcsp:([bool]$Spec['NoOcsp'])
    [void]$L.Add('[ san ]')
    $i = 0; foreach ($d in $san.Dns)   { $i++; [void]$L.Add("DNS.$i = $(ConvertTo-PkiConfValue $d)") }
    $i = 0; foreach ($a in $san.Ip)    { $i++; [void]$L.Add("IP.$i = $a") }
    $i = 0; foreach ($m in $san.Email) { $i++; [void]$L.Add("email.$i = $(ConvertTo-PkiConfValue $m)") }
    [void]$L.Add('')
    $ku = $Spec.KeyUsage
    if ($actual.Family -ne $Spec.Family -and -not [bool]$Spec['KeyUsageFixed']) {
        # PQC fallback produced RSA: key usage for RSA
        $ku = Get-PkiLeafEkuInfo -Eku $Spec.Eku -Family $actual.Family | ForEach-Object { $_.KeyUsage }
    }
    if ($Spec.ContainsKey('ExtraConfig')) { foreach ($x in @($Spec.ExtraConfig)) { [void]$L.Add([string]$x) } }
    [void]$L.Add('[ ext ]')
    [void]$L.Add('basicConstraints = critical,CA:false')
    [void]$L.Add("keyUsage = $ku")
    [void]$L.Add("extendedKeyUsage = $($Spec.EkuOpenSsl)")
    foreach ($x in @($Spec.ExtraExt)) { if ($x) { [void]$L.Add($x) } }
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

    # ---- issuer configuration: the issuer's own file plus the DN fields a leaf may carry ----
    $issuerText = [System.IO.File]::ReadAllText($cp.Cnf)
    if ($issuerText -match '(?m)^\[ policy_any \]\s*$' -and $issuerText -notmatch '(?m)^organizationIdentifier\s*=') {
        $issuerText = $issuerText -replace '(?m)^(\[ policy_any \]\s*)$', "`$1`norganizationIdentifier = optional"
    }
    Write-Utf8NoBom -Path $issuerCnf -Content $issuerText

    # ---- issue (issuer's key / provider / digest) ----
    $md = $Spec.Md
    $caArgs = @('ca', '-batch', '-notext', '-utf8', '-preserveDN', '-config', $issuerCnf, '-in', $csr, '-out', $crt,
                '-extfile', $cnf, '-extensions', 'ext', '-days', [string]$Spec.Days, '-md', $md)
    $caArgs += (Get-PkiSigOpts -Family $ca.Actual.Family -Md $md)
    $caArgs += (Get-PkiProviderArgs -Fips $fips)
    [void](Invoke-OpenSSL -Arguments $caArgs -ConfigPath $issuerCnf)
    Assert-PkiFile -Path $crt
    [void](ConvertTo-PkiLfFile -Path $crt)

    # ---- chains: full = leaf + CAs; chain = CAs only (the self-signed Enterprise Root is installed on clients) ----
    $sb = [System.Text.StringBuilder]::new()
    $chainOnly = [System.Text.StringBuilder]::new()
    [void]$sb.Append((([System.IO.File]::ReadAllText($crt)) -replace "`r", '').TrimEnd() + "`n")
    foreach ($anc in @($ca) + @(Get-PkiCaAncestors -Ca $ca)) {
        if ($anc.Kind -eq 'root' -and $null -eq $c.ExternalRoot) { continue }
        $t = (([System.IO.File]::ReadAllText((Get-PkiCaPaths -Ca $anc).Crt)) -replace "`r", '').TrimEnd() + "`n"
        [void]$sb.Append($t); [void]$chainOnly.Append($t)
    }
    if ($null -ne $c.ExternalRoot) {
        foreach ($pem in (Get-PkiExternalChainIntermediates)) { $pl = ($pem -replace "`r", '').TrimEnd() + "`n"; [void]$sb.Append($pl); [void]$chainOnly.Append($pl) }
    }
    Write-Utf8NoBom -Path $full -Content $sb.ToString()
    Write-Utf8NoBom -Path $chainF -Content $chainOnly.ToString()
    # a cross-certificate was imported (-ImportCrossCert): also the chain for clients that only know the public root
    $cross = Get-PkiLatestCrossCertificate
    if ($null -ne $cross) { [void](New-PkiCrossFullchainFile -FullChain $full -Cross $cross) }

    # ---- PFX (normal container; FIPS leaves also get a FIPS-conformant one) ----
    $pfxOk = $false; $pfxFipsOk = $false
    if ($Spec.Formats -contains 'PFX') {
        try { [void](New-PkiPfxFile -KeyPath $key -CertPath $crt -PfxPath $pfx -ChainPath $chainF -Name $Spec.FriendlyName -Legacy:$c.LegacyPfx); $pfxOk = $true }
        catch { Write-PkiLog "PFX for $stem was not created: $($_.Exception.Message.Split("`n")[0])" 'WARN' }
        if ($fips) {
            try { [void](New-PkiPfxFile -KeyPath $key -CertPath $crt -PfxPath $pfxFips -ChainPath $chainF -Name $Spec.FriendlyName -FipsContainer); $pfxFipsOk = $true }
            catch { Write-PkiLog "FIPS-conformant PFX for $stem was not created: $($_.Exception.Message.Split("`n")[0])" 'WARN' }
        }
    }
    Remove-Item -LiteralPath $csr, $issuerCnf -Force -ErrorAction SilentlyContinue

    $fp = Get-PkiCertificateFingerprint -Path $crt
    $notAfter = ''
    try {
        $endText = (Invoke-OpenSSL -ConfigPath (Get-PkiProviderConfigPath -Fips $false) -Arguments (@('x509', '-in', $crt, '-noout', '-enddate') + (Get-PkiProviderArgs -Fips $false))).StdOut.Trim() -replace '^notAfter=', ''
        $notAfter = ([DateTime]::ParseExact(($endText -replace ' GMT', '' -replace '\s+', ' ').Trim(), 'MMM d HH:mm:ss yyyy', [Globalization.CultureInfo]::InvariantCulture)).ToString('yyyy-MM-dd')
    }
    catch { }

    $R = @{
        Stem = $stem; Dir = $dir; Crt = $crt; Key = $key; Full = $full; Chain = $chainF; Cnf = $cnf
        Pfx = $(if ($pfxOk) { $pfx } else { $null }); PfxFips = $(if ($pfxFipsOk) { $pfxFips } else { $null })
        Sha1 = $fp.Sha1; Sha256 = $fp.Sha256; Actual = $actual; Md = $md; Days = $Spec.Days; NotAfter = $notAfter; Files = @()
    }
    $extra = Write-PkiLeafFormats -Spec $Spec -R $R
    foreach ($f in @($full, $chainF, (Join-Path $dir "$stem.pem"), (Join-Path $dir "$stem.cert"))) { [void](ConvertTo-PkiLfFile -Path $f) }
    $R.PubPem = $pubPem; $R.PubDer = $pubDer
    # <stem>.sha256 / <stem>.sha512 ... : the hashes of the certificate files of this stem (-HashFile; default sha256 + sha512)
    $hashAlgs = if (Test-Path variable:script:PkiHashFileAlgs) { @($script:PkiHashFileAlgs) } else { @('sha256', 'sha512') }
    [void](Write-PkiHashFiles -Directory $dir -Stem $stem -Algorithm $hashAlgs)
    $R.Files = @(Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Name -notlike '*.tmp.*' } | ForEach-Object { $_.Name } | Sort-Object)
    Write-PkiLog "  thumbprint : $($fp.Sha1)" 'OK'
    return $R
}

# ------------------------------------------------------------
# Validation of what was written
# ------------------------------------------------------------
function Test-PkiLeafResult {
    param([Parameter(Mandatory)][hashtable]$Spec, [Parameter(Mandatory)][hashtable]$R)
    $ca = $Spec.Ca
    $fips = [bool]$Spec.Fips
    $id = $R.Stem
    $t = Get-PkiCertText -Path $R.Crt -Fips $fips
    $problems = [System.Collections.Generic.List[string]]::new()

    if ($t -notmatch 'CA:FALSE') { [void]$problems.Add('basicConstraints CA:FALSE is missing') }
    foreach ($e in $Spec.Eku) {
        $label = switch ($e) { 'ServerAuth' { 'TLS Web Server Authentication' } 'ClientAuth' { 'TLS Web Client Authentication' } 'EmailProtection' { 'E-mail Protection' } 'CodeSigning' { 'Code Signing' } 'TimeStamping' { 'Time Stamping' } 'OcspSigning' { 'OCSP Signing' } 'DocumentSigning' { '1.3.6.1.4.1.311.10.3.12|Document Signing' } 'DocumentEncryption' { '1.3.6.1.4.1.311.80.1|Document Encryption' } 'DocumentSigningAdobe' { '1.2.840.113583.1.1.5|Adobe' } default { [regex]::Escape($e) } }
        if ($label -like '*|*') { $rx = $label } elseif ($e -match $script:PkiOidPattern) { $rx = $label } else { $rx = [regex]::Escape($label) }
        $found = ($t -match $rx)
        # a custom OID that OpenSSL knows by name is printed with the name: then count the entries of the extension
        if (-not $found -and $e -match $script:PkiOidPattern -and $t -match '(?m)X509v3 Extended Key Usage:[^\r\n]*\r?\n\s*([^\r\n]+)') { $found = (@($Matches[1] -split ',\s*').Count -ge @($Spec.Eku).Count) }
        if (-not $found) { [void]$problems.Add("extended key usage '$label' is missing") }
    }
    if ($Spec.Eku -contains 'OcspSigning' -and $t -notmatch 'OCSP No Check') { [void]$problems.Add('the OCSP no-check extension is missing') }
    if ($Spec.Eku -contains 'TimeStamping' -and $t -notmatch '(?s)Extended Key Usage:\s*critical') { [void]$problems.Add('the time stamping extended key usage is not critical') }
    if ([bool]$Spec['NoCrl'] -and $t -match 'CRL Distribution Points') { [void]$problems.Add('-NoCrl: the certificate still has a CRL distribution point') }
    if ([bool]$Spec['NoOcsp'] -and $t -match 'OCSP - URI') { [void]$problems.Add('-NoOcsp: the certificate still has an OCSP URL') }
    foreach ($p in $Spec.Policies) { if ($t -notmatch [regex]::Escape($p.Oid)) { [void]$problems.Add("policy $($p.Oid) ($($p.Label)) is missing") } }
    foreach ($d in $Spec.San.Dns) { if ($t -notmatch [regex]::Escape("DNS:$d")) { [void]$problems.Add("SAN DNS:$d is missing") } }
    foreach ($m in $Spec.San.Email) { if ($t -notmatch [regex]::Escape("email:$m")) { [void]$problems.Add("SAN email:$m is missing") } }
    $ipWanted = @($Spec.San.Ip).Count; $ipFound = ([regex]::Matches($t, 'IP Address:')).Count
    if ($ipFound -ne $ipWanted) { [void]$problems.Add("SAN has $ipFound IP address(es), expected $ipWanted") }
    foreach ($pair in $Spec.DnPairs) {
        if ($pair[0] -eq 'organizationIdentifier' -and $t -notmatch 'organizationIdentifier|2\.5\.4\.97') { [void]$problems.Add('the D-U-N-S (organizationIdentifier) was dropped by the issuing CA') }
    }
    try { [void](Assert-PkiSignatureDigest -Text $t -Kind 'leaf' -Id $id -ExpectPqc ($ca.Actual.Family -eq 'pqc')) } catch { [void]$problems.Add($_.Exception.Message) }
    if ($R.Actual.Family -eq 'rsa' -and $R.Actual.Bits -lt 2048) { [void]$problems.Add("RSA key below 2048 bits") }

    foreach ($tf in @($R.Key, $R.Crt, $R.Full, $R.Chain, $R.PubPem)) {
        if ($tf -and (Test-Path -LiteralPath $tf)) {
            $raw = [System.IO.File]::ReadAllBytes($tf)
            if ($raw -contains 13) { [void]$problems.Add("$([System.IO.Path]::GetFileName($tf)) has CRLF line endings (nginx / OpenSSL 3.5+ on Linux reject them)") }
            if ($raw.Length -ge 3 -and $raw[0] -eq 0xEF -and $raw[1] -eq 0xBB) { [void]$problems.Add("$([System.IO.Path]::GetFileName($tf)) starts with a BOM") }
        }
    }
    $kHead = [System.IO.File]::ReadAllText($R.Key)
    if ($kHead -notmatch '^-----BEGIN PRIVATE KEY-----\n') { [void]$problems.Add('the private key is not an unencrypted PKCS#8 PEM (-----BEGIN PRIVATE KEY-----)') }
    $kc = Invoke-OpenSSL -AllowFailure -ConfigPath (Get-PkiProviderConfigPath -Fips $fips) -Arguments (@('pkey', '-in', $R.Key, '-noout', '-check') + (Get-PkiProviderArgs -Fips $fips))
    if ($kc.ExitCode -ne 0) { [void]$problems.Add('openssl pkey -check cannot read / verify the private key') }
    if ($R.PubPem -and (Get-PkiPublicKeyPem -Path $R.PubPem -Kind pub -Fips $fips) -ne (Get-PkiPublicKeyPem -Path $R.Crt -Kind cert -Fips $fips)) { [void]$problems.Add('the .pub public key does not match the certificate') }
    if ((Get-PkiPublicKeyPem -Path $R.Crt -Kind cert -Fips $fips) -ne (Get-PkiPublicKeyPem -Path $R.Key -Kind key -Fips $fips)) { [void]$problems.Add('the private key does not match the certificate') }

    # chain
    $anchor = Get-PkiTrustAnchor
    $args = @('verify'); if ($anchor.RootIsAnchor) { $args += '-x509_strict' }
    $purpose = if ($Spec.Eku -contains 'EmailProtection') { 'smimesign' } elseif ($Spec.Eku -contains 'ServerAuth') { 'sslserver' } elseif ($Spec.Eku -contains 'ClientAuth') { 'sslclient' } elseif ($Spec.Eku -contains 'EmailProtection') { 'smimesign' } elseif ($Spec.Eku -contains 'TimeStamping') { 'timestampsign' } elseif ($Spec.Eku -contains 'OcspSigning') { 'ocsphelper' } else { $null }
    if ($purpose) { $args += @('-purpose', $purpose) }
    $args += @('-CAfile', $anchor.Anchor)
    $tmp = Join-Path $R.Dir "$($R.Stem).untrusted.tmp.pem"
    $sb = [System.Text.StringBuilder]::new()
    foreach ($anc in (@($ca) + @(Get-PkiCaAncestors -Ca $ca))) {
        if ($anc.Kind -eq 'root' -and $anchor.RootIsAnchor) { continue }
        [void]$sb.Append(([System.IO.File]::ReadAllText((Get-PkiCaPaths -Ca $anc).Crt)).TrimEnd() + "`n")
    }
    Write-Utf8NoBom -Path $tmp -Content $sb.ToString()
    try {
        $v = Invoke-OpenSSL -AllowFailure -ConfigPath (Get-PkiProviderConfigPath -Fips $fips) -Arguments ($args + @('-untrusted', $tmp) + (Get-PkiProviderArgs -Fips $fips) + @($R.Crt))
        if ($v.ExitCode -ne 0) { [void]$problems.Add("the chain does not verify: $(($v.StdErr + $v.StdOut -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 2) -join ' | ')") }
    }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }

    # the files themselves
    $cnf0 = Get-PkiProviderConfigPath -Fips $false; $prov0 = Get-PkiProviderArgs -Fips $false
    $check = [ordered]@{
        '.der'          = @('x509', '-inform', 'DER', '-noout')
        '.cer'          = @('x509', '-inform', 'DER', '-noout')
        '.pem'          = @('x509', '-noout')
        '.cert'         = @('x509', '-noout')
        '.rfc7468.pem'  = @('x509', '-noout')
        '.p7b'          = @('pkcs7', '-noout')
    }
    foreach ($ext in $check.Keys) {
        $f = Join-Path $R.Dir ($R.Stem + $ext)
        if (-not (Test-Path -LiteralPath $f)) { continue }
        $res = Invoke-OpenSSL -AllowFailure -ConfigPath $cnf0 -Arguments (@($check[$ext][0]) + @('-in', $f) + @($check[$ext] | Select-Object -Skip 1) + $prov0)
        if ($res.ExitCode -ne 0) { [void]$problems.Add("$($R.Stem + $ext) cannot be read back by OpenSSL") }
    }
    if ($R.Pfx) {
        $res = Invoke-OpenSSL -AllowFailure -ConfigPath $cnf0 -Arguments (@('pkcs12', '-in', $R.Pfx, '-noout', '-passin', 'env:PKI_PFX_PASSWORD') + $prov0)
        if ($res.ExitCode -ne 0) { [void]$problems.Add('the PFX cannot be opened with the configured password') }
    }
    $rf = Join-Path $R.Dir "$($R.Stem).rfc7468.pem"
    if (Test-Path -LiteralPath $rf) {
        $txt = [System.IO.File]::ReadAllText($rf)
        if ($txt -notmatch '^-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=]{64}\n)*[A-Za-z0-9+/=]{1,64}\n-----END CERTIFICATE-----\n$') { [void]$problems.Add('the RFC 7468 file is not in strict form') }
    }

    # policies the leaf asserts but the issuing CA does not carry
    $issuerText = Get-PkiCertText -Path (Get-PkiCaPaths -Ca $ca).Crt -Fips ([bool]$ca.Fips)
    $unsupported = @($Spec.Policies | Where-Object { $_.Label -ne 'TSA' -and $issuerText -notmatch [regex]::Escape($_.Oid) })
    if ($problems.Count -gt 0) { throw ("The leaf certificate failed validation [$id]:`n  - " + ($problems -join "`n  - ")) }
    return [ordered]@{ UnsupportedPolicies = @($unsupported | ForEach-Object { $_.Oid }) }
}

# ------------------------------------------------------------
# A SET: one certificate for EACH purpose, in one go, each in every format
# ------------------------------------------------------------
function Get-PkiLeafContactEmail {
    $c = $script:Pki
    if ($c.Bound.Contains('ContactEmail')) { return [string]$c.Bound['ContactEmail'] }
    return (Get-PkiIniValue -Ini $c.Ini -Section 'subject_ov' -Key 'ContactEmail' -Default 'info@nextmantra.com')
}

function New-PkiLeafSetSpecs {
    <#
    .SYNOPSIS
        Builds (and so validates) the specs of every purpose BEFORE anything is written.
    .PARAMETER Base
        Level, Quadrant, DnsName, IpAddress, EmailAddress, CommonName, KeyType, KeyBits, Curve, PqcAlgorithm, Hash, Days,
        Policy, Format
    .PARAMETER Purposes
        Names from $script:PkiPurposeProfiles.
    #>
    param([Parameter(Mandatory)][hashtable]$Base, [Parameter(Mandatory)][string[]]$Purposes)
    $level = ([string]$Base.Level).ToUpperInvariant()
    $org = ConvertTo-PkiAscii (Get-PkiLeafSubjectValue 'Organization' 'O' 'Agantra Inovatif OU' $level)
    $baseCn = if ($Base.ContainsKey('CommonName') -and $Base.CommonName) { [string]$Base.CommonName } else { $org }
    $webSan = Get-PkiLeafSan -Dns @($Base.DnsName | Where-Object { $_ }) -Ip @($Base.IpAddress | Where-Object { $_ }) -Email @($Base.EmailAddress | Where-Object { $_ })
    $setName = if ($webSan.Dns.Count -gt 0) { $webSan.Dns[0] } elseif ($webSan.Ip.Count -gt 0) { $webSan.Ip[0] } else { $baseCn }

    $specs = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($p in $Purposes) {
        $prof = $script:PkiPurposeProfiles[$p]
        $o = @{}
        foreach ($k in 'Level', 'Quadrant', 'KeyType', 'KeyBits', 'Curve', 'PqcAlgorithm', 'Hash', 'Days', 'Policy', 'Format', 'AddDevelopmentSan', 'CodeSigningCompany', 'NoCrl', 'NoOcsp') { if ($Base.ContainsKey($k)) { $o[$k] = $Base[$k] } }
        $o.Eku = $(if ($prof.Contains('Eku')) { @($prof['Eku']) } else { @($p) }); $o.SetMode = $true; $o.NameOverride = $setName
        if ($prof.Web) {
            $o.DnsName = @($Base.DnsName); $o.IpAddress = @($Base.IpAddress); $o.EmailAddress = @($Base.EmailAddress)
            if ($Base.ContainsKey('CommonName') -and $Base.CommonName) { $o.CommonName = [string]$Base.CommonName }
        }
        elseif ($p -eq 'EmailProtection') {
            $mail = @($Base.EmailAddress | Where-Object { $_ })
            if ($mail.Count -eq 0) { $mail = @(Get-PkiLeafContactEmail) }
            $o.EmailAddress = $mail; $o.CommonName = $mail[0]
        }
        else { $o.CommonName = "$baseCn $($prof.CnRole)" }
        [void]$specs.Add((New-PkiLeafSpec -Options $o))
    }
    return $specs
}

function Invoke-PkiLeafSet {
    <#
    .SYNOPSIS
        Creates ONE set folder (a NEW folder with date and time when it exists) with one sub-folder per purpose,
        issues, validates and documents every certificate. All or nothing: a failure removes the new set folder.
    .OUTPUTS
        @{ Folder; Items = @(@{ Spec; Result; Validation; Relative }) }
    #>
    param([Parameter(Mandatory)]$Specs, [Parameter(Mandatory)][string]$LeafRoot, [bool]$Guidance = $true)
    $tok = @{}; foreach ($k in $Specs[0].Tokens.Keys) { $tok[$k] = $Specs[0].Tokens[$k] }
    $tok.Purpose = 'all'; $tok.PurposeName = 'all'
    $setName = (Get-PkiLeafNames -Tokens $tok).Folder
    $folder = New-PkiUniqueFolder -Root $LeafRoot -Name $setName -SuffixTemplate $Specs[0].UniqueSuffix
    if ($folder.Renamed) { Write-PkiLog "The folder '$setName' exists already: a NEW folder was created: $($folder.Name)" 'WARN' }
    $items = [System.Collections.Generic.List[hashtable]]::new()
    try {
        foreach ($spec in $Specs) {
            $sub = Join-Path $folder.Path $spec.PurposeFolder
            [void][System.IO.Directory]::CreateDirectory($sub)
            $spec.OutDir = $sub
            $r = New-PkiLeafCertificate -Spec $spec
            $v = Test-PkiLeafResult -Spec $spec -R $r
            Write-PkiLog "  validated  : $($spec.PurposeFolder)" 'OK'
            foreach ($oid in $v.UnsupportedPolicies) { Write-PkiLog "  policy $oid is in the leaf but the issuing CA does not carry it" 'WARN' }
            if ($Guidance) { [void](Write-PkiLeafGuidance -Spec $spec -R $r -NoTls:(-not [bool]$script:PkiPurposeProfiles[$spec.Eku[0]].Web)) }
            $r.Files = @(@(Get-ChildItem -LiteralPath $r.Dir -File | Where-Object { $_.Name -notlike '*.tmp.*' } | ForEach-Object { $_.Name }) + @('leaf-info.json') | Sort-Object -Unique)
            [void]$items.Add(@{ Spec = $spec; Result = $r; Validation = $v; Relative = (Join-Path $folder.Name $spec.PurposeFolder) })
        }
    }
    catch {
        $err = $_
        if (Test-Path -LiteralPath $folder.Path) { [void](Unlock-PkiTree -Path @($folder.Path)); Remove-Item -LiteralPath $folder.Path -Recurse -Force -ErrorAction SilentlyContinue }
        throw $err
    }
    return @{ Folder = $folder; Items = @($items) }
}

# ------------------------------------------------------------
# Index of every leaf generated by GenerateLeafCertificate.ps1
# ------------------------------------------------------------
function Get-PkiLeafIndexPath { param([string]$Root) return (Join-Path $Root 'leaf-index.json') }

function Add-PkiLeafIndex {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][hashtable]$Spec, [Parameter(Mandatory)][hashtable]$R, [Parameter(Mandatory)][string]$FolderName, [string]$Set = '')
    $path = Get-PkiLeafIndexPath -Root $Root
    $list = @()
    if (Test-Path -LiteralPath $path) {
        try { $list = @(Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -AsHashtable) } catch { $list = @() }
    }
    $entry = [ordered]@{
        folder = $FolderName; set = $Set; path = $R.Dir; stem = $R.Stem; level = $Spec.Level; quadrant = $Spec.Quadrant; track = $Spec.Track; fips = $Spec.Fips
        issuer = $Spec.Ca.Id; issuerCommonName = (Get-PkiCaCommonName -Ca $Spec.Ca); pkiRelease = [int]$script:Pki.Release; pkiVariant = $(if ($script:Pki.NoCaRevocationInfo) { 'NoCR' } else { 'normal' }); keyAlgorithm = $R.Actual.Algorithm; signatureDigest = $R.Md; purposes = @($Spec.Eku)
        dns = @($Spec.San.Dns); ip = @($Spec.San.Ip); email = @($Spec.San.Email); developmentSan = [bool]$Spec.DevSan; revocationInfo = [ordered]@{ crlDistributionPoints = (-not [bool]$Spec['NoCrl']); ocsp = (-not [bool]$Spec['NoOcsp']) }; evSanOverride = [bool]$Spec.EvSanOverride
        days = $R.Days; notAfter = $R.NotAfter; timestampPolicyOid = [string]$Spec.TimestampPolicyOid
        sha1 = $R.Sha1; sha256 = $R.Sha256; formats = @($Spec.Formats); files = @($R.Files)
        createdUtc = [DateTime]::UtcNow.ToString('o'); generator = "GenerateLeafCertificate.ps1 $($script:PkiGeneratorVersion)"
        openssl = $script:Pki.OpenSslVersion
    }
    $list += $entry
    Write-Utf8NoBom -Path $path -Content (ConvertTo-Json -InputObject @($list) -Depth 6)
    return $entry
}

function Show-PkiLeafIndex {
    param([Parameter(Mandatory)][string]$Root)
    $path = Get-PkiLeafIndexPath -Root $Root
    if (-not (Test-Path -LiteralPath $path)) { Write-PkiLog "No leaf certificate has been generated yet ($path does not exist)."; return }
    $list = @(Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -AsHashtable)
    Write-Host ''
    Write-Host ('{0,-46} {1,-3} {2,-3} {3,-11} {4,-11} {5,-15} {6}' -f 'FOLDER', 'LVL', 'Q', 'KEY', 'EXPIRES', 'PURPOSE', 'NAMES') -ForegroundColor Cyan
    $gone = 0
    foreach ($e in $list) {
        $names = (@($e['dns']) + @($e['ip']) + @($e['email']) | Select-Object -First 3) -join ', '
        $present = Test-Path -LiteralPath (Join-Path $Root $e['folder']) -PathType Container
        $mark = if ($present) { '' } else { '   [folder no longer exists]'; $gone++ }
        if (-not $present) { $mark = '   [folder no longer exists]' }
        Write-Host ('{0,-46} {1,-3} {2,-3} {3,-11} {4,-11} {5,-15} {6}{7}' -f $e['folder'], $e['level'], "Q$($e['quadrant'])", $e['keyAlgorithm'], $e['notAfter'], ((@($e['purposes']) -join '+') -replace 'Auth', ''), $names, $mark) -ForegroundColor $(if ($present) { 'Gray' } else { 'DarkYellow' })
    }
    Write-Host ''
    Write-PkiLog "$($list.Count - $gone) leaf certificate(s) in $Root$(if ($gone -gt 0) { "  ($gone listed in the index but deleted from disk)" })" 'OK'
}

# ------------------------------------------------------------
# OpenSSL readiness: 4.x WITH the FIPS module and ML-DSA, checked BEFORE anything is generated
# ------------------------------------------------------------
function Get-PkiOpenSslReadiness {
    # Probes; never throws. Initialize-OpenSSL must have succeeded.
    $c = $script:Pki
    $r = [ordered]@{ Version = $c.OpenSslVersion; Exe = $c.OpenSslExe; MlDsa = $false; MlDsaError = ''; FipsConfig = $null; Fips = $false; FipsError = ''; MlDsaFips = $false; MlDsaFipsError = '' }
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "agantra-pki-ready-$([guid]::NewGuid().ToString('N'))"
    try {
        Ensure-PkiDirectory -Path $c.PkiRoot
        Write-Utf8NoBom -Path (Get-PkiProviderConfigPath -Fips $false) -Content (((Get-PkiProviderConfigHeader -Fips $false) -join "`n") + "`n")

        $pq = Invoke-PkiPqcSelfTest -Dir (Join-Path $tmp 'pq') -Fips $false
        $r.MlDsa = [bool]$pq.Ok; if (-not $pq.Ok) { $r.MlDsaError = "step '$($pq.Step)'" }

        $cfg = $null
        try { $cfg = Find-PkiFipsModuleConfig } catch { $r.FipsError = $_.Exception.Message.Split("`n")[0] }
        if ($null -eq $cfg) { if (-not $r.FipsError) { $r.FipsError = 'fipsmodule.cnf not found' } }
        else {
            $r.FipsConfig = $cfg
            $c.FipsConfigResolved = $cfg
            Write-Utf8NoBom -Path (Get-PkiProviderConfigPath -Fips $true) -Content (((Get-PkiProviderConfigHeader -Fips $true) -join "`n") + "`n")
            $lp = Invoke-OpenSSL -AllowFailure -ConfigPath (Get-PkiProviderConfigPath -Fips $true) -Arguments (@('list', '-providers') + (Get-PkiProviderArgs -Fips $true))
            if ($lp.ExitCode -eq 0) {
                $r.Fips = $true
                $pf = Invoke-PkiPqcSelfTest -Dir (Join-Path $tmp 'pqfips') -Fips $true
                $r.MlDsaFips = [bool]$pf.Ok; if (-not $pf.Ok) { $r.MlDsaFipsError = "step '$($pf.Step)'" }
            }
            else { $r.FipsError = ($lp.StdErr -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 1) }
        }
    }
    finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    return $r
}

function Assert-PkiLeafOpenSslReady {
    <#
    .SYNOPSIS
        Prints the OpenSSL readiness and stops when this leaf needs something that is missing.
        What is missing but not needed is a warning plus the suggestion to run Install-DevEnvironment.ps1.
    #>
    param([bool]$NeedFips = $false, [bool]$NeedPqc = $false)
    $script:PkiChecks.Clear()
    $r = Get-PkiOpenSslReadiness
    Write-Host ''
    Write-Host 'OPENSSL READINESS  (4.x with FIPS and quantum-safe support)' -ForegroundColor Cyan
    Add-PkiCheck 'OpenSSL 4.x' 'PASS' "$($r.Version.Split([char]40)[0].Trim())  [$($r.Exe)]"
    $missing = [System.Collections.Generic.List[string]]::new()
    $why = [System.Collections.Generic.List[string]]::new()
    if ($r.MlDsa) { Add-PkiCheck 'ML-DSA (default provider)' 'PASS' 'native post-quantum signatures work (Quantum quadrants 3 and 4)' }
    else { Add-PkiCheck 'ML-DSA (default provider)' $(if ($NeedPqc) { 'FAIL' } else { 'WARN' }) $r.MlDsaError; [void]$missing.Add('ML-DSA'); [void]$why.Add("ML-DSA: $($r.MlDsaError)") }
    if ($r.Fips) { Add-PkiCheck 'FIPS provider' 'PASS' "loads with $($r.FipsConfig)" }
    else { Add-PkiCheck 'FIPS provider' $(if ($NeedFips) { 'FAIL' } else { 'WARN' }) $r.FipsError; [void]$missing.Add('FIPS provider'); [void]$why.Add("FIPS provider: $($r.FipsError)") }
    if ($r.Fips) {
        if ($r.MlDsaFips) { Add-PkiCheck 'ML-DSA (FIPS provider)' 'PASS' 'ML-DSA works inside the FIPS provider (Quadrant 4)' }
        else { Add-PkiCheck 'ML-DSA (FIPS provider)' $(if ($NeedFips -and $NeedPqc) { 'FAIL' } else { 'WARN' }) $r.MlDsaFipsError; [void]$missing.Add('ML-DSA in the FIPS provider'); [void]$why.Add("ML-DSA in FIPS: $($r.MlDsaFipsError)") }
    }
    if ($missing.Count -eq 0) { return $r }

    $needed = ($NeedFips -and -not $r.Fips) -or ($NeedPqc -and -not $r.MlDsa) -or ($NeedFips -and $NeedPqc -and $r.Fips -and -not $r.MlDsaFips)
    $advice = Get-PkiOpenSslCapabilityAdvice -Missing @($missing)
    if ($needed) { throw ("This leaf certificate needs " + $(if ($NeedFips -and $NeedPqc) { 'FIPS and ML-DSA' } elseif ($NeedFips) { 'the FIPS provider' } else { 'ML-DSA' }) + " but this OpenSSL cannot provide it.`n" + ($why -join "`n") + "`n`n" + $advice) }
    Write-Host ''
    Write-PkiLog 'This certificate does not need it, but your OpenSSL is not fully equipped. Run the bootstrap to install OpenSSL with FIPS and quantum-safe support:' 'WARN'
    Write-PkiLog "  $(Get-PkiBootstrapCommand)" 'WARN'
    Write-Host ''
    return $r
}
