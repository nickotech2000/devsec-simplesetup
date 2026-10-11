# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# Module 20: leaf certificates of NATURAL PERSONS (e-mail + client authentication), modelled on the national ID card certificate:
#   Subject   serialNumber = <the ID>   givenName   surname   CN = SURNAME,GIVEN,<ID>   C = <country, default EE>      (in that order)
#             the ID can be ANY identifier: national ID, passport, driver licence, tax number, staff number ... (no country-specific check by default)
#   SAN       rfc822Name <e-mail>  +  DNS <domain of the e-mail> and DNS *.<domain>      (the DNS names are extracted from the e-mail address)
#   EKU       clientAuth + emailProtection      Key usage  digitalSignature + keyAgreement (EC) | keyEncipherment (RSA)
#   Key       Classic only (RSA / ECDSA P-384 default); Quadrant 1 non-FIPS by default, Quadrant 2 FIPS on request; level OV (EV on request, never DV)
#   Input     one JSON file with many persons ("isGenerate": true | false per person)   (optional) qcStatements: QcType eSign, never QcCompliance
# The same module serves GenerateOffice365LeafCertificate.ps1 (Profile office365: EKU emailProtection + documentEncryption + documentSigning,
# key usage digitalSignature + nonRepudiation + keyEncipherment | keyAgreement, ID optional, folder leafcerts\office365).
# Used by GeneratePersonLeafCertificate.ps1 through New-PkiLeafSpec / New-PkiLeafCertificate (module 14).
# Depends on: 00, 01, 01b, 03, 14
# ============================================================

function Test-PkiEstonianIdCode {
    # Isikukood: 11 digits, the last one is the check digit (weights 1..9,1 and, when the remainder is 10, 3..9,1,2,3).
    param([string]$Code)
    if ($Code -notmatch '^[1-8]\d{10}$') { return $false }
    $d = $Code.ToCharArray() | ForEach-Object { [int]::Parse([string]$_) }
    $w1 = 1, 2, 3, 4, 5, 6, 7, 8, 9, 1; $w2 = 3, 4, 5, 6, 7, 8, 9, 1, 2, 3
    $s = 0; for ($i = 0; $i -lt 10; $i++) { $s += $d[$i] * $w1[$i] }
    $r = $s % 11
    if ($r -eq 10) { $s = 0; for ($i = 0; $i -lt 10; $i++) { $s += $d[$i] * $w2[$i] }; $r = $s % 11; if ($r -eq 10) { $r = 0 } }
    return ($r -eq $d[10])
}

function Get-PkiPersonSettings {
    # agantra_pki.cnf [ person ]; every value can be replaced on the command line
    $c = $script:Pki
    $g = { param($k, $d) Get-PkiIniValue -Ini $c.Ini -Section 'person' -Key $k -Default $d }
    return [ordered]@{
        Days = [int](& $g 'Days' '730')
        Level = [string](& $g 'Level' 'OV')
        CommonNameFormat = [string](& $g 'CommonNameFormat' '{Surname},{Given},{IdCode}')
        SerialNumberFormat = [string](& $g 'SerialNumberFormat' '{IdCode}')
        Country = [string](& $g 'Country' 'EE')
        KeyType = [string](& $g 'KeyType' 'ECDSA')
        Curve = [string](& $g 'Curve' 'P-384')
        DnsFromEmail = ([string](& $g 'DnsFromEmail' 'true')).Trim().ToLowerInvariant() -notin 'false', 'no', '0', 'off'
    }
}

$script:PkiPersonAliases = @{
    idcode = 'IdCode'; id = 'IdCode'; idnumber = 'IdCode'; nationalid = 'IdCode'; personalcode = 'IdCode'; personalnumber = 'IdCode'; isikukood = 'IdCode'; nik = 'IdCode'
    passport = 'IdCode'; passportnumber = 'IdCode'; licence = 'IdCode'; license = 'IdCode'; drivinglicence = 'IdCode'; driverlicense = 'IdCode'; documentnumber = 'IdCode'
    givenname = 'GivenName'; given = 'GivenName'; firstname = 'GivenName'; forename = 'GivenName'; gn = 'GivenName'; g = 'GivenName'
    surname = 'Surname'; lastname = 'Surname'; familyname = 'Surname'; sn = 'Surname'
    email = 'Email'; emailaddress = 'Email'; mail = 'Email'; rfc822 = 'Email'; rfc822name = 'Email'
    country = 'Country'; c = 'Country'; idtype = 'IdType'; type = 'IdType'
    days = 'Days'; validity = 'Days'; validitydays = 'Days'; password = 'Password'; pfxpassword = 'Password'
    level = 'Level'; quadrant = 'Quadrant'; keytype = 'KeyType'; keybits = 'KeyBits'; curve = 'Curve'; commonname = 'CommonName'; cn = 'CommonName'
    serialnumber = 'SerialNumber'; serial = 'SerialNumber'; name = 'Name'; foldername = 'Name'; policy = 'Policy'
    isgenerate = 'IsGenerate'; generate = 'IsGenerate'; enabled = 'IsGenerate'; dnsfromemail = 'DnsFromEmail'
}

function ConvertTo-PkiPersonRecord {
    # a row / object with any spelling of the column names -> hashtable with the canonical names
    param([Parameter(Mandatory)]$Row, [int]$Line = 0)
    $rec = [ordered]@{ _Line = $Line }
    $props = if ($Row -is [System.Collections.IDictionary]) { @($Row.Keys | ForEach-Object { [pscustomobject]@{ Name = [string]$_; Value = $Row[$_] } }) } else { @($Row.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } }) }
    foreach ($p in $props) {
        $k = ([string]$p.Name -replace '[\s_\-\.]', '').ToLowerInvariant()
        if ($k -eq '' -or $k.StartsWith('_')) { continue }
        if (-not $script:PkiPersonAliases.ContainsKey($k)) { throw "Line ${Line}: unknown column '$($p.Name)'. Known: isGenerate, idCode, idType, serialNumber, givenName, surname, email, country, level, quadrant, days, keyType, keyBits, curve, commonName, password, name, policy, dnsFromEmail." }
        $v = $p.Value
        if ($null -eq $v) { continue }
        if ($v -is [string]) { $v = $v.Trim(); if ($v -eq '') { continue } }
        $rec[$script:PkiPersonAliases[$k]] = $v
    }
    return $rec
}

function Read-PkiPersonFile {
    <#
    .SYNOPSIS
        Reads the persons of a JSON file: { "persons": [ {..}, {..} ] }, a bare array [ {..}, {..} ] or one object.
        Keys starting with "_" (for example "_readme", "_note") are comments. CSV and other formats are not accepted.
        Returns a list of canonical records (one per person).
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Person file not found: $Path" }
    if ([System.IO.Path]::GetExtension($Path) -ne '.json') { throw "The person file must be a JSON file (.json); other formats such as CSV are not accepted: $Path. Write an example with -ExampleFile persons.json." }
    $raw = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path).Path, [System.Text.UTF8Encoding]::new($false))
    if ($raw.Length -gt 0 -and [int]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
    try { $j = $raw | ConvertFrom-Json -Depth 8 } catch { throw "The person file is not valid JSON ($Path): $($_.Exception.Message)" }
    $items = if ($j -is [System.Array]) { $j } elseif ($null -ne $j.PSObject.Properties['persons']) { @($j.persons) } else { @($j) }
    $out = [System.Collections.Generic.List[object]]::new()
    $n = 0; foreach ($it in $items) { $n++; [void]$out.Add((ConvertTo-PkiPersonRecord -Row $it -Line $n)) }
    return , $out
}

function ConvertTo-PkiBool {
    param($Value, [bool]$Default = $true)
    if ($null -eq $Value -or "$Value" -eq '') { return $Default }
    if ($Value -is [bool]) { return $Value }
    switch (([string]$Value).Trim().ToLowerInvariant()) { { $_ -in 'true', 'yes', 'y', '1', 'on' } { return $true } { $_ -in 'false', 'no', 'n', '0', 'off' } { return $false } }
    throw "'$Value' is not true or false."
}

function ConvertTo-PkiPersonEntry {
    <#
    .SYNOPSIS
        Validates one record and fills in the defaults. Returns the entry (canonical, checked) or throws a message naming the person / line.
        IsGenerate = $false is returned as an entry with Skip = $true (it is not validated further).
    #>
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)][hashtable]$Defaults)
    $r = $Record
    $where = if ($r.Contains('_Line') -and $r['_Line']) { "Person $($r['_Line'])" } else { 'Person' }
    $get = { param($k, $d) if ($r.Contains($k) -and "$($r[$k])" -ne '') { $r[$k] } elseif ($Defaults.ContainsKey($k) -and "$($Defaults[$k])" -ne '') { $Defaults[$k] } else { $d } }
    $line = if ($r.Contains('_Line')) { $r['_Line'] } else { 0 }
    try { $gen = ConvertTo-PkiBool -Value $(if ($r.Contains('IsGenerate')) { $r['IsGenerate'] } else { $null }) -Default $true } catch { throw "${where}: isGenerate: $($_.Exception.Message)" }
    if (-not $gen) {
        $nm = (@($r['GivenName'], $r['Surname']) | Where-Object { $_ }) -join ' '
        return [ordered]@{ Line = $line; Skip = $true; Label = "$nm ($($r['IdCode']))"; IdCode = [string]$r['IdCode']; SerialNumber = [string]$r['SerialNumber']; Email = [string]$r['Email'] }
    }
    $idReq = if ($Defaults.ContainsKey('IdRequired')) { [bool]$Defaults['IdRequired'] } else { $true }
    foreach ($req in @('IdCode', 'GivenName', 'Surname', 'Email') | Where-Object { $_ -ne 'IdCode' -or $idReq }) { if (-not ($r.Contains($req) -and "$($r[$req])" -ne '') -and -not ($Defaults.ContainsKey($req) -and "$($Defaults[$req])" -ne '')) { throw "${where}: $req is missing." } }
    $idCode = ([string](& $get 'IdCode' '')).Trim()
    $country = ([string](& $get 'Country' 'EE')).Trim().ToUpperInvariant()
    $idType = ([string](& $get 'IdType' '')).Trim().ToUpperInvariant()
    $given = ([string](& $get 'GivenName' '')).Trim() -replace '\s+', ' '
    $sur = ([string](& $get 'Surname' '')).Trim() -replace '\s+', ' '
    $label = if ($idCode -ne '') { "$sur $given ($idCode)" } else { "$sur $given" }
    if ($country -notmatch '^[A-Z]{2}$') { throw "${where} [$label]: Country must be a two-letter ISO code (EE, ID, FI ...), got '$country'." }
    if ($idType -ne '' -and $idType -notmatch '^[A-Z0-9]{2,6}$') { throw "${where} [$label]: IdType is a short code of 2 to 6 letters / digits (PNO, PAS, IDC, TIN, NIK, DL ...), got '$idType'." }
    if ($idCode -ne '' -and $idCode -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._/:+()\-]{0,62}[A-Za-z0-9]$') { throw "${where} [$label]: the ID '$idCode' must be 2 to 64 characters: letters, digits and . _ / : + ( ) - (not at the ends)." }
    if ([bool]$Defaults['CheckEstonianId'] -and $country -eq 'EE' -and -not (Test-PkiEstonianIdCode -Code $idCode)) {
        throw "${where} [$label]: '$idCode' is not a valid Estonian personal code (11 digits with check digit)."
    }
    foreach ($nm in @(@('GivenName', $given), @('Surname', $sur))) {
        if ($nm[1].Length -lt 1 -or $nm[1].Length -gt 64) { throw "${where} [$label]: $($nm[0]) must be 1 to 64 characters." }
        if ($nm[1] -match '[\x00-\x1F\x7F]|[=+"\\<>;]') { throw "${where} [$label]: $($nm[0]) contains a character that does not belong in a name (= + `" \ < > ;)." }
    }
    $email = ([string](& $get 'Email' '')).Trim()
    if ($email -notmatch '^[^@\s,;<>"]+@[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)+$') { throw "${where} [$label]: '$email' is not a valid e-mail address." }
    $level = ([string](& $get 'Level' 'OV')).ToUpperInvariant()
    if ($level -eq 'DV') { throw "${where} [$label]: Level DV is not used for person certificates (a person certificate carries the name of a person). Use OV (default) or EV." }
    if ($level -notin 'OV', 'EV') { throw "${where} [$label]: Level must be OV (default) or EV." }
    $q = 0; if (-not [int]::TryParse([string](& $get 'Quadrant' 1), [ref]$q) -or $q -notin 1, 2) { throw "${where} [$label]: Quadrant must be 1 (Classic non-FIPS, default) or 2 (Classic FIPS); person certificates are Classic only." }
    $days = [int](& $get 'Days' 0)
    $daysGiven = ($r.Contains('Days') -and "$($r['Days'])" -ne '') -or [bool]$Defaults['DaysGiven']
    if ($level -eq 'EV' -and -not $daysGiven) { $days = 397 }
    if ($days -lt 0 -or $days -gt 36500) { throw "${where} [$label]: Days must be 1 to 36500." }
    if ($level -eq 'EV' -and $days -gt 398) { throw "${where} [$label]: an EV certificate may not be valid longer than 398 days." }
    try { $dnsFrom = ConvertTo-PkiBool -Value $(if ($r.Contains('DnsFromEmail')) { $r['DnsFromEmail'] } else { $null }) -Default ([bool]$Defaults['DnsFromEmail']) } catch { throw "${where} [$label]: dnsFromEmail: $($_.Exception.Message)" }
    $dns = @(); if ($dnsFrom) { $dom = $email.Substring($email.LastIndexOf('@') + 1).ToLowerInvariant(); $dns = @($dom, "*.$dom") }
    $keep = [bool]$Defaults['KeepCase']
    $upper = { param($x) if ($keep) { $x } else { $x.ToUpperInvariant() } }
    $serialNumber = ([string](& $get 'SerialNumber' '')).Trim()
    if ($serialNumber -eq '') { $serialNumber = ([string]$Defaults['SerialNumberFormat']).Replace('{IdType}', $idType).Replace('{Country}', $country).Replace('{IdCode}', $idCode) }
    if ($serialNumber.Length -gt 64 -or ($serialNumber.Length -lt 1 -and $idCode -ne '')) { throw "${where} [$label]: the serial number '$serialNumber' must be 1 to 64 characters (X.520)." }
    $cn = ([string](& $get 'CommonName' '')).Trim()
    if ($cn -eq '') {
        $fmt = [string]$Defaults['CommonNameFormat']
        $cn = $fmt.Replace('{Surname}', $sur).Replace('{Given}', $given).Replace('{IdCode}', $idCode).Replace('{Country}', $country).Replace('{SurnameFirst}', "$sur $given")
        $cn = & $upper $cn
    }
    if ($cn.Length -gt 64) { throw "${where} [$label]: the common name '$cn' is longer than 64 characters (X.520 limit): use a shorter -CommonNameFormat or a commonName in the file." }
    $folder = ([string](& $get 'Name' '')).Trim()
    if ($folder -eq '') {
        # file-system name only: strip diacritics (Männik -> Mannik); the certificate keeps the real characters
        $fs = $(if ($idCode -ne '') { "$idCode-$sur-$given" } else { "$sur-$given" }).Normalize([Text.NormalizationForm]::FormD)
        $fs = (($fs.ToCharArray() | Where-Object { [Globalization.CharUnicodeInfo]::GetUnicodeCategory($_) -ne 'NonSpacingMark' }) -join '').Normalize([Text.NormalizationForm]::FormC)
        $fs = $fs -replace 'ß','ss' -replace 'ø','o' -replace 'Ø','O' -replace 'æ','ae' -replace 'Æ','AE' -replace 'đ','d' -replace 'ł','l' -replace 'Ł','L'
        $folder = ($fs -replace '[^A-Za-z0-9._-]+', '-').Trim('-', '.')
    }
    $keyType = ([string](& $get 'KeyType' '')).Trim().ToUpperInvariant()
    if ($keyType -notin '', 'RSA', 'ECDSA') { throw "${where} [$label]: KeyType must be RSA or ECDSA (person certificates are Classic only)." }
    return [ordered]@{
        Line = $line; Skip = $false; Label = $label
        IdCode = $idCode; Country = $country; IdType = $idType; SerialNumber = $serialNumber
        GivenName = (& $upper $given); Surname = (& $upper $sur); CommonName = $cn; Email = $email; Dns = @($dns)
        Level = $level; Quadrant = $q; Days = $days; Password = [string](& $get 'Password' ''); Name = $folder
        KeyType = $keyType; KeyBits = [int](& $get 'KeyBits' 0); Curve = [string](& $get 'Curve' ''); Policy = @(& $get 'Policy' @())
    }
}

function Get-PkiPersonDn {
    # Same order as the national ID card:  serialNumber, givenName, surname, CN, C   (UTF-8, no transliteration: õ ä ö ü stay)
    param([Parameter(Mandatory)]$Entry)
    $pairs = [System.Collections.Generic.List[object]]::new()
    if ($Entry.SerialNumber) { [void]$pairs.Add(@('serialNumber', $Entry.SerialNumber)) }
    [void]$pairs.Add(@('givenName', $Entry.GivenName))
    [void]$pairs.Add(@('surname', $Entry.Surname))
    [void]$pairs.Add(@('CN', $Entry.CommonName))
    [void]$pairs.Add(@('C', $Entry.Country))
    return , $pairs
}

function Get-PkiPersonKeyUsage {
    param([string]$Family, [switch]$NonRepudiation)
    $ku = [System.Collections.Generic.List[string]]::new()
    [void]$ku.Add('digitalSignature')
    if ($NonRepudiation) { [void]$ku.Add('nonRepudiation') }
    switch ($Family) { 'ecdsa' { [void]$ku.Add('keyAgreement') } 'rsa' { [void]$ku.Add('keyEncipherment') } }
    return 'critical,' + ($ku -join ',')
}

function New-PkiPersonOptions {
    <#
    .SYNOPSIS
        The options for New-PkiLeafSpec of one person. $Common: Format, Hash, QcStatements, NonRepudiation, Policy, KeyType, Curve, Days.
    #>
    param([Parameter(Mandatory)]$Entry, [Parameter(Mandatory)][hashtable]$Common)
    $kt = if ($Entry.KeyType) { $Entry.KeyType } else { [string]$Common.KeyType }
    $family = if ($kt.ToUpperInvariant() -eq 'RSA') { 'rsa' } else { 'ecdsa' }
    $office = ($Common.ContainsKey('Profile') -and [string]$Common['Profile'] -eq 'office365')
    $o = @{
        Level = $Entry.Level; Quadrant = [int]$Entry.Quadrant; Eku = $(if ($office) { @('EmailProtection', 'DocumentEncryption') + $(if (-not $Common.ContainsKey('DocumentSigning') -or [bool]$Common['DocumentSigning']) { @('DocumentSigning') } else { @() }) } else { @('EmailProtection', 'ClientAuth') }); EmailAddress = @($Entry.Email); DnsName = @($Entry.Dns)
        PersonDn = (Get-PkiPersonDn -Entry $Entry); CommonName = $Entry.CommonName
        KeyUsage = (Get-PkiPersonKeyUsage -Family $family -NonRepudiation:([bool]$Common.NonRepudiation -or $office))
        KeyType = $kt; KeyBits = $(if ($family -eq 'rsa') { $Entry.KeyBits } else { 0 }); Curve = $(if ($Entry.Curve) { $Entry.Curve } elseif ($family -eq 'ecdsa') { [string]$Common.Curve } else { '' })
        Hash = $Common.Hash; Days = $(if ($Entry.Days -gt 0) { $Entry.Days } else { [int]$Common.Days })
        Policy = @(@($Common.Policy) + @($Entry.Policy) | Where-Object { $_ }); Format = $Common.Format; NameOverride = $Entry.Name
    }
    if ([bool]$Common.QcStatements) {
        $o.ExtraConfig = @('[ person_qcs ]', 'qc1 = SEQUENCE:person_qc_type', '[ person_qc_type ]', 'oid = OID:0.4.0.1862.1.6', 'types = SEQUENCE:person_qc_types', '[ person_qc_types ]', 't1 = OID:0.4.0.1862.1.6.1', '')
        $o.ExtraExt = @('1.3.6.1.5.5.7.1.3 = ASN1:SEQUENCE:person_qcs')
    }
    return $o
}

function Test-PkiPersonResult {
    # what is specific to a person certificate, read back from the finished certificate
    param([Parameter(Mandatory)]$Entry, [Parameter(Mandatory)][hashtable]$Spec, [Parameter(Mandatory)][hashtable]$R, [switch]$QcStatements, [string]$Profile = 'person', [bool]$DocumentSigning = $true)
    $t = Get-PkiCertText -Path $R.Crt -Fips ([bool]$Spec.Fips)
    $p = [System.Collections.Generic.List[string]]::new()
    $subj = if ($t -match '(?m)^\s*Subject:\s*(?<s>.+)$') { $Matches['s'] } else { '' }
    if ($Entry.SerialNumber -and $subj -notmatch '(?i)serialNumber\s*=\s*' + [regex]::Escape($Entry.SerialNumber)) { [void]$p.Add("subject serialNumber $($Entry.SerialNumber) missing") }
    if ($subj -notmatch '(?i)(givenName|GN)\s*=') { [void]$p.Add('subject givenName missing') }
    if ($subj -notmatch '(?i)(surname|SN)\s*=') { [void]$p.Add('subject surname missing') }
    if ($subj -notmatch '(?i)\bC\s*=\s*' + [regex]::Escape($Entry.Country)) { [void]$p.Add("subject C=$($Entry.Country) missing") }
    if ($t -notmatch '(?i)email:' + [regex]::Escape($Entry.Email)) { [void]$p.Add("SAN e-mail $($Entry.Email) missing") }
    foreach ($d in @($Entry.Dns)) { if ($t -notmatch '(?i)DNS:' + [regex]::Escape($d) + '(,|\s|$)') { [void]$p.Add("SAN DNS:$d missing") } }
    if (@($Entry.Dns).Count -eq 0 -and $t -match 'DNS:') { [void]$p.Add('unexpected DNS name in the SAN') }
    if ($t -match 'IP Address:') { [void]$p.Add('a person certificate must not carry an IP address') }
    if ($Profile -ne 'office365' -and $t -notmatch 'TLS Web Client Authentication') { [void]$p.Add('clientAuth missing') }
    if ($Profile -eq 'office365') {
        if ($t -notmatch '1\.3\.6\.1\.4\.1\.311\.80\.1|Document Encryption') { [void]$p.Add('documentEncryption (1.3.6.1.4.1.311.80.1) missing') }
        if ($DocumentSigning -and $t -notmatch '1\.3\.6\.1\.4\.1\.311\.10\.3\.12|Document Signing') { [void]$p.Add('documentSigning (1.3.6.1.4.1.311.10.3.12) missing') }
        if ($t -notmatch '(?s)Key Usage:.*?Digital Signature') { [void]$p.Add('keyUsage digitalSignature missing') }
        if ($t -notmatch '(?s)Key Usage:[^\n]*\n[^\n]*(Non Repudiation|Content Commitment)') { [void]$p.Add('keyUsage nonRepudiation (contentCommitment) missing') }
    }
    if ($t -notmatch 'E-mail Protection') { [void]$p.Add('emailProtection missing') }
    if ($t -match 'TLS Web Server Authentication') { [void]$p.Add('serverAuth must not be in a person certificate') }
    if ($QcStatements -and $t -notmatch '(?i)qcStatements|1\.3\.6\.1\.5\.5\.7\.1\.3|0\.4\.0\.1862|id-etsi-qcs-QcType|ETSI') { [void]$p.Add('qcStatements missing') }
    if ($p.Count -gt 0) { throw ("The person certificate failed validation [$($Entry.Label)]:`n  - " + ($p -join "`n  - ")) }
    return $subj
}

function Write-PkiPersonExample {
    # JSON only. Five made-up people from different countries; "isGenerate" switches a person on or off.
    param([Parameter(Mandatory)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    if ([System.IO.Path]::GetExtension($full) -ne '.json') { $full = [System.IO.Path]::ChangeExtension($full, '.json') }
    [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $full))
    $json = @'
{
  "_readme": [
    "Persons for GeneratePersonLeafCertificate.ps1 -File persons.json   (JSON only; keys that start with _ are comments).",
    "isGenerate: true = issue the certificate, false = skip this person (default true).",
    "idCode: ANY identifier - national ID, passport, driver licence, tax number ...   idType: free short code (PNO PAS IDC TIN NIK DL ...), optional.",
    "serialNumber: goes into the subject serialNumber; here it is the same as idCode. Empty = idCode (see -SerialNumberFormat).",
    "email: becomes the SAN rfc822Name; the DNS names are taken from it (nicko@nextmantra.com -> DNS:nextmantra.com and DNS:*.nextmantra.com).",
    "country: ISO 3166 two letters, default EE.   level: OV (default) or EV, never DV.   quadrant: 1 = Classic non-FIPS (default), 2 = Classic FIPS.",
    "Optional per person: days, keyType (RSA|ECDSA), keyBits, curve, commonName, password, name (folder), policy, dnsFromEmail.",
    "All five people below are made up."
  ],
  "persons": [
    { "isGenerate": true,  "idCode": "3674010101900001", "idType": "NIK", "serialNumber": "3674010101900001", "givenName": "Budi",      "surname": "Santoso",  "email": "budi.santoso@example.co.id", "country": "ID" },
    { "isGenerate": true,  "idCode": "37605030299",      "idType": "PNO", "serialNumber": "37605030299",      "givenName": "Mari-Liis", "surname": "Männik",   "email": "mari-liis.mannik@example.ee" },
    { "isGenerate": false, "idCode": "AB1234567",        "idType": "DL",  "serialNumber": "AB1234567",        "givenName": "Jaan",      "surname": "Tamm",     "email": "jaan.tamm@example.ee", "country": "EE", "days": 1095 },
    { "isGenerate": true,  "idCode": "XP1234567",        "idType": "PAS", "serialNumber": "XP1234567",        "givenName": "Anna",      "surname": "Virtanen", "email": "anna.virtanen@example.fi", "country": "FI", "level": "EV" },
    { "isGenerate": false, "idCode": "D1234567890",      "idType": "DL",  "serialNumber": "D1234567890",      "givenName": "John",      "surname": "Smith",    "email": "john.smith@example.com", "country": "US", "quadrant": 2 }
  ]
}
'@
    Write-Utf8NoBom -Path $full -Content ($json.Replace("`r", '') + "`n")
    return @($full)
}

function Get-PkiOfficeSettings {
    # agantra_pki.cnf [ office365 ]; every value can be replaced on the command line / in the JSON file
    $c = $script:Pki
    $g = { param($k, $d) Get-PkiIniValue -Ini $c.Ini -Section 'office365' -Key $k -Default $d }
    return [ordered]@{
        Days = [int](& $g 'Days' '730')
        Level = [string](& $g 'Level' 'OV')
        CommonNameFormat = [string](& $g 'CommonNameFormat' '{Given} {Surname}')
        SerialNumberFormat = [string](& $g 'SerialNumberFormat' '{IdCode}')
        Country = [string](& $g 'Country' 'EE')
        KeyType = [string](& $g 'KeyType' 'RSA')
        KeyBits = [int](& $g 'KeyBits' '4096')
        Curve = [string](& $g 'Curve' 'P-384')
        DnsFromEmail = ([string](& $g 'DnsFromEmail' 'false')).Trim().ToLowerInvariant() -in 'true', 'yes', '1', 'on'
        KeepCase = ([string](& $g 'KeepCase' 'true')).Trim().ToLowerInvariant() -notin 'false', 'no', '0', 'off'
    }
}

function Write-PkiOfficeExample {
    # JSON only. Five made-up people; "isGenerate" switches a person on or off.
    param([Parameter(Mandatory)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    if ([System.IO.Path]::GetExtension($full) -ne '.json') { $full = [System.IO.Path]::ChangeExtension($full, '.json') }
    [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $full))
    $json = @'
{
  "_readme": [
    "Signers for GenerateOffice365LeafCertificate.ps1 -File office365.json   (JSON only; keys that start with _ are comments).",
    "isGenerate: true = issue the certificate, false = skip this person (default true).",
    "email: the SAN rfc822Name (the address of the Microsoft 365 account). givenName + surname: the name Office shows next to the signature (CN = 'Given Surname').",
    "idCode / serialNumber: optional. Any identifier (staff number, national ID, passport ...); it goes into the subject serialNumber.",
    "country: ISO 3166 two letters, default EE.   level: OV (default) or EV, never DV.   quadrant: 1 = Classic non-FIPS (default), 2 = Classic FIPS.",
    "Optional per person: days, keyType (RSA|ECDSA), keyBits, curve, commonName, password, name (folder), policy, dnsFromEmail.",
    "Office needs RSA >= 2048 (RSA 4096 is the default here) or ECDSA >= P-256, and SHA-2. ECDSA cannot do key encipherment: use RSA when the certificate must also ENCRYPT documents.",
    "All five people below are made up."
  ],
  "persons": [
    { "isGenerate": true,  "givenName": "Budi",      "surname": "Santoso",  "email": "budi.santoso@example.co.id", "country": "ID", "idCode": "STAFF-0001", "serialNumber": "STAFF-0001" },
    { "isGenerate": true,  "givenName": "Mari-Liis", "surname": "Männik",   "email": "mari-liis.mannik@example.ee" },
    { "isGenerate": false, "givenName": "Jaan",      "surname": "Tamm",     "email": "jaan.tamm@example.ee", "days": 1095 },
    { "isGenerate": true,  "givenName": "Anna",      "surname": "Virtanen", "email": "anna.virtanen@example.fi", "country": "FI", "level": "EV", "keyType": "ECDSA" },
    { "isGenerate": false, "givenName": "John",      "surname": "Smith",    "email": "john.smith@example.com", "country": "US", "quadrant": 2 }
  ]
}
'@
    Write-Utf8NoBom -Path $full -Content ($json.Replace("`r", '') + "`n")
    return @($full)
}
