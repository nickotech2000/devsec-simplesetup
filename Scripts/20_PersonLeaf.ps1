# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# Module 20: leaf certificates of NATURAL PERSONS (e-mail + client authentication), modelled on the national ID card certificate:
#   Subject   serialNumber = PNOEE-<id code>   givenName   surname   CN = SURNAME,GIVEN,<id code>   C = EE      (in that order)
#   SAN       rfc822Name <id code>@eesti.ee (or the e-mail you give)
#   EKU       clientAuth + emailProtection      Key usage  digitalSignature + keyAgreement (EC) | keyEncipherment (RSA)
#   Key       ECDSA P-384 by default            Policies   the level policy + PEN + -Policy      (optional) qcStatements: QcType eSign, never QcCompliance
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
        EmailDomain = [string](& $g 'EmailDomain' 'eesti.ee')
        Days = [int](& $g 'Days' '730')
        Level = [string](& $g 'Level' 'OV')
        CommonNameFormat = [string](& $g 'CommonNameFormat' '{Surname},{Given},{IdCode}')
        Country = [string](& $g 'Country' 'EE')
        IdType = [string](& $g 'IdType' 'PNO')
        KeyType = [string](& $g 'KeyType' 'ECDSA')
        Curve = [string](& $g 'Curve' 'P-384')
    }
}

$script:PkiPersonAliases = @{
    idcode = 'IdCode'; id = 'IdCode'; personalcode = 'IdCode'; personalnumber = 'IdCode'; isikukood = 'IdCode'; nationalid = 'IdCode'; idnumber = 'IdCode'
    givenname = 'GivenName'; given = 'GivenName'; firstname = 'GivenName'; forename = 'GivenName'; gn = 'GivenName'; g = 'GivenName'; eesnimi = 'GivenName'
    surname = 'Surname'; lastname = 'Surname'; familyname = 'Surname'; sn = 'Surname'; perenimi = 'Surname'
    email = 'Email'; emailaddress = 'Email'; mail = 'Email'; rfc822 = 'Email'; rfc822name = 'Email'
    country = 'Country'; c = 'Country'; idtype = 'IdType'; type = 'IdType'
    days = 'Days'; validity = 'Days'; validitydays = 'Days'; password = 'Password'; pfxpassword = 'Password'
    level = 'Level'; keytype = 'KeyType'; keybits = 'KeyBits'; curve = 'Curve'; commonname = 'CommonName'; cn = 'CommonName'
    serialnumber = 'SerialNumber'; serial = 'SerialNumber'; name = 'Name'; foldername = 'Name'; policy = 'Policy'
}

function ConvertTo-PkiPersonRecord {
    # a row / object with any spelling of the column names -> hashtable with the canonical names
    param([Parameter(Mandatory)]$Row, [int]$Line = 0)
    $rec = [ordered]@{ _Line = $Line }
    $props = if ($Row -is [System.Collections.IDictionary]) { @($Row.Keys | ForEach-Object { [pscustomobject]@{ Name = [string]$_; Value = $Row[$_] } }) } else { @($Row.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } }) }
    foreach ($p in $props) {
        $k = ([string]$p.Name -replace '[\s_\-\.]', '').ToLowerInvariant()
        if ($k -eq '' -or $k.StartsWith('_')) { continue }
        if (-not $script:PkiPersonAliases.ContainsKey($k)) { throw "Line ${Line}: unknown column '$($p.Name)'. Known: IdCode, GivenName, Surname, Email, Country, IdType, Days, Password, Level, KeyType, KeyBits, Curve, CommonName, SerialNumber, Name, Policy." }
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
        Reads the persons of a file: CSV (comma, semicolon, tab or | ; first line = column names; lines starting with # are comments),
        JSON (an array of objects, or { "persons": [ ... ] }, or one object) or a plain text file in the CSV form.
        Returns a list of canonical records (one per person).
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Person file not found: $Path" }
    $raw = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path).Path, [System.Text.UTF8Encoding]::new($false))
    if ($raw.Length -gt 0 -and [int]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
    $out = [System.Collections.Generic.List[object]]::new()
    $t = $raw.TrimStart()
    if ($t.StartsWith('[') -or $t.StartsWith('{')) {
        $j = $raw | ConvertFrom-Json -Depth 8
        $items = if ($j -is [System.Array]) { $j } elseif ($null -ne $j.PSObject.Properties['persons']) { @($j.persons) } else { @($j) }
        $n = 0; foreach ($it in $items) { $n++; [void]$out.Add((ConvertTo-PkiPersonRecord -Row $it -Line $n)) }
        return , $out
    }
    $lines = @($raw -split "`r?`n")
    $rows = [System.Collections.Generic.List[object]]::new()
    $num = 0; $header = $null; $delim = $null
    foreach ($ln in $lines) {
        $num++
        if ($ln.Trim() -eq '' -or $ln.TrimStart().StartsWith('#')) { continue }
        if ($null -eq $delim) {
            $cand = @(',', ';', "`t", '|') | Sort-Object { -([regex]::Matches($ln, [regex]::Escape($_))).Count } | Select-Object -First 1
            $delim = $cand
            $header = @($ln.Split($delim[0]) | ForEach-Object { $_.Trim().Trim('"') })
            continue
        }
        $cells = @($ln.Split($delim[0]) | ForEach-Object { $_.Trim().Trim('"') })
        if ($cells.Count -gt $header.Count) { throw "Line ${num}: $($cells.Count) values but the header has $($header.Count) columns (a value with the separator inside?)." }
        $o = [ordered]@{}
        for ($i = 0; $i -lt $header.Count; $i++) { $o[$header[$i]] = $(if ($i -lt $cells.Count) { $cells[$i] } else { '' }) }
        [void]$rows.Add(@{ Line = $num; Row = $o })
    }
    if ($null -eq $header) { throw "The person file has no header line: $Path" }
    foreach ($r in $rows) { [void]$out.Add((ConvertTo-PkiPersonRecord -Row $r.Row -Line $r.Line)) }
    return , $out
}

function ConvertTo-PkiPersonEntry {
    <#
    .SYNOPSIS
        Validates one record and fills in the defaults. Returns the entry (canonical, checked) or throws a message naming the person / line.
    #>
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)][hashtable]$Defaults)
    $r = $Record
    $where = if ($r.Contains('_Line') -and $r['_Line']) { "Line $($r['_Line'])" } else { 'Person' }
    $get = { param($k, $d) if ($r.Contains($k) -and "$($r[$k])" -ne '') { $r[$k] } elseif ($Defaults.ContainsKey($k) -and "$($Defaults[$k])" -ne '') { $Defaults[$k] } else { $d } }
    foreach ($req in 'IdCode', 'GivenName', 'Surname') { if (-not ($r.Contains($req) -and "$($r[$req])" -ne '') -and -not ($Defaults.ContainsKey($req) -and "$($Defaults[$req])" -ne '')) { throw "${where}: $req is missing." } }
    $idCode = ([string](& $get 'IdCode' '')).Trim()
    $country = ([string](& $get 'Country' 'EE')).Trim().ToUpperInvariant()
    $idType = ([string](& $get 'IdType' 'PNO')).Trim().ToUpperInvariant()
    $given = ([string](& $get 'GivenName' '')).Trim() -replace '\s+', ' '
    $sur = ([string](& $get 'Surname' '')).Trim() -replace '\s+', ' '
    $label = "$sur $given ($idCode)"
    if ($country -notmatch '^[A-Z]{2}$') { throw "${where} [$label]: Country must be a two-letter code (EE, FI ...), got '$country'." }
    if ($idType -notin 'PNO', 'PAS', 'IDC', 'TIN') { throw "${where} [$label]: IdType must be PNO (personal number), PAS (passport), IDC (identity card) or TIN (tax number), got '$idType'." }
    if ($idCode -notmatch '^[A-Za-z0-9][A-Za-z0-9._/\-]{2,38}[A-Za-z0-9]$') { throw "${where} [$label]: IdCode '$idCode' must be 4 to 40 letters / digits (. _ / - inside)." }
    if (-not [bool]$Defaults['NoIdCheck'] -and $country -eq 'EE' -and $idType -eq 'PNO' -and -not (Test-PkiEstonianIdCode -Code $idCode)) {
        throw "${where} [$label]: '$idCode' is not a valid Estonian personal code (11 digits with check digit). Check it, or -NoIdCheck."
    }
    foreach ($nm in @(@('GivenName', $given), @('Surname', $sur))) {
        if ($nm[1].Length -lt 1 -or $nm[1].Length -gt 64) { throw "${where} [$label]: $($nm[0]) must be 1 to 64 characters." }
        if ($nm[1] -match '[\x00-\x1F\x7F]|[=+"\\<>;]') { throw "${where} [$label]: $($nm[0]) contains a character that does not belong in a name (= + `" \ < > ;)." }
    }
    $email = ([string](& $get 'Email' '')).Trim()
    if ($email -eq '') { $email = ("{0}@{1}" -f $idCode.ToLowerInvariant(), ([string]$Defaults['EmailDomain']).Trim().TrimStart('@')) }
    if ($email -notmatch '^[^@\s,;<>"]+@[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)+$') { throw "${where} [$label]: '$email' is not a valid e-mail address." }
    $level = ([string](& $get 'Level' 'OV')).ToUpperInvariant()
    if ($level -notin 'DV', 'OV', 'EV') { throw "${where} [$label]: Level must be DV, OV or EV." }
    $days = [int](& $get 'Days' 0)
    if ($days -lt 0 -or $days -gt 36500) { throw "${where} [$label]: Days must be 1 to 36500." }
    $keep = [bool]$Defaults['KeepCase']
    $upper = { param($x) if ($keep) { $x } else { $x.ToUpperInvariant() } }
    $serialNumber = ([string](& $get 'SerialNumber' '')).Trim()
    if ($serialNumber -eq '') { $serialNumber = "$idType$country-$idCode" }
    $cn = ([string](& $get 'CommonName' '')).Trim()
    if ($cn -eq '') {
        $fmt = [string]$Defaults['CommonNameFormat']
        $cn = $fmt.Replace('{Surname}', $sur).Replace('{Given}', $given).Replace('{IdCode}', $idCode).Replace('{Country}', $country).Replace('{SurnameFirst}', "$sur $given")
        $cn = & $upper $cn
    }
    if ($cn.Length -gt 64) { throw "${where} [$label]: the common name '$cn' is longer than 64 characters (X.520 limit): use a shorter -CommonNameFormat or a CommonName column." }
    $folder = ([string](& $get 'Name' '')).Trim()
    if ($folder -eq '') {
        # file-system name only: strip diacritics (Männik -> Mannik); the certificate keeps the real characters
        $fs = ("$idCode-$sur-$given").Normalize([Text.NormalizationForm]::FormD)
        $fs = (($fs.ToCharArray() | Where-Object { [Globalization.CharUnicodeInfo]::GetUnicodeCategory($_) -ne 'NonSpacingMark' }) -join '').Normalize([Text.NormalizationForm]::FormC)
        $folder = $fs -replace 'ß','ss' -replace 'ø','o' -replace 'Ø','O' -replace 'æ','ae' -replace 'Æ','AE' -replace 'đ','d' -replace 'ł','l' -replace 'Ł','L'
    }
    $keyType = [string](& $get 'KeyType' '')
    return [ordered]@{
        Line = $(if ($r.Contains('_Line')) { $r['_Line'] } else { 0 }); Label = $label
        IdCode = $idCode; Country = $country; IdType = $idType; SerialNumber = $serialNumber
        GivenName = (& $upper $given); Surname = (& $upper $sur); CommonName = $cn; Email = $email
        Level = $level; Days = $days; Password = [string](& $get 'Password' ''); Name = $folder
        KeyType = $keyType; KeyBits = [int](& $get 'KeyBits' 0); Curve = [string](& $get 'Curve' ''); Policy = @(& $get 'Policy' @())
    }
}

function Get-PkiPersonDn {
    # Same order as the national ID card:  serialNumber, givenName, surname, CN, C   (UTF-8, no transliteration: õ ä ö ü stay)
    param([Parameter(Mandatory)]$Entry)
    $pairs = [System.Collections.Generic.List[object]]::new()
    [void]$pairs.Add(@('serialNumber', $Entry.SerialNumber))
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
        The options for New-PkiLeafSpec of one person. $Common: Quadrant, Format, Hash, PqcAlgorithm, QcStatements, NonRepudiation, Policy.
    #>
    param([Parameter(Mandatory)]$Entry, [Parameter(Mandatory)][hashtable]$Common)
    $q = [int]$Common.Quadrant
    $quantum = $q -in 3, 4
    $kt = if ($Entry.KeyType) { $Entry.KeyType } elseif ($quantum) { 'MLDSA' } else { [string]$Common.KeyType }
    $family = switch ($kt.ToUpperInvariant()) { 'RSA' { 'rsa' } 'MLDSA' { 'pqc' } default { 'ecdsa' } }
    $o = @{
        Level = $Entry.Level; Quadrant = $q; Eku = @('EmailProtection', 'ClientAuth'); EmailAddress = @($Entry.Email)
        PersonDn = (Get-PkiPersonDn -Entry $Entry); CommonName = $Entry.CommonName
        KeyUsage = (Get-PkiPersonKeyUsage -Family $family -NonRepudiation:([bool]$Common.NonRepudiation))
        KeyType = $kt; KeyBits = $Entry.KeyBits; Curve = $(if ($Entry.Curve) { $Entry.Curve } elseif ($family -eq 'ecdsa') { [string]$Common.Curve } else { '' })
        Hash = $Common.Hash; PqcAlgorithm = $Common.PqcAlgorithm; Days = $(if ($Entry.Days -gt 0) { $Entry.Days } else { [int]$Common.Days })
        Policy = @(@($Common.Policy) + @($Entry.Policy) | Where-Object { $_ }); Format = $Common.Format; NameOverride = $Entry.Name
    }
    if ($quantum -and $family -ne 'pqc') { throw "$($Entry.Label): Quadrants 3 and 4 (Quantum) issue ML-DSA keys only." }
    if ([bool]$Common.QcStatements) {
        $o.ExtraConfig = @('[ person_qcs ]', 'qc1 = SEQUENCE:person_qc_type', '[ person_qc_type ]', 'oid = OID:0.4.0.1862.1.6', 'types = SEQUENCE:person_qc_types', '[ person_qc_types ]', 't1 = OID:0.4.0.1862.1.6.1', '')
        $o.ExtraExt = @('1.3.6.1.5.5.7.1.3 = ASN1:SEQUENCE:person_qcs')
    }
    return $o
}

function Test-PkiPersonResult {
    # what is specific to a person certificate, read back from the finished certificate
    param([Parameter(Mandatory)]$Entry, [Parameter(Mandatory)][hashtable]$Spec, [Parameter(Mandatory)][hashtable]$R, [switch]$QcStatements)
    $t = Get-PkiCertText -Path $R.Crt -Fips ([bool]$Spec.Fips)
    $p = [System.Collections.Generic.List[string]]::new()
    $subj = if ($t -match '(?m)^\s*Subject:\s*(?<s>.+)$') { $Matches['s'] } else { '' }
    if ($subj -notmatch '(?i)serialNumber\s*=\s*' + [regex]::Escape($Entry.SerialNumber)) { [void]$p.Add("subject serialNumber $($Entry.SerialNumber) missing") }
    if ($subj -notmatch '(?i)(givenName|GN)\s*=') { [void]$p.Add('subject givenName missing') }
    if ($subj -notmatch '(?i)(surname|SN)\s*=') { [void]$p.Add('subject surname missing') }
    if ($subj -notmatch '(?i)\bC\s*=\s*' + [regex]::Escape($Entry.Country)) { [void]$p.Add("subject C=$($Entry.Country) missing") }
    if ($t -notmatch '(?i)email:' + [regex]::Escape($Entry.Email)) { [void]$p.Add("SAN e-mail $($Entry.Email) missing") }
    if ($t -match 'DNS:|IP Address:') { [void]$p.Add('a person certificate must not carry DNS or IP names') }
    if ($t -notmatch 'TLS Web Client Authentication') { [void]$p.Add('clientAuth missing') }
    if ($t -notmatch 'E-mail Protection') { [void]$p.Add('emailProtection missing') }
    if ($t -match 'TLS Web Server Authentication') { [void]$p.Add('serverAuth must not be in a person certificate') }
    if ($QcStatements -and $t -notmatch '(?i)qcStatements|1\.3\.6\.1\.5\.5\.7\.1\.3|0\.4\.0\.1862|id-etsi-qcs-QcType|ETSI') { [void]$p.Add('qcStatements missing') }
    if ($p.Count -gt 0) { throw ("The person certificate failed validation [$($Entry.Label)]:`n  - " + ($p -join "`n  - ")) }
    return $subj
}

function Write-PkiPersonExample {
    param([Parameter(Mandatory)][string]$Path)
    $dir = Split-Path -Parent ([System.IO.Path]::GetFullPath($Path)); [void][System.IO.Directory]::CreateDirectory($dir)
    $csv = @'
# Persons for GeneratePersonLeafCertificate.ps1 -File persons.csv       (# = comment; separator , ; tab or |)
# Required: IdCode, GivenName, Surname.   Optional: Email, Country, IdType, Days, Password, Level, KeyType, KeyBits, Curve, CommonName, SerialNumber, Name, Policy
# Empty = the default (Email = <IdCode>@eesti.ee, Country EE, IdType PNO, Days 730, Level OV, ECDSA P-384, Password of -Password).
# The two people below are made up; 37605030299 is the Estonian personal code used in the public examples (its check digit is valid).
IdCode,GivenName,Surname,Email,Days,Password
37605030299,Mari-Liis,Männik,mari-liis.mannik@example.ee,,
60001019906,Jaan,Tamm,,1095,Different1!
'@
    $json = @'
{
  "persons": [
    { "IdCode": "37605030299", "GivenName": "Mari-Liis", "Surname": "Männik", "Email": "mari-liis.mannik@example.ee" },
    { "IdCode": "60001019906", "GivenName": "Jaan", "Surname": "Tamm", "Days": 1095, "Password": "Different1!" }
  ]
}
'@
    $base = if ([System.IO.Path]::GetExtension($Path)) { $Path } else { "$Path.csv" }
    Write-Utf8NoBom -Path $base -Content ($csv.Replace("`r", '') + "`n")
    $jp = [System.IO.Path]::ChangeExtension($base, '.json')
    Write-Utf8NoBom -Path $jp -Content ($json.Replace("`r", '') + "`n")
    return @($base, $jp)
}
