# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Makes the configuration file  <short>_pki.cnf  of ANOTHER company's PKI, from the template agantra_pki.cnf.
    The new PKI has the same hierarchy as the Agantra PKI (Enterprise Root, Track Roots, Quadrant Roots, intermediates).
    Run  .\New-PkiConfig.ps1 -Help  for everything.
.EXAMPLE
    .\New-PkiConfig.ps1            (asks for every value)
.EXAMPLE
    .\New-PkiConfig.ps1 -CompanyName 'Raksaka Teknologi Indonesia' -ContactName 'Budi Santoso' -ContactEmail budi@raksaka.co.id -CompanyId 1234567890 `
        -Address 'Jl. Sudirman 1' -City Jakarta -Province 'DKI Jakarta' -Country ID -Website https://www.raksaka.co.id
#>
[CmdletBinding()]
param(
    [string]$CompanyName,
    [string]$ShortName,
    [string]$ContactName,
    [string]$ContactEmail,
    [string]$CompanyId,
    [string]$Address,
    [string]$City,
    [string]$Province,
    [string]$Country,
    [string]$PostalCode,
    [string]$Website,
    [string]$Phone,
    [string]$IanaPen,
    # ---- EV certificate data (optional; the defaults come from the values above) ----
    [string]$BusinessCategory = 'Private Organization',
    [string]$JurisdictionCountry,
    [string]$JurisdictionState,
    [string]$JurisdictionLocality,
    [string]$Duns,
    # the host names of the CRL / OCSP / CA-issuer URLs of this PKI: <name>.internal  (default: <short name>.internal)
    [string]$InternalDomain,
    [string]$OutDirectory,
    [switch]$Force,
    [switch]$NonInteractive,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$script:Root = $PSScriptRoot

function Show-NewConfigHelp {
    @'
============================================================
 New-PkiConfig.ps1 - make the configuration of another company's PKI
 Version 5.3.6
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : docs\pki_setup-MANUAL.txt (section PKI PROFILES)   Design : docs\PKI-Design-with-FIPS-and-PQC.txt

WHAT IT DOES
  Asks for the data of a company and writes  <short>_pki.cnf  next to the scripts, made from the template agantra_pki.cnf.
  The file is a PKI PROFILE: with  -Pki <short>  every script uses it. The new PKI has exactly the same structure as the Agantra PKI:
  Enterprise Root, Classic / Quantum Track Roots, Quadrant Roots (Q1 non-FIPS, Q2 FIPS), DV / OV / EV intermediates, CRL, OCSP, time
  stamping. Only the company data differ (names of the CAs, subject, policy URLs, domain names).
  SHORT NAME = the first real word of the company name, plain ASCII, small letters: "Raksaka Teknologi Indonesia" and "PT Raksaka Teknologi
  Indonesia" -> raksaka -> raksaka_pki.cnf;  "PT Bumi Daya Sakti" -> bumi;  "Tecooli Service OU" -> tecooli;  ArgÜwilis -> arguwilis.
  Words like PT, CV, Tbk, SDN, BHD, LLC, GmbH in front are skipped. The same short name of another company gets a number: tecooli002, tecooli003 ...
  The PKI of a profile is built in  .\pki\pki-<short>-01 , pki-<short>-02 ...  (the Agantra PKI: pki-default-01 ...).

USAGE
  .\New-PkiConfig.ps1                      asks for every value (Enter = the shown default; optional values may stay empty)
  .\New-PkiConfig.ps1 -CompanyName 'Raksaka Teknologi Indonesia' -ContactName 'Budi Santoso' -ContactEmail budi@raksaka.co.id `
                      -CompanyId 1234567890 -Address 'Jl. Sudirman 1' -City Jakarta -Province 'DKI Jakarta' -Country ID `
                      -Website https://www.raksaka.co.id
  Then:   .\pki_setup.ps1 -Pki raksaka -InstallTrust          build and install the PKI of that company
          .\pki_setup.ps1 -ListPki                            all PKIs and their folders

PARAMETERS  (* = required; the others are optional)
  -CompanyName *        full legal name                       -ShortName      default: first real word, plain ASCII, small letters (a-z, 0-9); numbered when taken
  -ContactName *        person in charge (full name)          -ContactEmail * e-mail of that person
  -CompanyId *          company number / registration ID (EV serialNumber)
  -Address *            street and number                     -City *         -Province *     (state)
  -Country *            two letters (ISO 3166), e.g. ID, EE, DE
  -PostalCode           optional                              -Phone          optional, e.g. +62 21 5551234
  -Website *            domain only: https:// and http:// are removed (www.example.com, api.example.com)
  -IanaPen              optional IANA Private Enterprise Number (company policy OIDs 1.3.6.1.4.1.<PEN>.1 ...)
  EV data:  -BusinessCategory (default Private Organization)  -JurisdictionCountry (default: Country)
            -JurisdictionState (default: Province)  -JurisdictionLocality (default: City)  -Duns (organizationIdentifier DUNS+number)
  -InternalDomain       base of the CRL / OCSP / CA-issuer host names: crl.<it> , ocsp.<it> , crt.<it>   Default: <short>.internal
  -OutDirectory         where to write the file. Default: next to the scripts.
  -Force                replace an existing file (otherwise the script stops).
  -NonInteractive       never ask: a missing required value is an error.
  -Help                 this text.

AFTER IT: open the file, read the comments, change what you want (validity, policies, SAN lists ...). Precedence stays:
  command line > file > built-in default.
RUNS ON: Windows 11 24H2+, Windows Server 2025 / 2022, Ubuntu 24+ / RHEL family 10+ / SUSE 15+ with PowerShell 7.
============================================================
'@ | Write-Host
}

if ($Help) { Show-NewConfigHelp; exit 0 }

$__pf = Join-Path $PSScriptRoot 'scripts/00a_Platform.ps1'
if (-not (Test-Path -LiteralPath $__pf)) { [Console]::Error.WriteLine('[ERROR] scripts/00a_Platform.ps1 is missing: the operating system cannot be checked. Nothing was done.'); exit 5 }
. $__pf; Assert-PkiPlatform
. (Join-Path $PSScriptRoot 'scripts/00b_Profiles.ps1')

function ConvertTo-PlainAscii {
    # ArgÜwilis -> Arguwilis : accents and umlauts removed, a few special letters mapped; anything else non-ASCII is dropped
    param([string]$Text)
    $map = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
    foreach ($p in 'ß=ss', 'ø=o', 'Ø=O', 'æ=ae', 'Æ=AE', 'œ=oe', 'Œ=OE', 'đ=d', 'Đ=D', 'ł=l', 'Ł=L', 'ð=d', 'þ=th', 'ı=i') { $kv = $p.Split('=', 2); $map[$kv[0]] = $kv[1] }
    $sb = [System.Text.StringBuilder]::new()
    foreach ($ch in $Text.ToCharArray()) { if ($map.ContainsKey([string]$ch)) { [void]$sb.Append($map[[string]$ch]) } else { [void]$sb.Append($ch) } }
    $n = $sb.ToString().Normalize([System.Text.NormalizationForm]::FormD)
    $o = [System.Text.StringBuilder]::new()
    foreach ($ch in $n.ToCharArray()) { if ([System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($ch) -ne [System.Globalization.UnicodeCategory]::NonSpacingMark -and [int]$ch -lt 128) { [void]$o.Append($ch) } }
    return $o.ToString()
}

function Get-PkiShortBase {
    # The first REAL word of the company name, plain ASCII, small letters: "PT Raksaka Teknologi Indonesia" -> raksaka, "PT Bumi Daya Sakti" -> bumi,
    # "Tecooli Service OU" -> tecooli, "ArgÜwilis" -> arguwilis. Legal-form words in front (PT, CV, Tbk, SDN, BHD, LLC, GmbH ...) are skipped.
    param([string]$Company)
    $legal = 'pt', 'cv', 'ud', 'pd', 'tbk', 'sdn', 'bhd', 'pte', 'ltd', 'llc', 'llp', 'lp', 'inc', 'corp', 'co', 'gmbh', 'ag', 'kg', 'ug', 'ou', 'oy', 'ab', 'as', 'sa', 'sas', 'sarl', 'srl', 'spa', 'bv', 'nv', 'plc', 'the', 'pty', 'limited', 'company'
    $words = @($Company -split '\s+' | Where-Object { $_ })
    foreach ($w in $words) {
        $plain = (ConvertTo-PlainAscii $w).ToLowerInvariant() -replace '[^a-z0-9]', ''
        if ($plain -eq '') { continue }
        if ($legal -contains $plain -and $words.Count -gt 1) { continue }
        if ($plain -match '^[0-9]') { $plain = "pki$plain" }
        return $plain
    }
    return ''
}

function Read-Value {
    param([string]$Prompt, [string]$Current, [string]$Default = '', [switch]$Required)
    if (-not [string]::IsNullOrWhiteSpace($Current)) { return $Current.Trim() }
    if ($NonInteractive -or [Console]::IsInputRedirected) {
        if ($Required -and $Default -eq '') { throw "Missing value: $Prompt (give the parameter, or run without -NonInteractive)." }
        return $Default
    }
    while ($true) {
        $d = if ($Default) { " [$Default]" } elseif (-not $Required) { ' (optional)' } else { '' }
        $v = (Read-Host "$Prompt$d").Trim()
        if ($v -eq '') { $v = $Default }
        if ($v -eq '' -and $Required) { Write-Host '  This value is required.' -ForegroundColor Yellow; continue }
        return $v
    }
}

function ConvertTo-Domain {
    param([string]$Text)
    $t = $Text.Trim() -replace '^(?i)https?://', ''
    $t = ($t -split '[/?#]')[0]
    $t = ($t -split ':')[0].Trim().TrimEnd('.').ToLowerInvariant()
    return $t
}

try {
    Write-Host '============================================================'
    Write-Host 'Author : Nicko Satria Utama'
    Write-Host 'Company: Agantra Inovatif OÜ (NextMantra)'
    Write-Host 'Email  : nicko@nextmantra.com'
    Write-Host '============================================================'

    $template = Join-Path $script:Root 'agantra_pki.cnf'
    if (-not (Test-Path -LiteralPath $template)) { throw "The template agantra_pki.cnf is missing next to this script ($script:Root)." }

    Write-Host ''
    Write-Host 'New PKI configuration (the same PKI structure as Agantra, with the data of another company)' -ForegroundColor Cyan
    $company = Read-Value 'Company name (full legal name)' $CompanyName -Required
    $firstWord = Get-PkiShortBase -Company $company
    # a short name that is taken by ANOTHER company gets a number: tecooli, tecooli002, tecooli003 ... (only when the name was not given with -ShortName)
    $autoShort = $firstWord
    if (-not $ShortName -and $firstWord -ne '') {
        $n = 1
        while ((Test-Path -LiteralPath (Join-Path $(if ($OutDirectory) { $OutDirectory } else { $script:Root }) "${autoShort}_pki.cnf")) -and -not $Force) { $n++; $autoShort = '{0}{1:000}' -f $firstWord, $n }
        if ($autoShort -ne $firstWord) { Write-Host "[INFO] ${firstWord}_pki.cnf exists already (another company): the short name $autoShort is used." -ForegroundColor Cyan }
    }
    $short = if ($ShortName) { $ShortName.Trim().ToLowerInvariant() } else { Read-Value 'Short name (first real word, small letters; PT / CV / SDN BHD ... are skipped)' '' $autoShort -Required }
    if ($short -notmatch '^[a-z][a-z0-9]{1,23}$') { throw "Short name '$short': use 2-24 characters, small letters and digits, starting with a letter." }
    if ($short -in 'default', 'nocr', 'all') { throw "Short name '$short' is reserved (it would clash with the folder names)." }
    if ($short -eq 'agantra') { throw "The short name 'agantra' is the default PKI (agantra_pki.cnf): choose the short name of the other company." }

    $outDir = if ($OutDirectory) { $OutDirectory } else { $script:Root }
    $outFile = Join-Path $outDir "${short}_pki.cnf"
    if ((Test-Path -LiteralPath $outFile) -and -not $Force) { throw "$outFile already exists. Nothing was changed. Use -Force to replace it, or another -ShortName." }

    $cName = Read-Value 'Person in charge (full name)' $ContactName -Required
    $cMail = Read-Value 'Contact e-mail' $ContactEmail -Required
    if ($cMail -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { throw "Contact e-mail '$cMail' is not an e-mail address." }
    $cid = Read-Value 'Company number / ID (registration number)' $CompanyId -Required
    $street = Read-Value 'Address (street, number)' $Address -Required
    $city = Read-Value 'City' $City -Required
    $prov = Read-Value 'Province / state' $Province -Required
    $cc = (Read-Value 'Country (2 letters, ISO 3166)' $Country -Required).ToUpperInvariant()
    if ($cc -notmatch '^[A-Z]{2}$') { throw "Country '$cc': two letters are needed (ID, EE, DE ...)." }
    $zip = Read-Value 'Postal code' $PostalCode
    $site = ConvertTo-Domain (Read-Value 'Company website (domain only, e.g. www.example.com)' $Website -Required)
    if ($site -notmatch '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$') { throw "Website '$site' is not a domain name." }
    $tel = Read-Value 'Phone number' $Phone
    $pen = Read-Value 'IANA Private Enterprise Number (PEN)' $IanaPen
    if ($pen -and $pen -notmatch '^[1-9]\d{0,9}$') { throw "IANA PEN '$pen' must be a number." }
    $bizCat = Read-Value 'EV: business category' $BusinessCategory 'Private Organization'
    $jCc = (Read-Value 'EV: jurisdiction country' $JurisdictionCountry $cc).ToUpperInvariant()
    $jSt = Read-Value 'EV: jurisdiction state / province' $JurisdictionState $prov
    $jLo = Read-Value 'EV: jurisdiction locality / city' $JurisdictionLocality $city
    $duns = Read-Value 'EV: DUNS number' $Duns
    $internal = (Read-Value 'Internal domain of the CRL / OCSP / CA-issuer hosts' $InternalDomain "$short.internal").ToLowerInvariant()
    if ($internal -notmatch '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$') { throw "Internal domain '$internal' is not valid." }

    $prefix = (Get-Culture).TextInfo.ToTitleCase($short)      # CA names: Raksaka, Tecooli002 (plain ASCII; the same as the short name)
    if ($prefix -eq '') { $prefix = $short.Substring(0, 1).ToUpperInvariant() + $short.Substring(1) }
    $siteBare = $site -replace '^www\.', ''
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm'

    # ---- values per section/key ----
    $set = @{
        'pki_settings' = [ordered]@{
            Organization = $company; Country = $cc; State = $prov; Locality = $city; Street = $street; PostalCode = $zip
            CaSerialNumber = $cid; BusinessCategory = $bizCat; JurisdictionCountry = $jCc; JurisdictionState = $jSt; JurisdictionLocality = $jLo
            CaContactName = $cName; CaContactEmail = $cMail; CaContactPhone = $tel
            CpsUrl = "https://$site/security/certs"; CpsUrlEv = "https://$site/security/certs/ev-cps.pdf"
        }
        'ca_names' = [ordered]@{ Prefix = $prefix; SlugPrefix = $short }
        'iana_pen' = [ordered]@{ PEN = $pen }
        'subject_ov' = [ordered]@{ O = $company; L = $city; ST = $prov; C = $cc; street = $street; postalCode = $zip; ContactPhone = $tel; ContactName = $cName; ContactEmail = $cMail }
        'subject_ev' = [ordered]@{ serialNumber = $cid; businessCategory = $bizCat; jurisdictionCountryName = $jCc; jurisdictionStateOrProvinceName = $jSt; jurisdictionLocalityName = $jLo; DUNS = $duns }
        'person'     = [ordered]@{ Country = $cc }
        'office365'  = [ordered]@{ Country = $cc }
    }
    # sections that are written new (the list of names)
    $sanDns = @($siteBare); if ($site -ne $siteBare) { $sanDns += $site } else { $sanDns += "www.$siteBare" }; $sanDns += 'localhost'
    $leafSan = [System.Collections.Generic.List[string]]::new()
    $i = 0; foreach ($d in $sanDns) { $i++; [void]$leafSan.Add("DNS.$i = $d") }
    [void]$leafSan.Add(''); [void]$leafSan.Add('IP.1 = 127.0.0.1'); [void]$leafSan.Add(''); [void]$leafSan.Add("email.1 = $cMail")
    $dev = [System.Collections.Generic.List[string]]::new()
    $devDns = @($siteBare, "www.$siteBare", "*.$siteBare", 'localhost', 'local.dev',
        "$short.internal", "*.$short.internal", "$short.developer", "*.$short.developer", "$short.api", "*.$short.api", "$short.ldap", "*.$short.ldap")
    if ($internal -ne "$short.internal") { $devDns += @($internal, "*.$internal") }
    $i = 0; foreach ($d in ($devDns | Select-Object -Unique)) { $i++; [void]$dev.Add(('DNS.{0,-2} = {1}' -f $i, $d)) }
    foreach ($l in '', 'IP.1 = 127.0.0.1', 'IP.2 = ::1', 'IPRange.1 = 192.168.0.1-192.168.0.200', 'IPRange.2 = 172.16.0.1-172.16.0.200', 'IPRange.3 = 192.168.1.1-192.168.1.100', 'IPRange.4 = 192.168.2.1-192.168.2.100', '', "email.1 = $cMail") { [void]$dev.Add($l) }
    $regen = @{ 'leaf_san' = $leafSan; 'development_san' = $dev }

    # ---- header ----
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($l in @(
        '# ============================================================',
        "# $company PKI configuration  (${short}_pki.cnf)",
        '#',
        "# Company : $company",
        "# Contact : $cName <$cMail>",
        "# Website : $site",
        "# Made by : New-PkiConfig.ps1 (5.3.6) on $stamp, from the template agantra_pki.cnf",
        '# Author  : Nicko Satria Utama',
        '# Company : Agantra Inovatif OÜ (NextMantra)',
        '# Email   : nicko@nextmantra.com',
        '#',
        "# This is the PKI PROFILE '$short'. Use it with  -Pki $short  on pki_setup.ps1, the leaf generators, SignCsr, SignExternalCa,",
        "# PkiTransport, pki_remove ... Its PKI is built in .\pki\pki-$short-01, pki-$short-02 ...  Same structure as the Agantra PKI.",
        '# Precedence: command line > this file > built-in default. The explanations of every section follow (copied from the template).',
        '# ============================================================')) { [void]$out.Add($l) }

    # ---- body: the template without its first comment block ----
    $lines = [System.IO.File]::ReadAllLines($template)
    $start = 0; $seen = 0
    for ($k = 0; $k -lt $lines.Count; $k++) { if ($lines[$k] -match '^# =====') { $seen++; if ($seen -eq 2) { $start = $k + 1; break } } }
    $sec = ''; $emitted = @{}; $written = @{}
    $commentMap = @(
        @('agantra_pki.cnf', "${short}_pki.cnf"), @('Agantra Inovatif OÜ (NextMantra)', $company), @('Agantra Inovatif OU (NextMantra)', $company),
        @('Agantra Inovatif OU', $company), @('Agantra Inovatif', $company), @('Nicko Satria Utama', $cName), @('nicko@nextmantra.com', $cMail),
        @('nextmantra.com', $siteBare), @('NextMantra', $prefix), @('nextmantra', $short), @('Agantra', $prefix), @('agantra', $short), @('67096', $(if ($pen) { $pen } else { '(none)' })))
    for ($k = $start; $k -lt $lines.Count; $k++) {
        $l = $lines[$k]
        if ($l -match '^\s*\[\s*([^\]]+?)\s*\]\s*$') {
            $sec = $Matches[1].ToLowerInvariant(); [void]$out.Add($l)
            if ($sec -eq 'ca_names') { foreach ($kv in $set['ca_names'].GetEnumerator()) { [void]$out.Add(('{0,-15} = {1}' -f $kv.Key, $kv.Value)) }; $written['ca_names'] = 'Prefix', 'SlugPrefix' }
            continue
        }
        if ($l -match '^\s*#' -or $l -match '^\s*;') {
            foreach ($p in $commentMap) { $l = $l.Replace($p[0], $p[1]) }
            [void]$out.Add($l); continue
        }
        if ($l.Trim() -eq '') { [void]$out.Add($l); continue }
        if ($regen.ContainsKey($sec)) {
            if (-not $emitted.ContainsKey($sec)) { $emitted[$sec] = $true; foreach ($x in $regen[$sec]) { [void]$out.Add($x) } }
            continue
        }
        if ($l -match '^(?<k>\s*[A-Za-z_][\w.]*)(?<eq>\s*=\s*)(?<v>.*)$') {
            $key = $Matches['k'].Trim()
            if ($set.ContainsKey($sec) -and $set[$sec].Contains($key)) {
                $val = [string]$set[$sec][$key]
                [void]$out.Add(('{0}{1}{2}' -f $Matches['k'], $Matches['eq'], $val).TrimEnd())
                if (-not $written.ContainsKey($sec)) { $written[$sec] = @() }; $written[$sec] += $key
                continue
            }
            if ($sec -in 'crl_urls', 'ocsp_urls', 'ca_issuer_urls') { [void]$out.Add($l.Replace('nextmantra.internal', $internal)); continue }
        }
        [void]$out.Add($l)
    }
    # keys that the template does not have in a section: add them at the end of the section's first line
    $final = [System.Collections.Generic.List[string]]::new(); $sec = ''
    for ($k = 0; $k -lt $out.Count; $k++) {
        $l = $out[$k]
        if ($l -match '^\s*\[\s*([^\]]+?)\s*\]\s*$') {
            $sec = $Matches[1].ToLowerInvariant(); [void]$final.Add($l)
            if ($sec -in 'pki_settings', 'subject_ov', 'subject_ev') {
                $have = if ($written.ContainsKey($sec)) { @($written[$sec]) } else { @() }
                foreach ($kv in $set[$sec].GetEnumerator()) { if ($have -notcontains $kv.Key) { [void]$final.Add(('{0,-31} = {1}' -f $kv.Key, $kv.Value).TrimEnd()) } }
            }
            continue
        }
        [void]$final.Add($l)
    }
    $left = @($final | Where-Object { $_ -notmatch '^\s*[#;]' -and $_ -match '(?i)agantra|nextmantra' })
    foreach ($x in $left) { Write-Host "[WARN] still names the template company: $x" -ForegroundColor Yellow }

    if (-not (Test-Path -LiteralPath $outDir)) { [void](New-Item -ItemType Directory -Path $outDir -Force) }
    [System.IO.File]::WriteAllText($outFile, (($final -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    Write-Host ''
    Write-Host "[OK] Written: $outFile" -ForegroundColor Green
    Write-Host "     Company  : $company   Short name: $short   CA names start with: $prefix   Website: $site"
    Write-Host "     Build it : .\pki_setup.ps1 -Pki $short -InstallTrust      (folder .\pki\pki-$short-01)"
    Write-Host "     List     : .\pki_setup.ps1 -ListPki"
    exit 0
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
