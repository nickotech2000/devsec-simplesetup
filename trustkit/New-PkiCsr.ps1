# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 5.1
<#
.SYNOPSIS
    Makes a private key and a certificate request (CSR) step by step, on the computer that needs the certificate (the DESTINATION). STANDALONE: it needs
    only OpenSSL (Prepare-Computer.ps1 installs it). Send the .csr to the owner of the PKI; keep the .key. Full help: .\New-PkiCsr.ps1 -Help
.EXAMPLE
    .\New-PkiCsr.ps1                       (asks one question after the other)
.EXAMPLE
    .\New-PkiCsr.ps1 -CommonName app.example.com -Company "Example OU" -Country EE -San app.example.com,10.0.0.5 -NonInteractive
.EXAMPLE
    .\New-PkiCsr.ps1 -CertificateType IntermediateCA -CommonName "Dept Issuing CA G1" -Company "Dept Ltd" -OrganizationalUnit "IT Department" -Country EE -NonInteractive
#>
param(
    [ValidateSet('Leaf', 'IntermediateCA')][string]$CertificateType,
    [string]$CommonName,
    [string]$CompanyId,
    [string]$Company,
    [string]$OrganizationalUnit,
    [string]$Email,
    [string]$Phone,
    [string]$ContactPerson,
    [string]$Address,
    [string]$City,
    [string]$State,
    [string]$Country,
    [string]$PostalCode,
    [string]$BusinessCategory,
    [string]$JurisdictionCountry,
    [string]$JurisdictionState,
    [string]$JurisdictionLocality,
    [string]$IanaPen,
    [string[]]$San,
    [switch]$AddDevelopmentSAN,
    [ValidateSet('ServerAuth', 'ClientAuth', 'ServerClientAuth', 'CodeSigning', 'EmailProtection')][string]$Purpose = 'ServerAuth',
    [ValidateSet('RSA', 'ECDSA', 'MLDSA')][string]$KeyType = 'RSA',
    [int]$KeyBits = 4096,
    [string]$Curve = 'P-384',
    [int]$MlDsa = 65,
    [string]$Digest = 'SHA384',
    [string]$Name,
    [string]$OutDirectory,
    [string]$OpenSslPath,
    [switch]$NonInteractive,
    [switch]$Help
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:ToolVersion = '6.4.3'
$script:DevSanMarker = 'add-development-san.pki-marker.invalid'

function Show-Help {
@'
============================================================
 New-PkiCsr.ps1 - make a key and a certificate request (CSR) step by step (for the DESTINATION
 computer)
 Version 6.4.3
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
WHAT IT DOES
  Asks you, one question after the other, for the data of the certificate, makes a PRIVATE KEY and a
  CSR on this computer, and writes both into a new folder.
  You send ONLY the .csr to the owner of the PKI (he signs it with SignCsr.ps1 / SignCsr.sh). The
  .key never leaves this computer.
  Standalone: it needs only OpenSSL 3.x or 4.x (Prepare-Computer.ps1 installs it with winget or
  Chocolatey). Windows PowerShell 5.1 or PowerShell 7.

WHAT THE REQUEST IS FOR  (-CertificateType, asked first)
  Leaf             a certificate for a server, a person, code signing or e-mail (default). Signed by
                   SignCsr.ps1 / SignCsr.sh.
  IntermediateCA   the certificate of a NEW CA of your department. The request asks for CA:TRUE and
                   key usage keyCertSign + cRLSign, carries NO names (no SAN) and NEVER the
                   development names. Company, country, department (OU) and the name of the CA (CN)
                   are required; the key is RSA 4096 / 8192 or ECDSA P-384 / P-521 (not ML-DSA, not
                   RSA 2048 / 3072, not P-256). The owner of the PKI signs it with
                   SignExternalCa.ps1 (a Quadrant Root; SignCsr refuses a CA request).

THE STEPS (press Enter to skip an optional one)
   1 Common name (CN)      the host name of the server, or the name of the certificate
                           REQUIRED
   2 Company ID            the registration number of the company: becomes the SERIAL NUMBER of the
                           subject
   3 Company               the official company name (O)           4 Department (OU; required for a CA)   5 E-mail   6 Contact phone   7 Contact person
   7 Address (street)      8 City   9 State / province   10 Country (2 letters, e.g. EE, ID, DE)   11 Postal code
  12 EV information        business category (Private Organization | Government Entity | Business Entity | Non-Commercial Entity) and the
                           jurisdiction of registration (country, state, locality). Fill it and the
                           CA signs an EV certificate.
  13 IANA PEN (optional)   your Private Enterprise Number: your company policy OID
                           1.3.6.1.4.1.<PEN>.1 is put in the request
  14 Names (SAN)           DNS names, IP addresses and e-mail addresses, ONE BY ONE (empty line =
                           finished). The first DNS name is the CN if you gave none. "Add the
                           development names?" puts a marker in the request: the CA then adds its
                           development SAN list (like -AddDevelopmentSAN).
  15 Key                   RSA 4096 + SHA-384 (default), RSA 2048 / 3072 / 8192, ECDSA P-256 / P-384
                           / P-521, ML-DSA-44 / 65 / 87 (OpenSSL 3.5+ or 4)

WHICH CERTIFICATE YOU GET  (the CA decides by what the request carries; Classic, Quadrant 1 unless
it says otherwise)
   EV information complete (business category + jurisdiction country + company ID + state + city)
   ->  an EV certificate a company (name + country) without EV information
   ->  an OV certificate
   only a common name
                                            ->  a DV certificate
   The CRL and OCSP addresses in the certificate are those of the CA that signs it.

RULES (the request is REFUSED here when it breaks one - the CA checks the same)
   RSA below 2048 bit, ECDSA below P-256, ML-DSA other than 44 / 65 / 87, a request hash below
   SHA-256 (SHA-1, SHA-224, MD5 ...) are rejected.
   Code signing needs RSA 4096+, ECDSA P-384+, ML-DSA-65+.

OPTIONS  (give them to skip the questions; with -NonInteractive nothing is asked)
  -CertificateType Leaf|IntermediateCA   -OrganizationalUnit <department>
  -CommonName -CompanyId -Company -Email -Phone -ContactPerson -Address -City -State -Country
  -PostalCode
  -BusinessCategory <one of the four>  -JurisdictionCountry -JurisdictionState -JurisdictionLocality
                                       (EV; the three jurisdiction values default to Country / State
                                       / City)
  -IanaPen <number>   -San <name,name,...>   -AddDevelopmentSAN
  -Purpose ServerAuth (default) | ClientAuth | ServerClientAuth | CodeSigning | EmailProtection
  -KeyType RSA (default) | ECDSA | MLDSA    -KeyBits 2048|3072|4096|8192    -Curve P-256|P-384|P-521    -MlDsa 44|65|87    -Digest SHA256|SHA384|SHA512
  -Name <text> (folder and file name, default the CN)   -OutDirectory <folder> (default
  .\csr-requests)   -OpenSslPath <openssl.exe>
  -NonInteractive   -Help

RESULT  (folder  csr-requests\<name>_<yyyyMMdd-HHmmss>\ )
  <name>.key   your private key - KEEP IT SECRET, never send it     <name>.csr   the request - send THIS one
  request-info.txt   what the request contains and which level it asks for     README.txt   what to do next

WHERE IT RUNS
  Windows 11 24H2 or newer (Home, Pro, Pro for Workstations, Education, Pro Education, Enterprise),
  Windows Server 2025 and Windows Server 2022 (Essentials,
  Standard, Datacenter). Refused (exit 5): Windows 10 and earlier, Windows 11 before 24H2, Windows
  Server before 2022 and the Chinese, Government, IoT,
  SE and Embedded editions. Linux with PowerShell: Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky
  10+, Oracle Linux 10+, SLES 15+, openSUSE 15+.
  The shell twin for Linux: new-pki-csr.sh.     EXIT CODES   0 ok   1 error   4 OpenSSL not found   5 system not supported
============================================================
'@ | Write-Host
}

function Say { param([string]$Level, [string]$Text)
    $c = 'Cyan'; if ($Level -eq 'OK') { $c = 'Green' } elseif ($Level -eq 'WARN') { $c = 'Yellow' } elseif ($Level -eq 'ERROR') { $c = 'Red' }
    Write-Host ('[{0}] {1}' -f $Level, $Text) -ForegroundColor $c
}
function Read-Answer { param([string]$Prompt) $v = Read-Host $Prompt; if ($null -eq $v) { Stop-Tool 'The input ended before all questions were answered. Give the values as options, or use -NonInteractive.' 1 }; return $v }
function Stop-Tool { param([string]$Text, [int]$Code = 1) Say 'ERROR' $Text; exit $Code }

if ($Help) { Show-Help; return }

# ---------------------------------------------------------------- the system
function Test-HostSupported {
    $isWin = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
    if ($isWin -or $env:PKI_FAKE_OS) {
        $osBuild = 0; $osProduct = ''; $osEd = ''; $osKind = ''
        if ($isWin) {
            try {
                $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
                $osBuild = [int]$cv.CurrentBuildNumber; $osProduct = [string]$cv.ProductName; $osKind = [string]$cv.InstallationType; $osEd = [string]$cv.EditionID
            } catch { $osBuild = [Environment]::OSVersion.Version.Build }
        }
        if ($env:PKI_FAKE_OS) { $fp = $env:PKI_FAKE_OS.Split(':'); $osKind = $fp[0]; $osBuild = [int]$fp[1]; $osProduct = 'test (PKI_FAKE_OS)'; $osEd = $(if ($fp.Count -gt 2) { $fp[2] } elseif ($osKind -like 'Server*') { 'ServerStandard' } else { 'Professional' }) }
        $name = if ($osProduct) { "$osProduct (build $osBuild)" } else { "Windows build $osBuild" }
        if ($osEd) { $name = "$name, edition $osEd" }
        $txt = "$osEd $osProduct"
        $bad = ''
        if ($txt -match '(?i)china|chinese|CountrySpecific') { $bad = 'a Chinese edition: specialised editions are NOT supported' }
        elseif ($txt -match '(?i)government|EnterpriseG\b|EnterpriseGN|\bGov\b') { $bad = 'a Government edition: specialised editions are NOT supported' }
        elseif ($txt -match '(?i)IoT') { $bad = 'an IoT / IoT Enterprise edition: specialised editions are NOT supported' }
        elseif ($txt -match '(?i)\bSE\b|Embedded') { $bad = 'an SE / Embedded edition: specialised editions are NOT supported' }
        elseif ($osKind -like 'Server*') {
            if ($osEd -and $osEd -notmatch '^Server(Standard|Datacenter|Solution|Essentials)(Core|Eval|ACor)?$') { $bad = 'this Windows Server edition is NOT supported (Essentials, Standard, Datacenter only)' }
            elseif ($osBuild -lt 20348) { $bad = 'a Windows Server before 2022 is NOT supported' }
            elseif ($osBuild -ge 22000 -and $osBuild -lt 26100) { $bad = 'this Windows Server build is NOT supported (only Windows Server 2022 and 2025)' }
        }
        else {
            if ($osBuild -lt 22000) { $bad = 'Windows 10 and earlier are NOT supported' }
            elseif ($osBuild -lt 26100) { $bad = 'Windows 11 before 24H2 is NOT supported (needs 24H2 = build 26100 or newer)' }
            elseif ($osEd -and $osEd -notmatch '^(Core|CoreN|CoreSingleLanguage|Professional|ProfessionalN|ProfessionalWorkstation|ProfessionalWorkstationN|ProfessionalEducation|ProfessionalEducationN|Education|EducationN|Enterprise|EnterpriseN)$') { $bad = 'this Windows edition is NOT supported' }
        }
        if ($bad) { Stop-Tool "This computer is ${name}: $bad. Nothing was done." 5 }
        return
    }
    $rel = if ($env:PKI_OS_RELEASE_FILE) { $env:PKI_OS_RELEASE_FILE } else { '/etc/os-release' }
    $id = ''; $ver = ''; $pretty = ''
    if (Test-Path -LiteralPath $rel) {
        foreach ($l in (Get-Content -LiteralPath $rel)) {
            if ($l -match '^ID="?([^"]*)"?$') { $id = $Matches[1] } elseif ($l -match '^VERSION_ID="?([^"]*)"?$') { $ver = $Matches[1] } elseif ($l -match '^PRETTY_NAME="?([^"]*)"?$') { $pretty = $Matches[1] }
        }
    }
    $maj = 0; [void][int]::TryParse(($ver -split '\.')[0], [ref]$maj)
    $ok = $false
    switch ($id) {
        'ubuntu' { $ok = ($maj -ge 24) }
        { $_ -in 'centos', 'rhel', 'rocky', 'ol' } { $ok = ($maj -ge 10) }
        { $_ -in 'sles', 'sles_sap', 'sled', 'opensuse-leap' } { $ok = ($maj -ge 15) }
        'opensuse-tumbleweed' { $ok = $true }
    }
    if (-not $ok) { Stop-Tool ("This system is '{0}' (ID={1} VERSION_ID={2}): NOT supported. Supported: Windows 11 24H2+, Windows Server 2022 / 2025; Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky 10+, Oracle Linux 10+, SLES 15+, openSUSE 15+. Nothing was done." -f $pretty, $id, $ver) 5 }
}

Write-Host '============================================================'
Write-Host ' New-PkiCsr.ps1 - a key and a certificate request (CSR), step by step'
Write-Host ' Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   nicko@nextmantra.com'
Write-Host '============================================================'
Say 'INFO' "New-PkiCsr.ps1 version $script:ToolVersion"
Test-HostSupported

# ---------------------------------------------------------------- OpenSSL
function Find-OpenSsl {
    $cands = New-Object System.Collections.ArrayList
    if ($OpenSslPath) { [void]$cands.Add($OpenSslPath) }
    if ($env:PKI_OPENSSL) { [void]$cands.Add($env:PKI_OPENSSL) }
    foreach ($n in 'openssl4', 'openssl') { $g = Get-Command $n -ErrorAction SilentlyContinue; if ($g) { [void]$cands.Add($g.Source) } }
    foreach ($d in @("$env:ProgramFiles\FireDaemon OpenSSL 4\bin", "$env:ProgramFiles\FireDaemon OpenSSL\bin", "$env:ProgramFiles\FireDaemon OpenSSL 3\bin", "$env:ProgramFiles\OpenSSL-Win64\bin", "$env:ProgramFiles\OpenSSL\bin", 'C:\ProgramData\chocolatey\bin', 'C:\Program Files\OpenSSL-Win64\bin')) {
        if ($d -and (Test-Path -LiteralPath $d)) { foreach ($e in 'openssl.exe') { $p = Join-Path $d $e; if (Test-Path -LiteralPath $p) { [void]$cands.Add($p) } } }
    }
    foreach ($c in $cands) {
        if (-not (Test-Path -LiteralPath $c)) { continue }
        try { $v = (& $c version 2>&1 | Select-Object -First 1).ToString() } catch { continue }
        if ($v -match '^OpenSSL (\d+)\.(\d+)') { if ([int]$Matches[1] -ge 3) { return [pscustomobject]@{ Path = $c; Text = $v.Trim(); Major = [int]$Matches[1]; Minor = [int]$Matches[2] } } }
    }
    return $null
}
$ossl = Find-OpenSsl
if (-not $ossl) { Stop-Tool 'OpenSSL 3.x or 4.x was not found. Install it:  .\Prepare-Computer.ps1   (Windows: winget or Chocolatey; Linux: prepare-computer.sh)  or give -OpenSslPath.' 4 }
Say 'INFO' ("OpenSSL: {0}  ({1})" -f $ossl.Text, $ossl.Path)
# the PKI may already be installed on this computer (Install-PkiCa.ps1 / Local Machine store): the request needs none of it, so nothing is required or changed
try {
    $tc = New-Object System.Collections.ArrayList
    if ($env:PKI_KIT_STATE_DIR) { [void]$tc.Add((Join-Path $env:PKI_KIT_STATE_DIR 'installed.tsv')) }
    if ($env:ProgramData) { [void]$tc.Add((Join-Path $env:ProgramData 'PkiTrustKit\installed.tsv')) }
    if ($env:LOCALAPPDATA) { [void]$tc.Add((Join-Path $env:LOCALAPPDATA 'PkiTrustKit\installed.tsv')) }
    [void]$tc.Add('/var/lib/pki-trust-kit/installed.tsv')
    $tsv = $tc | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($tsv) {
        $names = @(Get-Content -LiteralPath $tsv | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object { ($_ -split "`t")[0] } | Where-Object { $_ -and $_ -ne 'pki' } | Sort-Object -Unique)
        if ($names.Count -gt 0) { Say 'INFO' ("PKI already installed on this computer: {0}. The request does not need it; the certificate you get back will chain to it." -f ($names -join ', ')) }
    }
} catch { }

# ---------------------------------------------------------------- the questions
$interactive = (-not $NonInteractive) -and (($env:PKI_FORCE_INTERACTIVE -eq '1') -or ([Environment]::UserInteractive -and (-not [Console]::IsInputRedirected)))   # PKI_FORCE_INTERACTIVE=1: test hook (piped answers)
$asked = 0
function Ask {
    param([string]$Label, [string]$Current, [string]$Hint = '', [bool]$Required = $false, [scriptblock]$Check = $null, [string]$Default = '')
    if ($Current) { return $Current.Trim() }          # given on the command line
    if (-not $interactive) { return $Default }
    $script:asked++
    while ($true) {
        $suffix = if ($Default) { " [$Default]" } elseif (-not $Required) { ' (Enter = skip)' } else { '' }
        Write-Host ''
        Write-Host ("Step {0}: {1}" -f $script:asked, $Label) -ForegroundColor Cyan
        if ($Hint) { Write-Host "         $Hint" -ForegroundColor DarkGray }
        $v = (Read-Answer ("         >$suffix")).Trim()
        if (-not $v) { $v = $Default }
        if (-not $v) { if ($Required) { Say 'WARN' 'This one is required.'; continue } else { return '' } }
        if ($Check) { $m = & $Check $v; if ($m) { Say 'WARN' $m; continue } }
        return $v
    }
}
$chkCn = { param($v) if ($v.Length -gt 64) { 'At most 64 characters.' } elseif ($v -match '[/\\]') { "Without / and \." } else { $null } }
$chkMail = { param($v) if ($v -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { 'Not an e-mail address.' } else { $null } }
$chkPhone = { param($v) if ($v -notmatch '^\+?[0-9][0-9 ()./-]{4,30}$') { 'Digits, spaces and + - ( ) only, e.g. +372 5555 1234.' } else { $null } }
$chkCountry = { param($v) if ($v -cnotmatch '^[A-Z]{2}$') { 'Two UPPER-case letters (ISO 3166), e.g. EE, ID, DE.' } else { $null } }
$chkPen = { param($v) if ($v -notmatch '^[1-9][0-9]{0,9}$') { 'Digits only, e.g. 12345.' } else { $null } }

Write-Host ''
Say 'INFO' 'Answer the questions one by one. Optional steps: press Enter to skip.'
# what the request is for
if (-not $CertificateType) {
    if ($interactive) {
        $script:asked++
        Write-Host ''; Write-Host ("Step {0}: What is the request for?" -f $script:asked) -ForegroundColor Cyan
        Write-Host '           1. Leaf: a server, a person, code signing, e-mail (default)'
        Write-Host '           2. Intermediate CA: the certificate of a new CA of your department (no names, no development names)'
        while ($true) { $n = (Read-Answer '         Number [1]').Trim(); if (-not $n) { $n = '1' }; if ($n -in '1', '2') { break }; Say 'WARN' '1 or 2.' }
        $CertificateType = if ($n -eq '2') { 'IntermediateCA' } else { 'Leaf' }
    }
    else { $CertificateType = 'Leaf' }
}
$isCa = ($CertificateType -eq 'IntermediateCA')
if ($isCa) { Say 'INFO' 'Request for an INTERMEDIATE CA: CA:TRUE, no names, no development names. The owner of the PKI signs it with SignExternalCa.ps1.' }
$CommonName = Ask $(if ($isCa) { 'Name of the CA (CN), e.g. Dept Issuing CA G1' } else { 'Common name (CN): the host name of the server, e.g. app.example.com' }) $CommonName $(if ($isCa) { 'Not the name of a CA of the PKI that signs you.' } else { 'For a person or a code signing certificate: the name.' }) $true $chkCn
$CompanyId = Ask 'Company ID / registration number (becomes the SERIAL NUMBER of the subject)' $CompanyId 'e.g. 17344131. Needed for an EV certificate.'
$Company = Ask 'Company name (O)' $Company $(if ($isCa) { 'Required for a CA. The official name, as registered.' } else { 'The official name, as registered.' }) $isCa
$OrganizationalUnit = Ask 'Department (OU)' $OrganizationalUnit $(if ($isCa) { 'Required for a CA, e.g. IT Department.' } else { 'Optional, e.g. IT Department.' }) $isCa
$Email = Ask 'Contact e-mail' $Email '' $false $chkMail
$Phone = Ask 'Contact phone' $Phone 'e.g. +372 5555 1234' $false $chkPhone
$ContactPerson = Ask 'Contact person (full name)' $ContactPerson
$Address = Ask 'Address (street and number)' $Address
$City = Ask 'City' $City
$State = Ask 'State / province' $State
$Country = Ask 'Country (2 letters)' $Country 'e.g. EE, ID, DE. Needed with the company name.' $isCa $chkCountry
$PostalCode = Ask 'Postal code' $PostalCode

# EV information
$evAsked = [bool]($BusinessCategory -or $JurisdictionCountry -or $JurisdictionState -or $JurisdictionLocality)
$cats = @('Private Organization', 'Government Entity', 'Business Entity', 'Non-Commercial Entity')
if (-not $evAsked -and $interactive) {
    Write-Host ''; $script:asked++
    Write-Host ("Step {0}: EV information (extended validation)" -f $script:asked) -ForegroundColor Cyan
    Write-Host '         Fill it when the company is registered and you want an EV certificate. The CA then signs it as EV.' -ForegroundColor DarkGray
    $a = (Read-Answer '         Fill the EV information now? (y/N)').Trim()
    $evAsked = ($a -match '^(?i)y(es)?$')
}
if ($evAsked) {
    if (-not $BusinessCategory) {
        if ($interactive) {
            Write-Host '         Business category:'
            for ($i = 0; $i -lt $cats.Count; $i++) { Write-Host ("           {0}. {1}" -f ($i + 1), $cats[$i]) }
            while ($true) { $n = (Read-Answer '         Number [1]').Trim(); if (-not $n) { $n = '1' }; if ($n -match '^[1-4]$') { $BusinessCategory = $cats[[int]$n - 1]; break }; Say 'WARN' '1, 2, 3 or 4.' }
        }
        else { $BusinessCategory = $cats[0] }
    }
    if ($cats -cnotcontains $BusinessCategory) { Stop-Tool "BusinessCategory must be one of: $($cats -join ' | ')" }
    $JurisdictionCountry = Ask 'Jurisdiction of registration: country (2 letters)' $JurisdictionCountry '' $true $chkCountry $Country
    $JurisdictionState = Ask 'Jurisdiction of registration: state / province' $JurisdictionState '' $false $null $State
    $JurisdictionLocality = Ask 'Jurisdiction of registration: locality (city)' $JurisdictionLocality '' $false $null $City
}
$IanaPen = Ask 'IANA Private Enterprise Number (PEN) of the company' $IanaPen 'Optional. Your company policy OID 1.3.6.1.4.1.<PEN>.1 is put in the request.' $false $chkPen

# names (SAN), one by one
$names = New-Object System.Collections.ArrayList
foreach ($x in @($San)) { foreach ($t in ("$x" -split '[,;\s]+')) { if ($t) { [void]$names.Add($t) } } }
if (-not $isCa -and $names.Count -eq 0 -and $interactive -and $Purpose -ne 'CodeSigning') {
    Write-Host ''; $script:asked++
    Write-Host ("Step {0}: Names of the certificate (SAN), one by one" -f $script:asked) -ForegroundColor Cyan
    Write-Host $(if ($Purpose -eq 'EmailProtection') { '         E-mail addresses. An empty line = finished.' } else { '         DNS names (also *.example.com), IP addresses. An empty line = finished.' }) -ForegroundColor DarkGray
    $k = 0
    while ($true) {
        $k++
        $v = (Read-Answer ("         name {0}" -f $k)).Trim()
        if (-not $v) { break }
        [void]$names.Add($v)
    }
}
$dev = [bool]$AddDevelopmentSAN
if (-not $isCa -and -not $AddDevelopmentSAN -and $interactive -and $Purpose -in 'ServerAuth', 'ClientAuth', 'ServerClientAuth', 'EmailProtection') {
    Write-Host ''
    $a = (Read-Answer '         Add the DEVELOPMENT names too (the CA adds its development list: local host names and IP ranges)? (y/N)').Trim()
    $dev = ($a -match '^(?i)y(es)?$')
}

# the key (step 15)
if ($isCa -and $interactive -and -not ($PSBoundParameters.ContainsKey('KeyType') -or $PSBoundParameters.ContainsKey('KeyBits') -or $PSBoundParameters.ContainsKey('Curve') -or $PSBoundParameters.ContainsKey('Digest'))) {
    $script:asked++
    Write-Host ''; Write-Host ("Step {0}: Key and hash of the CA" -f $script:asked) -ForegroundColor Cyan
    $kc = @('RSA 4096 + SHA-384 (default)', 'RSA 8192 + SHA-512', 'ECDSA P-384 + SHA-384', 'ECDSA P-521 + SHA-512')
    for ($i = 0; $i -lt $kc.Count; $i++) { Write-Host ("           {0}. {1}" -f ($i + 1), $kc[$i]) }
    while ($true) { $n = (Read-Answer '         Number [1]').Trim(); if (-not $n) { $n = '1' }; if ($n -match '^[1-4]$') { break }; Say 'WARN' '1 to 4.' }
    switch ([int]$n) { 2 { $KeyBits = 8192; $Digest = 'SHA512' } 3 { $KeyType = 'ECDSA'; $Curve = 'P-384' } 4 { $KeyType = 'ECDSA'; $Curve = 'P-521'; $Digest = 'SHA512' } }
}
if (-not $isCa -and $interactive -and -not ($PSBoundParameters.ContainsKey('KeyType') -or $PSBoundParameters.ContainsKey('KeyBits') -or $PSBoundParameters.ContainsKey('Curve') -or $PSBoundParameters.ContainsKey('MlDsa') -or $PSBoundParameters.ContainsKey('Digest'))) {
    $script:asked++
    Write-Host ''; Write-Host ("Step {0}: Key and hash" -f $script:asked) -ForegroundColor Cyan
    $kc = @('RSA 4096 + SHA-384 (default)', 'RSA 3072 + SHA-384', 'RSA 2048 + SHA-256', 'ECDSA P-256 + SHA-256', 'ECDSA P-384 + SHA-384', 'ECDSA P-521 + SHA-512', 'ML-DSA-65 (quantum, OpenSSL 3.5+/4)', 'ML-DSA-87 (quantum)', 'ML-DSA-44 (quantum)')
    for ($i = 0; $i -lt $kc.Count; $i++) { Write-Host ("           {0}. {1}" -f ($i + 1), $kc[$i]) }
    while ($true) {
        $n = (Read-Answer '         Number [1]').Trim(); if (-not $n) { $n = '1' }
        if ($n -match '^[1-9]$') { break }; Say 'WARN' '1 to 9.'
    }
    switch ([int]$n) {
        1 { }
        2 { $KeyBits = 3072 }
        3 { $KeyBits = 2048; $Digest = 'SHA256' }
        4 { $KeyType = 'ECDSA'; $Curve = 'P-256'; $Digest = 'SHA256' }
        5 { $KeyType = 'ECDSA'; $Curve = 'P-384' }
        6 { $KeyType = 'ECDSA'; $Curve = 'P-521'; $Digest = 'SHA512' }
        7 { $KeyType = 'MLDSA'; $MlDsa = 65 }
        8 { $KeyType = 'MLDSA'; $MlDsa = 87 }
        9 { $KeyType = 'MLDSA'; $MlDsa = 44 }
    }
}

# ---------------------------------------------------------------- check what was given
function Test-Dns { param([string]$n) $b = if ($n.StartsWith('*.')) { $n.Substring(2) } else { $n }; return ($b -match '^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$') }
$errs = New-Object System.Collections.ArrayList
$dns = New-Object System.Collections.ArrayList; $ips = New-Object System.Collections.ArrayList; $mails = New-Object System.Collections.ArrayList
foreach ($n in $names) {
    $t = $null
    if ($n -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') { if (-not ($mails -contains $n)) { [void]$mails.Add($n) } }
    elseif ([System.Net.IPAddress]::TryParse($n, [ref]$t)) { if (-not ($ips -contains $t.ToString())) { [void]$ips.Add($t.ToString()) } }
    elseif (Test-Dns $n) { if (-not ($dns | Where-Object { $_ -ieq $n })) { [void]$dns.Add($n) } }
    else { [void]$errs.Add("'$n' is not a DNS name, an IP address or an e-mail address.") }
}
if ($CommonName -and $CommonName.Length -gt 64) { [void]$errs.Add('The common name is longer than 64 characters.') }
if ($CommonName -match '[/\\]') { [void]$errs.Add('The common name contains / or \.') }
if (-not $CommonName) { [void]$errs.Add('The common name (CN) is required.') }
if (($Company -and -not $Country) -or ($Country -and -not $Company)) { [void]$errs.Add('The company name and the country go together: give both, or neither (then the request carries the common name only).') }
if ($Country -and $Country -cnotmatch '^[A-Z]{2}$') { [void]$errs.Add('Country: two UPPER-case letters.') }
if ($Email -and $Email -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { [void]$errs.Add('The e-mail address is not valid.') }
if ($IanaPen -and $IanaPen -notmatch '^[1-9][0-9]{0,9}$') { [void]$errs.Add('IANA PEN: digits only.') }
if ($evAsked) {
    foreach ($pair in @(@('Company ID (serial number)', $CompanyId), @('Company', $Company), @('Country', $Country), @('State / province', $State), @('City', $City), @('Business category', $BusinessCategory), @('Jurisdiction country', $JurisdictionCountry))) {
        if (-not $pair[1]) { [void]$errs.Add("EV information needs: $($pair[0]).") }
    }
    if ($JurisdictionCountry -and $JurisdictionCountry -cnotmatch '^[A-Z]{2}$') { [void]$errs.Add('Jurisdiction country: two UPPER-case letters.') }
    if (($dns | Where-Object { $_.Contains('*') }) ) { [void]$errs.Add('An EV certificate may not have a wildcard name.') }
}
foreach ($v in @($CommonName, $Company, $CompanyId, $ContactPerson, $Address, $City, $State, $PostalCode, $Phone, $Email)) { if ($v -match "[\r\n]") { [void]$errs.Add('A value contains a line break.') } }
# an intermediate CA request
if ($isCa) {
    if ($AddDevelopmentSAN) { [void]$errs.Add('An intermediate CA may not have the development names: -AddDevelopmentSAN is refused for -CertificateType IntermediateCA.') }
    if ($names.Count -gt 0) { [void]$errs.Add('A request for an intermediate CA carries no names (-San).') }
    if ($PSBoundParameters.ContainsKey('Purpose')) { [void]$errs.Add('-Purpose is for a leaf certificate; a CA request has none.') }
    foreach ($pair in @(@('Company (O)', $Company), @('Department (OU)', $OrganizationalUnit), @('Country', $Country))) { if (-not $pair[1]) { [void]$errs.Add("A CA request needs: $($pair[0]).") } }
    if ($KeyType -eq 'MLDSA') { [void]$errs.Add('A CA of this PKI is Classic: ML-DSA is refused for an intermediate CA request (RSA 4096 / 8192 or ECDSA P-384 / P-521).') }
    if ($KeyType -eq 'RSA' -and $KeyBits -notin 4096, 8192 -and $KeyBits -ge 2048) { [void]$errs.Add("RSA $KeyBits bit is too small for a CA: 4096 or 8192.") }
    if ($KeyType -eq 'ECDSA' -and $Curve.ToUpperInvariant().Replace('P', 'P-').Replace('P--', 'P-') -eq 'P-256') { [void]$errs.Add('Curve P-256 is too small for a CA: P-384 or P-521.') }
}
# the key and the hash
$Digest = $Digest.ToUpperInvariant().Replace('-', '')
if ($Digest -notin 'SHA256', 'SHA384', 'SHA512') { [void]$errs.Add("Hash $Digest is refused: SHA256, SHA384 or SHA512 (SHA-1, SHA-224 and MD5 are below SHA-256).") }
$strong = ($Purpose -eq 'CodeSigning')
switch ($KeyType) {
    'RSA' {
        if ($KeyBits -lt 2048) { [void]$errs.Add("RSA $KeyBits bit is refused: the minimum is 2048.") }
        elseif ($KeyBits -notin 2048, 3072, 4096, 8192) { [void]$errs.Add("RSA $KeyBits bit is not a size of this PKI: 2048, 3072, 4096 or 8192.") }
        elseif ($strong -and $KeyBits -lt 4096) { [void]$errs.Add('Code signing needs RSA 4096 or more.') }
    }
    'ECDSA' {
        $Curve = $Curve.ToUpperInvariant().Replace('P', 'P-').Replace('P--', 'P-')
        if ($Curve -notin 'P-256', 'P-384', 'P-521') { [void]$errs.Add("Curve $Curve is refused: P-256, P-384 or P-521.") }
        elseif ($strong -and $Curve -eq 'P-256') { [void]$errs.Add('Code signing needs ECDSA P-384 or P-521.') }
    }
    'MLDSA' {
        if ($MlDsa -notin 44, 65, 87) { [void]$errs.Add("ML-DSA-$MlDsa is refused: 44, 65 or 87.") }
        elseif ($strong -and $MlDsa -lt 65) { [void]$errs.Add('Code signing needs ML-DSA-65 or 87.') }
    }
}
if ($KeyType -eq 'MLDSA' -and -not ($ossl.Major -ge 4 -or ($ossl.Major -eq 3 -and $ossl.Minor -ge 5))) { [void]$errs.Add("ML-DSA needs OpenSSL 3.5 or 4 (this is $($ossl.Text)). Prepare-Computer.ps1 installs a newer one.") }
if (-not $isCa -and $Purpose -in 'ServerAuth', 'ServerClientAuth', 'ClientAuth') {
    if ($dns.Count -eq 0 -and $ips.Count -eq 0 -and -not $dev) {
        if ($CommonName -and (Test-Dns $CommonName) -and $CommonName -notmatch '\s') { [void]$dns.Add($CommonName); Say 'INFO' "No names given: the common name '$CommonName' is the DNS name." }
        else { [void]$errs.Add('A TLS certificate needs at least one DNS name or IP address (-San), or the development names.') }
    }
    elseif ($CommonName -and (Test-Dns $CommonName) -and -not ($dns | Where-Object { $_ -ieq $CommonName }) -and $dns.Count -gt 0 -and -not $evAsked) { }
}
if (-not $isCa -and $Purpose -eq 'EmailProtection' -and $mails.Count -eq 0 -and -not $dev) {
    if ($CommonName -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') { [void]$mails.Add($CommonName) } elseif ($Email) { [void]$mails.Add($Email) } else { [void]$errs.Add('An S/MIME certificate needs an e-mail address (-San or -Email).') }
}
if ($errs.Count -gt 0) { Write-Host ''; foreach ($e in $errs) { Say 'ERROR' $e }; Stop-Tool 'The request was NOT made. Correct the points above and run again.' 1 }

# ---------------------------------------------------------------- make it
if (-not $Name) { $Name = $CommonName }
$safe = (($Name -replace '^\*\.', 'wildcard.' -replace '[^A-Za-z0-9._-]+', '-').Trim('-.')); if (-not $safe) { $safe = 'request' }
$base = if ($OutDirectory) { $OutDirectory } else { Join-Path (Get-Location).Path 'csr-requests' }
$dir = Join-Path $base ("{0}_{1}" -f $safe, (Get-Date -Format 'yyyyMMdd-HHmmss'))
[void][System.IO.Directory]::CreateDirectory($dir)
$utf8 = New-Object System.Text.UTF8Encoding($false)
$keyF = Join-Path $dir "$safe.key"; $csrF = Join-Path $dir "$safe.csr"; $cnf = Join-Path $dir 'req.tmp.cnf'

function Q([string]$v) { return '"' + ($v -replace '\\', '\\\\' -replace '"', '\"' -replace '\$', '\$' -replace '#', '\#') + '"' }
$L = New-Object System.Collections.ArrayList
[void]$L.Add('[ req ]'); [void]$L.Add('distinguished_name = dn'); [void]$L.Add('req_extensions = ext'); [void]$L.Add('prompt = no'); [void]$L.Add('utf8 = yes'); [void]$L.Add('string_mask = utf8only'); [void]$L.Add('')
[void]$L.Add('[ dn ]')
$dnPairs = New-Object System.Collections.ArrayList
function Add-Dn([string]$k, [string]$v) { if ($v) { [void]$dnPairs.Add(@($k, $v)) } }
Add-Dn 'C' $Country; Add-Dn 'ST' $State; Add-Dn 'L' $City; Add-Dn 'street' $Address; Add-Dn 'postalCode' $PostalCode
Add-Dn 'O' $Company; Add-Dn 'OU' $OrganizationalUnit; Add-Dn 'name' $ContactPerson; Add-Dn 'emailAddress' $Email; Add-Dn 'telephoneNumber' $Phone
if ($Company) { Add-Dn 'serialNumber' $CompanyId }
Add-Dn 'CN' $CommonName
if ($evAsked) { Add-Dn 'businessCategory' $BusinessCategory; Add-Dn 'jurisdictionC' $JurisdictionCountry; Add-Dn 'jurisdictionST' $JurisdictionState; Add-Dn 'jurisdictionL' $JurisdictionLocality }
foreach ($p in $dnPairs) { [void]$L.Add(('{0} = {1}' -f $p[0], (Q $p[1]))) }
[void]$L.Add(''); [void]$L.Add('[ ext ]')
$hasSan = (-not $isCa) -and (($dns.Count + $ips.Count + $mails.Count -gt 0) -or $dev)
if ($isCa) { [void]$L.Add('basicConstraints = critical,CA:TRUE'); [void]$L.Add('keyUsage = critical,keyCertSign,cRLSign') }
if ($hasSan) { [void]$L.Add('subjectAltName = @alt') }
if ($IanaPen) { [void]$L.Add("certificatePolicies = 1.3.6.1.4.1.$IanaPen.1") }
if ($hasSan) {
    [void]$L.Add(''); [void]$L.Add('[ alt ]')
    $i = 0; foreach ($d in $dns) { $i++; [void]$L.Add("DNS.$i = $d") }
    if ($dev) { $i++; [void]$L.Add("DNS.$i = $script:DevSanMarker") }
    $i = 0; foreach ($a in $ips) { $i++; [void]$L.Add("IP.$i = $a") }
    $i = 0; foreach ($m in $mails) { $i++; [void]$L.Add("email.$i = $m") }
}
[System.IO.File]::WriteAllText($cnf, (($L -join "`n") + "`n"), $utf8)

try {
    switch ($KeyType) {
        'RSA' { $ga = @('genpkey', '-algorithm', 'RSA', '-pkeyopt', "rsa_keygen_bits:$KeyBits", '-out', $keyF) }
        'ECDSA' { $ga = @('genpkey', '-algorithm', 'EC', '-pkeyopt', "ec_paramgen_curve:$Curve", '-pkeyopt', 'ec_param_enc:named_curve', '-out', $keyF) }
        'MLDSA' { $ga = @('genpkey', '-algorithm', "ML-DSA-$MlDsa", '-out', $keyF) }
    }
    Say 'INFO' 'Making the private key ...'
    $o = & $ossl.Path @ga 2>&1; if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $keyF)) { throw "OpenSSL could not make the key: $(($o | Select-Object -Last 2) -join ' ')" }
    $ra = @('req', '-new', '-key', $keyF, '-config', $cnf, '-out', $csrF)
    if ($KeyType -ne 'MLDSA') { $ra += @('-' + $Digest.ToLowerInvariant().Replace('sha', 'sha')) }
    Say 'INFO' 'Making the request ...'
    $o = & $ossl.Path @ra 2>&1; if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $csrF)) { throw "OpenSSL could not make the request: $(($o | Select-Object -Last 3) -join ' ')" }
    $o = & $ossl.Path req -in $csrF -noout -verify 2>&1; if ($LASTEXITCODE -ne 0) { throw "The request does not verify: $o" }
    $txt = (& $ossl.Path req -in $csrF -noout -text 2>&1) -join "`n"
    $subj = ((& $ossl.Path req -in $csrF -noout -subject -nameopt RFC2253 2>&1) -join ' ') -replace '^subject=', ''
    $sigAlg = if ($txt -match 'Signature Algorithm:\s*(\S+)') { $Matches[1] } else { '' }
    if ($KeyType -ne 'MLDSA' -and $sigAlg -match '(?i)md5|sha1|sha-1|sha224') { throw "The request was signed with $sigAlg (below SHA-256). Not accepted." }
    # the key file is for the owner only
    try {
        if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { & icacls.exe $keyF /inheritance:r /grant:r "$($env:USERNAME):(R,W)" 2>&1 | Out-Null }
        else { & chmod 600 $keyF 2>&1 | Out-Null }
    } catch { Say 'WARN' "Could not restrict the key file to your account: protect $keyF yourself." }
}
catch { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue; Stop-Tool $_.Exception.Message 1 }
finally { Remove-Item -LiteralPath $cnf -Force -ErrorAction SilentlyContinue }

$level = if ($evAsked) { 'EV' } elseif ($Company -and $Country) { 'OV' } else { 'DV' }
$keyDesc = switch ($KeyType) { 'RSA' { "RSA-$KeyBits" } 'ECDSA' { "ECDSA-$($Curve -replace '-', '')" } 'MLDSA' { "ML-DSA-$MlDsa" } }
$track = if ($isCa) { 'Classic only (signed by SignExternalCa.ps1 with a Quadrant Root: Quadrant 1, or 2 with -Fips)' } elseif ($KeyType -eq 'MLDSA') { 'Quantum (the CA signs it with -Quantum, Quadrant 3)' } else { 'Classic (Quadrant 1 unless the CA decides otherwise)' }
$hdr = ('=' * 60) + "`nAuthor : Nicko Satria Utama`nCompany: Agantra Inovatif OU (NextMantra)`nEmail  : nicko@nextmantra.com`n" + ('=' * 60) + "`n"
$allNames = (@($dns) + @($ips) + @($mails)) -join ', '
$info = $hdr + @"

CERTIFICATE REQUEST            $safe          (New-PkiCsr.ps1 $script:ToolVersion, $((Get-Date).ToString('yyyy-MM-dd HH:mm')))
Subject    : $subj
Names      : $(if ($allNames) { $allNames } else { '(none)' })$(if ($dev) { "`n             + the development names (the request carries the marker)" })
Key        : $keyDesc, request signed with $(if ($KeyType -eq 'MLDSA') { 'ML-DSA' } else { $Digest })
Purpose    : $(if ($isCa) { 'Intermediate CA (CA:TRUE, keyCertSign + cRLSign, no names)' } else { $Purpose })
Type       : $CertificateType
Level      : $level  - $(switch ($level) { 'EV' { 'the EV information is complete: the CA signs an EV certificate' } 'OV' { 'a company without EV information: the CA signs an OV certificate' } default { 'common name only: the CA signs a DV certificate' } })
Track      : $track
$(if ($IanaPen) { "Company OID : 1.3.6.1.4.1.$IanaPen.1 (your PEN policy; the CA adds it to the certificate)`n" })
"@
[System.IO.File]::WriteAllText((Join-Path $dir 'request-info.txt'), ($info -replace "`r", '') , $utf8)
$readme = $hdr + @"

WHAT TO DO
  1. Send the file  $safe.csr  to the owner of the PKI (e-mail is fine: it holds no secret).
  2. KEEP  $safe.key  on this computer. It is your private key. NEVER send it. Whoever has it can pretend to be you.
  3. The owner signs the request ($(if ($isCa) { 'SignExternalCa.ps1 -Csr ' + $safe + '.csr' + $(if ($level -eq 'EV') { ' -Level EV' } else { '' }) } else { 'SignCsr.ps1 / SignCsr.sh' })) and sends you a folder: your certificate, the chain and root.crt.
  4. $(if ($isCa) { 'Install the certificate as the CA certificate of your CA together with ' + $safe + '.key. Protect that key like a root key (offline or in an HSM).' } else { 'Use  ' + $safe + '.key  together with  ' + $safe + '-fullchain.crt  in your server or application.' })
  The CRL (revocation list) and OCSP addresses inside your certificate are those of the CA that signs it.

LEVEL ASKED   $level   ($track)
"@
[System.IO.File]::WriteAllText((Join-Path $dir 'README.txt'), ($readme -replace "`r", ''), $utf8)

Write-Host ''
Say 'OK' "Request: $csrF"
Say 'OK' "Private key (keep it secret): $keyF"
Say 'INFO' ("Subject: {0}" -f $subj)
Say 'INFO' ("Key {0}, level asked: {1}. {2}" -f $keyDesc, $level, $(if ($level -eq 'EV') { 'The EV information is complete.' } elseif ($level -eq 'OV') { 'No EV information: an OV certificate.' } else { 'Common name only: a DV certificate.' }))
Say 'INFO' "Send ONLY the .csr to the owner of the PKI. Folder: $dir"
exit 0
