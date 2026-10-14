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
$script:ToolVersion = '5.3.6'
$script:DevSanMarker = 'add-development-san.pki-marker.invalid'

function Show-Help {
@'
============================================================
 New-PkiCsr.ps1 - make a key and a certificate request (CSR) step by step (for the DESTINATION computer)
 Version 5.3.6
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
WHAT IT DOES
  Asks you, one question after the other, for the data of the certificate, makes a PRIVATE KEY and a CSR on this computer, and writes both into a new folder.
  You send ONLY the .csr to the owner of the PKI (he signs it with SignCsr.ps1 / SignCsr.sh). The .key never leaves this computer.
  Standalone: it needs only OpenSSL 3.x or 4.x (Prepare-Computer.ps1 installs it with winget or Chocolatey). Windows PowerShell 5.1 or PowerShell 7.

WHAT THE REQUEST IS FOR  (-CertificateType, asked first)
  Leaf             a certificate for a server, a person, code signing or e-mail (default). Signed by SignCsr.ps1 / SignCsr.sh.
  IntermediateCA   the certificate of a NEW CA of your department. The request asks for CA:TRUE and key usage keyCertSign + cRLSign, carries NO names (no SAN) and NEVER the
                   development names. Company, country, department (OU) and the name of the CA (CN) are required; the key is RSA 4096 / 8192 or ECDSA P-384 / P-521
                   (not ML-DSA, not RSA 2048 / 3072, not P-256). The owner of the PKI signs it with SignExternalCa.ps1 (a Quadrant Root; SignCsr refuses a CA request).

THE STEPS (press Enter to skip an optional one)
   1 Common name (CN)      the host name of the server, or the name of the certificate            REQUIRED
   2 Company ID            the registration number of the company: becomes the SERIAL NUMBER of the subject
   3 Company               the official company name (O)           4 Department (OU; required for a CA)   5 E-mail   6 Contact phone   7 Contact person
   7 Address (street)      8 City   9 State / province   10 Country (2 letters, e.g. EE, ID, DE)   11 Postal code
  12 EV information        business category (Private Organization | Government Entity | Business Entity | Non-Commercial Entity) and the
                           jurisdiction of registration (country, state, locality). Fill it and the CA signs an EV certificate.
  13 IANA PEN (optional)   your Private Enterprise Number: your company policy OID 1.3.6.1.4.1.<PEN>.1 is put in the request
  14 Names (SAN)           DNS names, IP addresses and e-mail addresses, ONE BY ONE (empty line = finished). The first DNS name is the CN if you gave none.
                           "Add the development names?" puts a marker in the request: the CA then adds its development SAN list (like -AddDevelopmentSAN).
  15 Key                   RSA 4096 + SHA-384 (default), RSA 2048 / 3072 / 8192, ECDSA P-256 / P-384 / P-521, ML-DSA-44 / 65 / 87 (OpenSSL 3.5+ or 4)

WHICH CERTIFICATE YOU GET  (the CA decides by what the request carries; Classic, Quadrant 1 unless it says otherwise)
   EV information complete (business category + jurisdiction country + company ID + state + city)  ->  an EV certificate
   a company (name + country) without EV information                                                   ->  an OV certificate
   only a common name                                                                                    ->  a DV certificate
   The CRL and OCSP addresses in the certificate are those of the CA that signs it.

RULES (the request is REFUSED here when it breaks one - the CA checks the same)
   RSA below 2048 bit, ECDSA below P-256, ML-DSA other than 44 / 65 / 87, a request hash below SHA-256 (SHA-1, SHA-224, MD5 ...) are rejected.
   Code signing needs RSA 4096+, ECDSA P-384+, ML-DSA-65+.

OPTIONS  (give them to skip the questions; with -NonInteractive nothing is asked)
  -CertificateType Leaf|IntermediateCA   -OrganizationalUnit <department>
  -CommonName -CompanyId -Company -Email -Phone -ContactPerson -Address -City -State -Country -PostalCode
  -BusinessCategory <one of the four>  -JurisdictionCountry -JurisdictionState -JurisdictionLocality   (EV; the three jurisdiction values default to Country / State / City)
  -IanaPen <number>   -San <name,name,...>   -AddDevelopmentSAN
  -Purpose ServerAuth (default) | ClientAuth | ServerClientAuth | CodeSigning | EmailProtection
  -KeyType RSA (default) | ECDSA | MLDSA    -KeyBits 2048|3072|4096|8192    -Curve P-256|P-384|P-521    -MlDsa 44|65|87    -Digest SHA256|SHA384|SHA512
  -Name <text> (folder and file name, default the CN)   -OutDirectory <folder> (default .\csr-requests)   -OpenSslPath <openssl.exe>
  -NonInteractive   -Help

RESULT  (folder  csr-requests\<name>_<yyyyMMdd-HHmmss>\ )
  <name>.key   your private key - KEEP IT SECRET, never send it     <name>.csr   the request - send THIS one
  request-info.txt   what the request contains and which level it asks for     README.txt   what to do next

WHERE IT RUNS
  Windows 11 24H2 or newer (Home, Pro, Pro for Workstations, Education, Pro Education, Enterprise), Windows Server 2025 and Windows Server 2022 (Essentials,
  Standard, Datacenter). Refused (exit 5): Windows 10 and earlier, Windows 11 before 24H2, Windows Server before 2022 and the Chinese, Government, IoT,
  SE and Embedded editions. Linux with PowerShell: Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky 10+, Oracle Linux 10+, SLES 15+, openSUSE 15+.
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

# SIG # Begin signature block
# MIJENgYJKoZIhvcNAQcCoIJEJzCCRCMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCHc8ie1HLS0CS8
# UWrv0QZ5qeIk+MCKcktCiSEOkeFCJqCCPI4wggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphB
# cr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6p
# vF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHe
# HYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEd
# gkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjU
# jsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bR
# VFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeS
# LsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIV
# NSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL
# 6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2Zd
# SoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFU
# eEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# DQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/
# T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQ
# E7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9r
# EVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y
# 1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gx
# dEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3t
# y9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcy
# tL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEB
# YTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud
# /v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiS
# uEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZP
# ubdcMIIG7TCCBNWgAwIBAgIQCE/cM09+RU7bww+P+ZIYNTANBgkqhkiG9w0BAQsF
# ADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMB4XDTI2MDgwNTAwMDAwMFoXDTM3MTEwNDIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjYg
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALZ7pvLJ/s1K+NSbTGWz
# /TjGMPh8CQ6RucZCLv5anHzWJjF/NWJrFIhy24fcpKXlgRiky4WAawDfU3YP0BMx
# t9l3Dm5oCG5Z69AqEN1kgHg2epx+l+lZBcmJCcN0ASURML5uFIS80sZsDwO3BSkU
# xDjLJhBI+qiZP3aixAC/qEGLjsBNlLol9VZ7pfGEXiMlneJIC5/YKuizVzNFKZZE
# eoy/0B8Zm+nzKBgSWG52lCO1w+nCg6XpCtklTJXeIg283hw7TmmsZXR+SMbjbrEO
# vZ3fP2VxIgeR28Y90ZStd3F9VuA5RVynb/whITPAo9b75Zr4Ta6Mj3URm26QZYMn
# /FnbuTegcoRcFEZ9FOqM5T6MTdtr/n74lIT/ug0eeOzmZ6QTFg33otX+bFRsIolv
# ykE1jive4PuESaT8zzVeFWDAMDtozNgLctkGD1ZjkEyZtJrLl5ya0m5doH/ScpaZ
# CZVl6pNUOCybMc/kxC6EAmSJY24L0yYKD1Nkddsnb/ItVKi/2nXpQNMu1PT5prW8
# 3vV8d67WowuUs0HdY4H8AMLGvdL/WHEj3ZnqMqAQQP9u3Ai9t+5eQ02GDwy0ODjd
# zi0xlp70W+ow63/0++YDEX1M0iwgUHwbrJvfpklkZQvw3+kv3vUPItdwroczk9ic
# flf55W1zOEKAcJVAIXpcMCU9AgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0G
# A1UdDgQWBBQUyWOKMC7USvtulPPm40B+9ezN4jAfBgNVHSMEGDAWgBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEy
# NTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hB
# MjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQCNxTphHp1SCt+ZrAmAfn0oQLFr0mLywSLaDXQI
# ENoyKqxrFbJblzCVP/pkXmwXOdrOpWygLzlT12os5ipDCy35RBCg2UMeApEtrfGh
# z45F4Wt4WGdNdIbRWt3YTYJmpR+b7lr4d7Uwn+H600u4D7RnOGf8Wj4UNgAdZkfH
# hHv1mx9EVh71SJelcEN/oORSjXzdjfw1iZH9d8Nh/thn6hH23d+VsPAr6GAYyzSA
# 02nXD1nYLI7Ijmiv+xLCiYC41DSFYL3GhTiy0PxpawPtGRyaBVGzq+UiTfM8pD7K
# VyF5aQyWP4KhVGUUTnmm/RlYJoW3TiXA/+t0YcT2oRVBm3JETjajHug2AL+v5jht
# KVnd3D0rbHXEu27o+Q8p4sEWPMqKDB+qbceb6T/6WcwTwXmQ9lOCLLYcsQeSWmvK
# qzpAec9etE14jOQAzLKWdE3w/TCaKtLRaRT7LCkRYVnhA2D73FLje1O5b3HR5eHs
# 0NzU/+xX7NbEdcofy0W3Wdwd1XOqtlpg/JgwtKfZM5dqO94lbUveOiJBI+xZEbGR
# sMNbXmMREUTgu+Oca7Y73MPWcslIx2VhkSKSXjDbD6rgg39H5Mh7QfieAIjWagkJ
# Nt68Yfim6cjEzVSiLSeZfdkr5dtFPTW6jATlWJdYeeDRGCyatf8R1hSjzSvdN8yW
# QPT9gzCCCDgwggYgoAMCAQICEC/wnA/zwDdlYzgmYE7STJMwDQYJKoZIhvcNAQEL
# BQAwggEKMRMwEQYLKwYBBAGCNzwCAQMTAkVFMRowGAYDVQQFExFFRUFSSVJFRy4x
# NzM0NDEzMTELMAkGA1UEBhMCRUUxEDAOBgNVBAcMB1RhbGxpbm4xHDAaBgNVBAoM
# E0FnYW50cmEgSW5vdmF0aWYgT1UxGDAWBgNVBAsMD0ludGVybWVkaWF0ZS1DQTEl
# MCMGA1UEAwwcQWdhbnRyYSBFViBSU0EtNDA5NiBHMSBDQSBSNDEbMBkGA1UEKQwS
# Tmlja28gU2F0cmlhIFV0YW1hMSMwIQYJKoZIhvcNAQkBFhRuaWNrb0BuZXh0bWFu
# dHJhLmNvbTEXMBUGA1UEFAwOKCszNzIpNTMxOTQwMTkwHhcNMjYxMDE0MDczOTA1
# WhcNMjcxMTE1MDczOTA1WjBtMQswCQYDVQQGEwJFRTEQMA4GA1UECAwHVGFsbGlu
# bjEQMA4GA1UEBwwHVGFsbGlubjEcMBoGA1UECgwTQWdhbnRyYSBJbm92YXRpZiBP
# VTEcMBoGA1UEAwwTQWdhbnRyYSBJbm92YXRpZiBPVTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAKFbev2e6J9ybFSt0oH0hZdH2ahZh+jF6xMfvK46lEMw
# lE4Nut5Ac3FUmJoRpVwu4oCEUZkUFrHmcnJ22Ps5TRcNwlZhCCqEL9UbmGkrytUf
# Oan/LFExlGlZ0R/unwi4de/8XvVSMugRoi0PyI/CVl4hEMKBNB9qMRSQySSON2SH
# glcnVjACK7Fp7fu9I+x5uW3h55a36mMSXKiB1Xe8s9VuLX7Q8Jdsdhk0DcPatCBy
# MARQTHr04H7bqf3vU4aPewJ1/LcKlBpHWVpbla35R3V9pA5CrGkeAH4/V4fendI5
# f8V5zQml8u+UeEVQ4h+HM1lQk9HnZ+L8VNrw5yxGEW7arDVJOIhxXrzDUMJ7lKb+
# 6yNi5ou7NJ2FSzxG0AaOawvulVUEqGK+oblFbzl6AJQj6tFKkPYjbKNz9aRJHSUV
# G+OiOSCiTAPX8qaB0kqNgN9NYqRbnlfCwkq7BJ85m7p9AlnIDeDseCnwMMthPmja
# uqpg/cSN5wQStX0tTsXxJp1JROUz0dLuXjsPj7XI2iG9HjZEB5Cr/s28IfWeSQ0N
# P4SbEGimz7mFZlhUgY91vCWQWQdan391bNyYju+BxNPQ4UYh2DEseXzLAmWlsZi7
# b9qyuevaBBDCB5ixWri6LJgAvrWv4BwhoEeKLAKOeMrafeWO5hdzqPTUkl+Uxq4D
# AgMBAAGjggIzMIICLzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNV
# HSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU7UNGc/tauoRRQYNJYD7VrsCxaIMw
# HwYDVR0jBBgwFoAUfQqouJFjhFteE2U8Qs3fLP8iGj4wge8GA1UdIASB5zCB5DBH
# BgVngQwBATA+MDwGCCsGAQUFBwIBFjBodHRwczovL25leHRtYW50cmEuY29tL3Nl
# Y3VyaXR5L2NlcnRzL2V2LWNwcy5wZGYwSwYJKwYBBAGEjBgBMD4wPAYIKwYBBQUH
# AgEWMGh0dHBzOi8vbmV4dG1hbnRyYS5jb20vc2VjdXJpdHkvY2VydHMvZXYtY3Bz
# LnBkZjBMBgorBgEEAYSMGAEBMD4wPAYIKwYBBQUHAgEWMGh0dHBzOi8vbmV4dG1h
# bnRyYS5jb20vc2VjdXJpdHkvY2VydHMvZXYtY3BzLnBkZjBHBgNVHR8EQDA+MDyg
# OqA4hjZodHRwOi8vY3JsLm5leHRtYW50cmEuaW50ZXJuYWwvYWdhbnRyYS1xMS1l
# di1nMS1yNC5jcmwwfwYIKwYBBQUHAQEEczBxMCsGCCsGAQUFBzABhh9odHRwOi8v
# b2NzcC5uZXh0bWFudHJhLmludGVybmFsMEIGCCsGAQUFBzAChjZodHRwOi8vY3J0
# Lm5leHRtYW50cmEuaW50ZXJuYWwvYWdhbnRyYS1xMS1ldi1nMS1yNC5jcnQwDQYJ
# KoZIhvcNAQELBQADggIBAH2cMoiRHY4uw0dyP9ekla5Hy9fNnh7zdBqS72NatuJ+
# bxiicgKxcFCqRbVsnphgXHRXV+Lr8bhoNG46Ijq6HGVyuemy+6E8jg+CkT4qI0zI
# aScgExBFaVxRo6JmnT/vz2e1hY8fWm61jf0bBV3L6vr3xsfrCF64T7uKw4D5B1ju
# E0Tejsy4zSKObDA4PFASi7cK/5PksNj8A7ajnaOeIJVhqpFOoMQiaRwJ2ulSaSkC
# 5rJsSG29JyXZXXaVwB1rA0nuq8cpLJh77+xXXSJw7nVrlwf6wfflGORNYS3Hgujw
# cgKYCa+dWX6EE+7NS+qAbt40n6kPHqeExT6Z5XYwnE5gPyCHq87A4emQRrxlzaJq
# LX2P63LQMFdMrvjssKOfAEdgx5tbFKcYQDbmTMfCd079D2BHnEuA9nruiA96ItXM
# CEs9TSssy3IOkbzmm0LZlmhEMI4/LwFeHl1MaXfr4w+fw8eU0HQUqCrsS103pLXB
# 7FUsZmWbVVIY6bja6l1e88SG7hu5B84/FOGSakBbviM2bSQldoRxBxVVrVsAdXJu
# lKg7G9b6jRDf9a5cLepaVD+Bg9p5Ods+67SSS1xDcsfGZdof81/1PihnZSh/uOeN
# NI85/ORGq3QPd8IOtfL2FIEiIol1hQa6DkC4eK6BzVMFFdwWDKMQrojsz75JnqoE
# MIII0jCCBrqgAwIBAgIQIC8gOot0KY+b0mJbLp35GjANBgkqhkiG9w0BAQwFADCC
# AQ0xEzARBgsrBgEEAYI3PAIBAxMCRUUxGjAYBgNVBAUTEUVFQVJJUkVHLjE3MzQ0
# MTMxMQswCQYDVQQGEwJFRTEQMA4GA1UEBwwHVGFsbGlubjEcMBoGA1UECgwTQWdh
# bnRyYSBJbm92YXRpZiBPVTEXMBUGA1UECwwOUXVhZHJhbnQtUm9vdHMxKTAnBgNV
# BAMMIEFnYW50cmEgQ2xhc3NpYyBRMSBSb290IENBIEcxIFI0MRswGQYDVQQpDBJO
# aWNrbyBTYXRyaWEgVXRhbWExIzAhBgkqhkiG9w0BCQEWFG5pY2tvQG5leHRtYW50
# cmEuY29tMRcwFQYDVQQUDA4oKzM3Mik1MzE5NDAxOTAgFw0yNjEwMTMxMDUyNTFa
# GA8yMjc2MTAxMzEwNTI1MVowggEKMRMwEQYLKwYBBAGCNzwCAQMTAkVFMRowGAYD
# VQQFExFFRUFSSVJFRy4xNzM0NDEzMTELMAkGA1UEBhMCRUUxEDAOBgNVBAcMB1Rh
# bGxpbm4xHDAaBgNVBAoME0FnYW50cmEgSW5vdmF0aWYgT1UxGDAWBgNVBAsMD0lu
# dGVybWVkaWF0ZS1DQTElMCMGA1UEAwwcQWdhbnRyYSBFViBSU0EtNDA5NiBHMSBD
# QSBSNDEbMBkGA1UEKQwSTmlja28gU2F0cmlhIFV0YW1hMSMwIQYJKoZIhvcNAQkB
# FhRuaWNrb0BuZXh0bWFudHJhLmNvbTEXMBUGA1UEFAwOKCszNzIpNTMxOTQwMTkw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCl4u+x6WZUz26tMXEYzA4P
# 6fpSh7UhL8+JefHcpXT3A92BZQErechPq8AGINFux6DGbjex9XGoOd1P7In7uRqI
# y9OuHPt+QQHCEACSki4BcVjtAAcn3vDQZRDVFoB8JZEXJK1apBn8xajf44oqvMMK
# nQ0sUdGMAmyEEj0RkLe/cGdsd6B+7pzhGCMXS/B28++vZ1ypLWGknSpA3dUZh36P
# 1hzqzfG67MWOZ0XYF21MbNkr7zKe4ESmp9qO1lyZMrUvLLXPfPhtqlRJVEuG9dCb
# VkvPvNjvsK0IuWvntTk93xUa9ZvWy2r39TN6FVwmR/Aazddmr+V7r8fZH4yZJ1pj
# X2iAG7TglMu6Lv6FrVQAGeXTnqz2Io1/BL4JpESSv5or43C4ox2SSdFbh+VkU2vX
# /PE0LbV7eJn/7y2VG7szmI9yt+ynlkhnuY6GjFYB2vTqjUkvxKTTms1v/PbCwuSu
# wsGAjG27Gq0hJIQcl6wVp3lWZGvCT0lwZkHK5uD+1mAoP4i26rZYpyRK7JuXE+ZE
# 2Wk/DFacYWEmksKbRgY+nRis958f5y7S7t1qg63PjMLnAfs/epZ0KIqvlhdMl0a1
# nCwGVt469geMBHCjVQ02PqAV30l+uzhBvex/YWwbkUpfS4JCyi5ApyTpmQoRDim6
# LadwqCD/jmySFWUGZX8JtQIDAQABo4ICKTCCAiUwEgYDVR0TAQH/BAgwBgEB/wIB
# ADAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFH0KqLiRY4RbXhNlPELN3yz/Iho+
# MB8GA1UdIwQYMBaAFChduOZZ2PzKwCx0DZ2gnnfSdBmqMIHvBgNVHSAEgecwgeQw
# RwYFZ4EMAQEwPjA8BggrBgEFBQcCARYwaHR0cHM6Ly9uZXh0bWFudHJhLmNvbS9z
# ZWN1cml0eS9jZXJ0cy9ldi1jcHMucGRmMEsGCSsGAQQBhIwYATA+MDwGCCsGAQUF
# BwIBFjBodHRwczovL25leHRtYW50cmEuY29tL3NlY3VyaXR5L2NlcnRzL2V2LWNw
# cy5wZGYwTAYKKwYBBAGEjBgBATA+MDwGCCsGAQUFBwIBFjBodHRwczovL25leHRt
# YW50cmEuY29tL3NlY3VyaXR5L2NlcnRzL2V2LWNwcy5wZGYwSQYDVR0fBEIwQDA+
# oDygOoY4aHR0cDovL2NybC5uZXh0bWFudHJhLmludGVybmFsL2FnYW50cmEtcTEt
# cm9vdC1nMS1yNC5jcmwwgYEGCCsGAQUFBwEBBHUwczArBggrBgEFBQcwAYYfaHR0
# cDovL29jc3AubmV4dG1hbnRyYS5pbnRlcm5hbDBEBggrBgEFBQcwAoY4aHR0cDov
# L2NydC5uZXh0bWFudHJhLmludGVybmFsL2FnYW50cmEtcTEtcm9vdC1nMS1yNC5j
# cnQwDQYJKoZIhvcNAQEMBQADggIBAJP1SFc2V5gsVrmW7OjmxaRY84C1uGGiYQOO
# yZZFp1fV0Fc7LdJPVt0CN3/aWFvcIudhkW9Ks3XB8UMgfx0yIxoCeBmY8DgZ0IPx
# OJWSVKJeMYomZ8wnAJlKwWh3xqYQyRXiUPuTREMbIYKWPap7NLWjqOSY04OKeG0P
# gsTwJL0R2s6UsBC/Rtsd0nEC8WGAcwHECNBn8mGzSKXGqm/jh//PGMf8m1O8xPcG
# 6XkUUxUfp4GzjQODqUTvHnhSgqWr1oBLbGi4B/9lcyAsGo8qmBT5ME4GF1eZGiDn
# M3GyRQZsMLgZcw+JvjDjIrBSWGjPpjN/VqKnNJw9wc/FnuVrt41cxKgMJXA4UhvR
# bsAhPgEPa1Do7mZRZHCI+GDt4UNQd3AF0nPQzO+k1fkudLxnRdJsKcVUnQPBqdmK
# axEdSw7e8SsgB1BGiOuTk0umzp0QsBVGG3ju5SbJbV+zfDcr2a4LSe35zSY+0nqJ
# g/SNjgjCfUT9/Lvquzl4WyNwh5brS90iH1yAuh8g9owGCV10BfWKA8rZ1xhqaVyf
# vbzoVmMQlNCDsWo58T6W41guIYRCrTG3SvRmA8GJVdI1/ghqp3jHJrWOvSIVyNnq
# n6m2b1S2tD+nlX+/ZzGayfXqXD850DriO/POfYV7wokK/h/p1IFrFdErYEl31DkI
# KUl/E8yQMIIMGDCCCACgAwIBAgIQeiwJ3fIGYU9JY1Q0EQG5zTANBgkqhkiG9w0B
# AQ0FADCCAQcxEzARBgsrBgEEAYI3PAIBAxMCRUUxGjAYBgNVBAUTEUVFQVJJUkVH
# LjE3MzQ0MTMxMQswCQYDVQQGEwJFRTEQMA4GA1UEBwwHVGFsbGlubjEcMBoGA1UE
# CgwTQWdhbnRyYSBJbm92YXRpZiBPVTEUMBIGA1UECwwLVHJhY2stUm9vdHMxJjAk
# BgNVBAMMHUFnYW50cmEgQ2xhc3NpYyBSb290IENBIEcxIFI0MRswGQYDVQQpDBJO
# aWNrbyBTYXRyaWEgVXRhbWExIzAhBgkqhkiG9w0BCQEWFG5pY2tvQG5leHRtYW50
# cmEuY29tMRcwFQYDVQQUDA4oKzM3Mik1MzE5NDAxOTAgFw0yNjEwMTMxMDUyNDla
# GA8yNDI2MTAxMzEwNTI0OVowggENMRMwEQYLKwYBBAGCNzwCAQMTAkVFMRowGAYD
# VQQFExFFRUFSSVJFRy4xNzM0NDEzMTELMAkGA1UEBhMCRUUxEDAOBgNVBAcMB1Rh
# bGxpbm4xHDAaBgNVBAoME0FnYW50cmEgSW5vdmF0aWYgT1UxFzAVBgNVBAsMDlF1
# YWRyYW50LVJvb3RzMSkwJwYDVQQDDCBBZ2FudHJhIENsYXNzaWMgUTEgUm9vdCBD
# QSBHMSBSNDEbMBkGA1UEKQwSTmlja28gU2F0cmlhIFV0YW1hMSMwIQYJKoZIhvcN
# AQkBFhRuaWNrb0BuZXh0bWFudHJhLmNvbTEXMBUGA1UEFAwOKCszNzIpNTMxOTQw
# MTkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCsKWvO2g37z5Ot77n0
# 08rLq1CO28p9gubOzRJVNTfc91xNYwEKuHedRT1zeKSzwY5+fUhxUR5Zzvroxf+k
# BFX9xO2pvNK2iXvV6Wer3yh6N+zIo9C486HNcU05f71o6d2qPVVhmmJbvrngqrYF
# tbig/S98Htt3LeoQU1DmJuwlst7ZKaj3XT0NxKVngUvGKA9AM/iULfGcsv2pML2M
# icK/K1TBK0zSAvbgZggebWx5ft3EZlsMfF9MKeYifbk0b8rZDD/dmcUczNm1F82n
# 8Jg9J2E7LFRi/HGd1515nrj+FO2UL5mbCeVfBzzPegE5VhyNCessKKd7kt6Mk/qZ
# inL3THincHs64Qxr+8KOeH/v+qdpSq1tDgy2JOfCwtr/7eWNfav7orYtFI2PlH8N
# Szk0VJW2Drndnf0wZItaRFdZaJUffPWr+6eB8EhBwUkzIrPCnTSTIKUD8IpajJzy
# 0iyVpVsS4b0KiAXlKJ3hDyQN9gwVS1CSndAIK7Pe/jyL6aA93wpb/0b1RzZrBdmp
# q+ZNon9PuTIBwGDcRYQKSvh34XOMU5h7Xbzb5MrlwZ6Is/+VZT0N/dMPffEOx+PM
# vJRUA2r945C5JZ2qL1QC7RLiFibLsPZqA6mMXwxieLOxE8NNJOjW4ExHqGzAAMzM
# GwyRhpEUmX/5/wHOQLEGCwMD8QIDAQABo4IDcjCCA24wEgYDVR0TAQH/BAgwBgEB
# /wIBATAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFChduOZZ2PzKwCx0DZ2gnnfS
# dBmqMB8GA1UdIwQYMBaAFND4vlby6dM1xkldSNF4LXDh4+3VMIICLQYDVR0gBIIC
# JDCCAiAwRwYFZ4EMAQEwPjA8BggrBgEFBQcCARYwaHR0cHM6Ly9uZXh0bWFudHJh
# LmNvbS9zZWN1cml0eS9jZXJ0cy9ldi1jcHMucGRmMD0GBmeBDAECAjAzMDEGCCsG
# AQUFBwIBFiVodHRwczovL25leHRtYW50cmEuY29tL3NlY3VyaXR5L2NlcnRzMD0G
# BmeBDAECATAzMDEGCCsGAQUFBwIBFiVodHRwczovL25leHRtYW50cmEuY29tL3Nl
# Y3VyaXR5L2NlcnRzMEAGCSsGAQQBhIwYATAzMDEGCCsGAQUFBwIBFiVodHRwczov
# L25leHRtYW50cmEuY29tL3NlY3VyaXR5L2NlcnRzMEwGCisGAQQBhIwYAQEwPjA8
# BggrBgEFBQcCARYwaHR0cHM6Ly9uZXh0bWFudHJhLmNvbS9zZWN1cml0eS9jZXJ0
# cy9ldi1jcHMucGRmMEEGCisGAQQBhIwYAQIwMzAxBggrBgEFBQcCARYlaHR0cHM6
# Ly9uZXh0bWFudHJhLmNvbS9zZWN1cml0eS9jZXJ0czBBBgorBgEEAYSMGAEDMDMw
# MQYIKwYBBQUHAgEWJWh0dHBzOi8vbmV4dG1hbnRyYS5jb20vc2VjdXJpdHkvY2Vy
# dHMwQQYKKwYBBAGEjBgBBTAzMDEGCCsGAQUFBwIBFiVodHRwczovL25leHRtYW50
# cmEuY29tL3NlY3VyaXR5L2NlcnRzME4GA1UdHwRHMEUwQ6BBoD+GPWh0dHA6Ly9j
# cmwubmV4dG1hbnRyYS5pbnRlcm5hbC9hZ2FudHJhLWNsYXNzaWMtcm9vdC1nMS1y
# NC5jcmwwgYYGCCsGAQUFBwEBBHoweDArBggrBgEFBQcwAYYfaHR0cDovL29jc3Au
# bmV4dG1hbnRyYS5pbnRlcm5hbDBJBggrBgEFBQcwAoY9aHR0cDovL2NydC5uZXh0
# bWFudHJhLmludGVybmFsL2FnYW50cmEtY2xhc3NpYy1yb290LWcxLXI0LmNydDAN
# BgkqhkiG9w0BAQ0FAAOCBAEAT4ELi1pdD2mGhC8NO6S/1ViPT+t5g7OZj+/j4bxS
# mLDd5v6lUXulMxb1Ie3Wd3HO4BdDslWP3f2MA4BEtmfDYZmUspF2hiyynCZlDC3A
# PJz71xIybLl7m3T41SmsMHTVgtqrACuUmez91cjFec5eOiFr84mHqwz9YALVmJ1o
# fvpahYeNs9ZUh3XsRUuyvPrasTdFALOczNhe3HG4fr4ExkIiDGBFs772Vn5/UOTK
# 8sMC4uj1cZUcw4Ibs69szUqitsyaztv4vIKOutLyWOdgZwuNUsUWfy5+HwvilfUM
# 3lBB7IwmVxF2q2v2Nq2+4z8F0CFcVi+7Z3yNywVTP1xfJTawPTVxUpdYelCu/8Ov
# lffJOFYDfO2/MbglrYyxcPkw2x24zkHSSUYW247zryjbY2rYQsdNeChRkCl0JN7A
# z90dSAvfkZVnRipu13swu9/FMaZwJ8aI31Vc81zfPpq0lLXkIKtMppU5U8F4GaVa
# YMd9t72aJpb6Ol2z+idCt8Hpd/D5dm+LjfLUK/OjeY31lew7rNzRsvSh2XmELdsK
# FkdGyc/mq0bxEAJOT6UP3URh0yex/iuoamgEeHY3ec1WoDMdYjIlMKL7Fzy+sTLf
# jhkOHU3774MaEtKbkr+dFzAroOVBhoQCnv4kmbs+gZMr4ods1lxIbZ0BEoyN+NXQ
# N7kjgtAFdUBVKwfGMmfyt8LIS4CcRW5atRQO74Z3PrQuz0IhhYydQI3FAtqCbaN2
# sHq1EKI82xEnI8+HcK808wN1pVB/UifsdeA7JKaZ8tEBW4d9Kd9W8UiuK1FPonfp
# +tuaQRT4lFfFOjpJADxQBLZNBlB4DeTkrkHfBTFdE+yJQWF8IDJ/zSR2ZLT8orEj
# ONHDKDkEMOKgfTWBcydZJ0cMyZJg6o+gN5TeMPJB6TTONtDW6nFAv8l4IMXuNU5L
# r6OfCL6b33yXgvSver53MWtEpn4UyHAlKJvExR44jqVfzvoUSDLX4kH72ywJRHIq
# qp/SgSkOK3tD2kp5DIwHDcyp3AyYPFyGaJ8dEIgN6zCHHDvlwT+vjXuayH/bVk0m
# LLc9gNVdEUL3d66Si6tdwARoE8WQ7mHj0TJUhEolniTkwjIEppmABlM0sodn9s+T
# RauFsfY1AEE1ANt5LKnYXOjHLbGB+gtpjQqKHiXVKh2wVzl0nIyammnj8waaGVqj
# LozIEbKsacULJbsYg9oo5GHfECYw63ICVIHF6tFPsx+xxMOQ6dSy9YUXUUNzhQRM
# wXeIv+QrXUD5HdR0auoPyT4SSw0+LQdy1Da+nVqYjWDpiRaNfDYEwn7dsMICjSos
# X+XTG2gNIqw1Po2K1xvNrLbaEWcgDuoPlCBUOSqVw029RDCCDCIwgggKoAMCAQIC
# EAJihrjI0/Vk+DEfNdd/pkQwDQYJKoZIhvcNAQENBQAwgf4xEzARBgsrBgEEAYI3
# PAIBAxMCRUUxGjAYBgNVBAUTEUVFQVJJUkVHLjE3MzQ0MTMxMQswCQYDVQQGEwJF
# RTEQMA4GA1UEBwwHVGFsbGlubjEcMBoGA1UECgwTQWdhbnRyYSBJbm92YXRpZiBP
# VTETMBEGA1UECwwKUm9vdC1DZXJ0czEeMBwGA1UEAwwVQWdhbnRyYSBSb290IENB
# IEcxIFI0MRswGQYDVQQpDBJOaWNrbyBTYXRyaWEgVXRhbWExIzAhBgkqhkiG9w0B
# CQEWFG5pY2tvQG5leHRtYW50cmEuY29tMRcwFQYDVQQUDA4oKzM3Mik1MzE5NDAx
# OTAgFw0yNjEwMTMxMDUyNDhaGA8yNTI2MTAxMzEwNTI0OFowggEHMRMwEQYLKwYB
# BAGCNzwCAQMTAkVFMRowGAYDVQQFExFFRUFSSVJFRy4xNzM0NDEzMTELMAkGA1UE
# BhMCRUUxEDAOBgNVBAcMB1RhbGxpbm4xHDAaBgNVBAoME0FnYW50cmEgSW5vdmF0
# aWYgT1UxFDASBgNVBAsMC1RyYWNrLVJvb3RzMSYwJAYDVQQDDB1BZ2FudHJhIENs
# YXNzaWMgUm9vdCBDQSBHMSBSNDEbMBkGA1UEKQwSTmlja28gU2F0cmlhIFV0YW1h
# MSMwIQYJKoZIhvcNAQkBFhRuaWNrb0BuZXh0bWFudHJhLmNvbTEXMBUGA1UEFAwO
# KCszNzIpNTMxOTQwMTkwggQiMA0GCSqGSIb3DQEBAQUAA4IEDwAwggQKAoIEAQCy
# Drs2SqSfTbVrHWN2Zfk75iIxPQ/qOxAD/Xorcgygpmq8mpLDOY1Otwbi5v7mOQ/D
# 8qNeMp4vsqz2TCFJcQAA6OupMDeNVAlUSagEecwRwfpgrsRg4gVU9QpepX2TpibM
# bmMFWmQsVHI2A/Jhu8YtdFAA+gXy0pw5zOWPNpS4M0AnLqqmUgLqbOYX4IHkTBr/
# K95Sd09oMgOBYIeJjuW+Eg/ythvEseIzitwWGuKibRLEp9LrBmE2QAEByE2SNxor
# ZEi0q0Wa913VmGEpBPbc6qLNzYRndKeZmAOJwGptmtdaPlNllQowf3gAac4TtkGk
# nKwkphFofsEKYTlgMZV49UZzr8PJnDtFYk44zjuwdy3i1MfYWnmVbWrwACLlU70Z
# SBbkEFPQ9O9ptg9OOSLu5UtxIz8hpG/Ng03b33irY1nq+8YrBTTOg/MazV2AH8VO
# d+F/bHAKSCWeZ+PGOeZ+27XFAAlhJdAuNKqfqc8InGQvOyal7CtagWuFHZ9WAJ/O
# 2ca8wSnqQ3WbyvOD6LZnKZfkrd2EjnCP8O3A2FvCvPwDChUR3TiMK+0zJ0qn0FrK
# kxy2SbzI44EjICESdzEgnc6PKTIGuZummQWBKlBSTuhrWXeOA6AhhSdUCkqgmMxQ
# gE6hbCRF2bBWT+S7gW9DmFHuP1UE8RZ8Bpe87YWXk5rwAmgMsYIkK61dQCa4NLPL
# 6Mdg8JkjV4mlW51aRObYVi0FppkTZeYHGjicFxKqCAHMGvqYn8HRHrUIg7vS13uI
# pnuVYXI2Kp+F0cnJTDO2nc1gBj+y0Sb4sBiBVYXidnfj/pFQYpZBDfX8WpTOk9tN
# hanLnj+SMlkhiAXP8sxgGh2Qp24rlJLXocC8Kvq0kwRdI0o08KuchAsRY20fPvoN
# OUmAZ37KIojyRrDJZb+hg8iOU7MYLScnopdnZBmtWQZ34uELDC/y6Ls/XbIg/mNK
# vBwa4eZiYPELEl5vVR7XxA7s9k0WNzux8qCdLSiiqJDg4gvz9/qVSD5MMrYvgT96
# 2v9plk8/bLoP0maHM6WnyAgmiDIQF3Yr+cW/sqxOsty6nyeSvl/Vjzb9d99azw1y
# 0cwIWakyfqVufAG2Vmu3RNOkt43UTwlGNNxpT1ySbrwXx9WguNH6PddCG33OCVnl
# kbQkGq3xn1wzs/okWU3wwl88haATQSTozQDOUb1Ex4Q9Hj9RJr49rKPmXTJcxDbf
# kXcHWYBS2yVZuMldsqI1Uz8UQ8wXCu0TbGjgUAypJn4sC7wHsIRYOcCl3RWO9d8t
# LsS8a7dl+DSpIVNgHIfMLspelB7VtcklPD2fS3T1oWDQDiAMPCZ7y+urlLrrEVVB
# KkPlvV34RRtJS6ui76rVAgMBAAGjggGMMIIBiDASBgNVHRMBAf8ECDAGAQH/AgEC
# MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQU0Pi+VvLp0zXGSV1I0XgtcOHj7dUw
# HwYDVR0jBBgwFoAUbJ7gqnlXpySXpKpJQSdq4xxxID8wWgYDVR0gBFMwUTAGBgRV
# HSAAMEcGBWeBDAEBMD4wPAYIKwYBBQUHAgEWMGh0dHBzOi8vbmV4dG1hbnRyYS5j
# b20vc2VjdXJpdHkvY2VydHMvZXYtY3BzLnBkZjBGBgNVHR8EPzA9MDugOaA3hjVo
# dHRwOi8vY3JsLm5leHRtYW50cmEuaW50ZXJuYWwvYWdhbnRyYS1yb290LWcxLXI0
# LmNybDB+BggrBgEFBQcBAQRyMHAwKwYIKwYBBQUHMAGGH2h0dHA6Ly9vY3NwLm5l
# eHRtYW50cmEuaW50ZXJuYWwwQQYIKwYBBQUHMAKGNWh0dHA6Ly9jcnQubmV4dG1h
# bnRyYS5pbnRlcm5hbC9hZ2FudHJhLXJvb3QtZzEtcjQuY3J0MA0GCSqGSIb3DQEB
# DQUAA4IEAQCMwFeVD4MJdfiH+XWe6pZeY82sBaj0otXM+ZPT8ayKKV9E9oPbW8JE
# m3TkdmIPAckQf7xcxLbKwfq3UHeH/e+ijl6vYOzD3nK1YygvL0YZrOZQoH13HW2t
# LQqi0KxfusBbniMX5LHRpJaHv8sLc/vhV01dLU0xijT9neInYEItaOrYG85msi67
# /LLYMY5Ld5/U/GbIx+kaUC1m0K+OXXWh089vAYSYoFyhKqGZaQhP42nn+X0jb02K
# dwDV4Hu/dloXbrSSG2owHnebtQbV19jmQmj8S4WQ5LGfq4DnU/j0FqxRe7KlJ1Gy
# /dkBUp0YI9TXnvcFcjLNHuRFE9ErE70/2R6TbzHVlqBJJjHzbpSwGY2Q9SvhG/4D
# eMDMu1xUd58Nn2Id2eGq56zDccH+RQwuDhFdQZvBzryhIsv8yqP7+kaD95BG1gpJ
# fxykc+IPQuPvNCxs+K2/rMO1ZcM9WYk7MyNYB+QLaT7QcFXW1i2ySq9NODvY2yuE
# qm4FLN/5Kz2BPtfHHPco0yRT2V2FHAS53r1WYqxICP3+qFJeuD60XjebDFt+J4V6
# /QN7L01rysLAbPEjbTR90fA9QVZ8Bo5BvPBdb5dPdawLl/Uw2EQQqAm3YVsCKmNe
# /dTuX0/zqrrlzqNN1YVHk0ZbWRrFmC/cWk2cHU02XrXB+Oo11FrCst6H98r5WaXI
# ahIeXdmL1X/cEh9F25Ltada7BVLSk0mZmRjX13WwUmwRQwT5p1uO2cMP7hO/ZBTp
# OOAsq6fPM6uIUhYQ1R4lYQ/L/6iXlFn97zsjRRGR5KVcekVqzcrp8McouLuYLTPa
# XtxQS9T8WnJictY7Nbaa+UcwdOaTsYnyJnsbigW1aAioR9H7+POpN2cdgvGqF8T5
# Fd6c9GW4e3AXDJUfuh1yprV2Nf5mBucBPRWtsj+DHoE1Ll7Y9iqhbuilRsjedt3a
# PVOwc3mdlU+UuC/QdJAA1wsTBBYzc6rhdid2AvJ9nA7PvBBv/x6gCDX1TuuYiNqU
# vPc2IXOLqoNa4mmq+Abq4QbmTJDcpOkzdrS54Z8VFxp6x5e59eD3ocC6Z7pu3s4B
# Nc02+TNCSbCUlT26cdCYGykDzyRp/ElJggSNjuYqr9T03+gOTjnDBheU9kTKoXXV
# V8+CZsOx40OuOQyCU+m8NlxI4QHNpbsekuIdVFKRoOTIb+zGJYWhIXs2RtkVg+bh
# FxMiveoY5IhWpL+fvXFdet0rPdJM0rOiKwYOuyCME52fCarfKb6JqN1l6Ittw9UY
# zPVI1UatO1Ar4Sz/xFo7LFFa3j30qz7iy2tsWqODD5qoKYy4Nbkxa5YmQ0oSaV94
# 4VDVMUObQJ4OgHTo7jip9UEaZ+eLQAtJMYIG/jCCBvoCAQEwggEgMIIBCjETMBEG
# CysGAQQBgjc8AgEDEwJFRTEaMBgGA1UEBRMRRUVBUklSRUcuMTczNDQxMzExCzAJ
# BgNVBAYTAkVFMRAwDgYDVQQHDAdUYWxsaW5uMRwwGgYDVQQKDBNBZ2FudHJhIElu
# b3ZhdGlmIE9VMRgwFgYDVQQLDA9JbnRlcm1lZGlhdGUtQ0ExJTAjBgNVBAMMHEFn
# YW50cmEgRVYgUlNBLTQwOTYgRzEgQ0EgUjQxGzAZBgNVBCkMEk5pY2tvIFNhdHJp
# YSBVdGFtYTEjMCEGCSqGSIb3DQEJARYUbmlja29AbmV4dG1hbnRyYS5jb20xFzAV
# BgNVBBQMDigrMzcyKTUzMTk0MDE5AhAv8JwP88A3ZWM4JmBO0kyTMA0GCWCGSAFl
# AwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkD
# MQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJ
# KoZIhvcNAQkEMSIEIBYTrkUEUE12t2tj9KymQnI6w8iq/zrbkUGTma0Coyr2MA0G
# CSqGSIb3DQEBAQUABIICABILTJI3E/q06G4gCGXp9+bis342NdIb3nSNeWYxVfGm
# CSOM1ox7tHr4lGdiDlYCss76cU5nhVVWbwK4IKq/YC0S3Ts9vZYHL22j4L3ynaVP
# ssF32dm1FBOZPn6dmk7JoZXF0UAajdwGfIh6F4GeJMrVcrAoq48F6x01pPNNyqca
# vn0k1iUc3Nsz5LaAdCnK7G/bhI/UgDBWo1ADTu6LhYbCbcundodvIZtf3LXKVG1S
# ZHaoXfkP1iZE5PMkDgOxt3SOLOzAvbuBBuYLcbxbNwZU5L4DPq1EfVE7PuBkSnz3
# OCUO3QUpw7mmI+LW/L1FXO5GHngSHsBF+y5KMn/Nl1Hxbk60Mz+GxQx5JnqUcG2R
# LECNgev3TbXDZ/PEnj4koLF0KpB70hdg8X+EyKjOpy+mSupHVpkSvi4YlYitIvRM
# UEzcZCKwARv2JVW0e0dHQvoEyBm246gRKZJeOMjJ8pN2aqbFZ7OKzbbsz1uE7xgf
# AJNgED3XXa8IC02Q+u/dz7gpgNEsw6x/AqLBg11b7LVeY8NNlYEtcLoaODd/9afK
# 5DQZ2++u60kxKNvMfepUS+ABIea0VBxiPILddHDI35MPL8GceZr1SJGLGYTrO9za
# ZzlYDULIlI6Sae1e4WrgizOeL7g8/glO+l9b8DSLsgF6gZsWrULA7qcNdKYafC2K
# oYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVz
# dGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCE/c
# M09+RU7bww+P+ZIYNTANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkq
# hkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MTAxNDA3NDc1OFowLwYJKoZIhvcN
# AQkEMSIEIC/x3k3PXD+Hh7JfG8YOaPnjDfyvd6s76npElxEbRfdwMA0GCSqGSIb3
# DQEBAQUABIICAJCm8pxDQ9DOk6McrMTMGBtgm3CqOW8Ynt6OGZpH6H9B8MxeGWFf
# goOKTw/mGrPkUpiy1W8bHUzgWwlSnNQDhN3RdAviflxBVtc+0RAe/OyHzTVOZl3p
# eq2k7nP4aKuNPHa9AWd1Voavzo0otscrZwu+nnJNZMMJiuqj5tSQUnVXApT1z9Tb
# r6eXpmYmdgcxpdSyhhky2fmU1Ogkwg/WBweTTh69Y9jcmAkqL8lz/PxyN6wl4KKk
# Q2VyT3PkF/f0LOavBg1tqwQyO20CqdBquVKTwKEWPhJAo4iuyQfjS1NEigVtZo7m
# W7Y3s9K2gVeRq/QVqvPXm94F0TN12N/KcFzRWsaRjZtaxDwQCQgdadeczDDxFOL3
# FPugX1ZPp0luDTFVvIqgafQedhisaIiPwFv16lf3XZg1hp0r5PFpJUUvBf4T1lPh
# 36yUTtZQyDGhoJ6fTd8aklZ5ULtwSk53Q2PgNIqDE3yI/FEXsCBGMwjNxuK7ctvc
# G/lH7bwpWEaPF9K8rlxGmsoo2g5B9TJETLBmzvNSMZJGlAMdYNurxsvnG+f796wv
# unwYfTgDaoPw5ZTe8H41QEnHV4rB6P8j/O+iIGJ9p9aXLwH8AMqABQY3xwM+nVQB
# lphK60LRoWtD9IE1q1cQwV8hSn4NN/ujfC5YcHYkAlJnLa60sb0bjiO9
# SIG # End signature block
