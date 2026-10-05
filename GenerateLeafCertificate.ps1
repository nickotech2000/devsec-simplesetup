#requires -Version 7.0
# ============================================================
# GenerateLeafCertificate.ps1
#
# Standalone Windows Local PKI EV Leaf Certificate Generator
#
# Author  : Nicko Satria Utama
# Company : Agantra Inovatif OÜ (NextMantra)
# Email   : nicko@nextmantra.com
#
# Run  .\GenerateLeafCertificate.ps1 -Help  for every parameter
# and examples.
#
# Every certificate is an EV certificate:
#   - EV subject (businessCategory, jurisdictionC, serialNumber, C, L,
#     O, OU, CN) + contact name / e-mail / phone, from ev_pki.cnf
#   - EV certificate policy (2.23.140.1.1; 2.23.140.1.3 for code signing)
#   - CA:FALSE, SAN, CRL distribution points, OCSP and CA Issuers
#   - at most 398 days
#   - wildcard names ARE allowed (private / lab PKI, not EV-compliant
#     for public use)
#
# One certificate (one file set) per EKU:
#   TLS EV certificate (serverAuth + clientAuth)   <name>.*
#   codeSigning                                    <name>-codesigning.*
#   emailProtection / timeStamping / smartCardLogon / ipsecIKE /
#   ipsecEndSystem / ipsecTunnel / ipsecUser / msSGC / nsSGC
#                                                  <name>-<eku>.*
#   File set: .key .pub .csr .crt -fullchain.crt .pfx .txt
#
# Key rules:
#   RSA (default) 2048 / 3072 / 4096 / 8192, or ECC P-256 / P-384 / P-521
#   Code signing is always RSA, at least 4096 bits
#   A missing or too small -Bit (for example 1024) is raised
#
# IMPORTANT:
#   This is a PRIVATE PKI. It is NOT a publicly trusted EV certificate.
#   Chrome / Edge show "Issued to: <company>" only for EV certificates
#   that chain to a root in the browser's built-in EV list, so a private
#   root can never trigger that line. The company name is visible under
#   "Show certificate".
#
# Example:
#   .\GenerateLeafCertificate.ps1 -Domain nextmantra.com -AddDevelopmentSAN -Force
#
# ============================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# GLOBAL CONFIGURATION
# ============================================================

$ScriptRoot = if ($PSScriptRoot) {
    $PSScriptRoot
}
else {
    Split-Path -Parent $MyInvocation.MyCommand.Path
}

$ProjectRoot = $ScriptRoot

$OpenSSL = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'

if (-not (Test-Path -LiteralPath $OpenSSL -PathType Leaf)) {
    $FoundOpenSSL = Get-Command 'openssl.exe', 'openssl' -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if ($null -ne $FoundOpenSSL) {
        $OpenSSL = $FoundOpenSSL.Source
    }
}

$ConfigFile = Join-Path $ProjectRoot 'ev_pki.cnf'

$ProfileModule = Join-Path (Join-Path $ProjectRoot 'scripts') '03_RuntimeConfig.ps1'

$PKIRoot = Join-Path $ProjectRoot 'pki'

$RootCertificate = Join-Path $PKIRoot 'root/root.crt'

$IntermediateCertificate = Join-Path $PKIRoot 'intermediate/intermediate.crt'

$IntermediatePrivateKey = Join-Path $PKIRoot 'intermediate/intermediate.key'

$LeafRoot = Join-Path $ProjectRoot 'leafcerts'

$TempRoot = Join-Path $LeafRoot '_temp'

# Replaced by -AddPkiContentPath. Documented in -Help.
$PkiContentPath = ''

# EV Guidelines: at most 398 days.
$EvMaxDays = 398

$EvTlsPolicyOid = '2.23.140.1.1'

$EvCodeSigningPolicyOid = '2.23.140.1.3'

# ============================================================
# EKU CATALOG
#
#   Key      : name accepted by -Eku
#   Slug     : file-name suffix (<name>-<slug>.crt); empty = TLS
#   Oids     : EKU values written to the certificate
#   KeyUsageRsa / KeyUsageEcc : keyUsage for the key type
#   Critical : EKU extension is marked critical
# ============================================================

$EkuCatalog = [ordered]@{

    'tls' = @{
        Label = 'TLS server + client authentication'
        Slug = ''
        Oids = @('serverAuth', 'clientAuth')
        Check = @('1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2')
        KeyUsageRsa = 'digitalSignature,keyEncipherment'
        KeyUsageEcc = 'digitalSignature'
        Critical = $false
        Policy = $EvTlsPolicyOid
    }

    'codesigning' = @{
        Label = 'Code signing'
        Slug = 'codesigning'
        Oids = @('codeSigning')
        Check = @('1.3.6.1.5.5.7.3.3')
        KeyUsageRsa = 'digitalSignature'
        KeyUsageEcc = 'digitalSignature'
        Critical = $false
        Policy = $EvCodeSigningPolicyOid
    }

    'emailprotection' = @{
        Label = 'Email protection (S/MIME)'
        Slug = 'emailprotection'
        Oids = @('emailProtection')
        Check = @('1.3.6.1.5.5.7.3.4')
        KeyUsageRsa = 'digitalSignature,nonRepudiation,keyEncipherment'
        KeyUsageEcc = 'digitalSignature,nonRepudiation,keyAgreement'
        Critical = $false
        Policy = $EvTlsPolicyOid
    }

    'timestamping' = @{
        Label = 'Time stamping'
        Slug = 'timestamping'
        Oids = @('timeStamping')
        Check = @('1.3.6.1.5.5.7.3.8')
        KeyUsageRsa = 'digitalSignature,nonRepudiation'
        KeyUsageEcc = 'digitalSignature,nonRepudiation'
        Critical = $true
        Policy = $EvTlsPolicyOid
    }

    'smartcardlogon' = @{
        Label = 'Microsoft Smart Card Logon'
        Slug = 'smartcardlogon'
        Oids = @('1.3.6.1.4.1.311.20.2.2')
        Check = @('1.3.6.1.4.1.311.20.2.2')
        KeyUsageRsa = 'digitalSignature,keyEncipherment'
        KeyUsageEcc = 'digitalSignature'
        Critical = $false
        Policy = $EvTlsPolicyOid
    }

    'ipsecike' = @{
        Label = 'IPsec IKE'
        Slug = 'ipsecike'
        Oids = @('1.3.6.1.5.5.7.3.17')
        Check = @('1.3.6.1.5.5.7.3.17')
        KeyUsageRsa = 'digitalSignature,keyEncipherment'
        KeyUsageEcc = 'digitalSignature'
        Critical = $false
        Policy = $EvTlsPolicyOid
    }

    'ipsecendsystem' = @{
        Label = 'IPsec End System'
        Slug = 'ipsecendsystem'
        Oids = @('1.3.6.1.5.5.7.3.5')
        Check = @('1.3.6.1.5.5.7.3.5')
        KeyUsageRsa = 'digitalSignature,keyEncipherment'
        KeyUsageEcc = 'digitalSignature'
        Critical = $false
        Policy = $EvTlsPolicyOid
    }

    'ipsectunnel' = @{
        Label = 'IPsec Tunnel'
        Slug = 'ipsectunnel'
        Oids = @('1.3.6.1.5.5.7.3.6')
        Check = @('1.3.6.1.5.5.7.3.6')
        KeyUsageRsa = 'digitalSignature,keyEncipherment'
        KeyUsageEcc = 'digitalSignature'
        Critical = $false
        Policy = $EvTlsPolicyOid
    }

    'ipsecuser' = @{
        Label = 'IPsec User'
        Slug = 'ipsecuser'
        Oids = @('1.3.6.1.5.5.7.3.7')
        Check = @('1.3.6.1.5.5.7.3.7')
        KeyUsageRsa = 'digitalSignature,keyEncipherment'
        KeyUsageEcc = 'digitalSignature'
        Critical = $false
        Policy = $EvTlsPolicyOid
    }

    'mssgc' = @{
        Label = 'Microsoft Server Gated Cryptography'
        Slug = 'mssgc'
        Oids = @('1.3.6.1.4.1.311.10.3.3')
        Check = @('1.3.6.1.4.1.311.10.3.3')
        KeyUsageRsa = 'digitalSignature,keyEncipherment'
        KeyUsageEcc = 'digitalSignature'
        Critical = $false
        Policy = $EvTlsPolicyOid
    }

    'nssgc' = @{
        Label = 'Netscape Server Gated Cryptography'
        Slug = 'nssgc'
        Oids = @('2.16.840.1.113730.4.1')
        Check = @('2.16.840.1.113730.4.1')
        KeyUsageRsa = 'digitalSignature,keyEncipherment'
        KeyUsageEcc = 'digitalSignature'
        Critical = $false
        Policy = $EvTlsPolicyOid
    }
}

# Names accepted by -Eku (case-insensitive, '-' and '_' ignored).
$EkuAliases = @{
    'tls'                 = 'tls'
    'serverauth'          = 'tls'
    'clientauth'          = 'tls'
    'codesigning'         = 'codesigning'
    'codesign'            = 'codesigning'
    'emailprotection'     = 'emailprotection'
    'email'               = 'emailprotection'
    'smime'               = 'emailprotection'
    'timestamping'        = 'timestamping'
    'timestamp'           = 'timestamping'
    'smartcardlogon'      = 'smartcardlogon'
    'smartcard'           = 'smartcardlogon'
    'ipsecike'            = 'ipsecike'
    'ipsecendsystem'      = 'ipsecendsystem'
    'ipsectunnel'         = 'ipsectunnel'
    'ipsecuser'           = 'ipsecuser'
    'mssgc'               = 'mssgc'
    'microsoftsgc'        = 'mssgc'
    'nssgc'               = 'nssgc'
    'netscapesgc'         = 'nssgc'
}

# ============================================================
# DEVELOPMENT SAN SET  (-AddDevelopmentSAN)
#
# 'raksakateknologi.api' is used for the last DNS name; the request
# spelled it 'raksakteknologi.api' once, but every other entry
# (and the wildcard) uses 'raksakateknologi'.
# ============================================================

$DevelopmentDns = @(
    'localhost',
    'local.dev',
    'nextmantra.local',
    'nextmantra.developer',
    'nextmantra.internal',
    'nextmantra.api',
    'raksakateknologi.local',
    'raksakateknologi.developer',
    'raksakateknologi.internal',
    'raksakateknologi.api'
)

$DevelopmentIPv4 = @('127.0.0.1', '10.10.2.2', '192.168.0.1')

$DevelopmentIPv6 = @('::1')

$DevelopmentWildcardDns = @(
    '*.raksakateknologi.local',
    '*.raksakateknologi.developer',
    '*.raksakateknologi.internal',
    '*.raksakateknologi.api',
    '*.nextmantra.local',
    '*.nextmantra.developer',
    '*.nextmantra.internal',
    '*.nextmantra.api'
)

# Code signing certificates never use less than this many RSA bits.
$CodeSigningMinimumBits = 4096

$RsaSizes = @(2048, 3072, 4096, 8192)

# ============================================================
# DEFAULT VALUES
# ============================================================

$Domains = New-Object System.Collections.Generic.List[string]

$IPv4Addresses = New-Object System.Collections.Generic.List[string]

$IPv6Addresses = New-Object System.Collections.Generic.List[string]

$EmailAddresses = New-Object System.Collections.Generic.List[string]

$SelectedEku = New-Object System.Collections.Generic.List[string]

$EvOverrides = @{}

$Algorithm = 'RSA'

$Bit = 0

$Curve = ''

$Hash = 'sha256'

$Days = 397

$CommonName = ''

$Force = $false

$NoPfx = $false

$LegacyPfx = $false

$AddDevelopmentSAN = $false

$NoRevocationInfo = $false

$NoVerify = $false

$TlsOnly = $false

$ShowHelp = $false

# ============================================================
# FUNCTIONS
# ============================================================

function Write-Header {
    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host 'GenerateLeafCertificate.ps1' -ForegroundColor Cyan
    Write-Host 'Standalone Windows Local PKI EV Leaf Generator' -ForegroundColor Cyan
    Write-Host 'Author : Nicko Satria Utama' -ForegroundColor Cyan
    Write-Host 'Company: Agantra Inovatif OÜ (NextMantra)' -ForegroundColor Cyan
    Write-Host 'Email  : nicko@nextmantra.com' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ''
}

function Show-LeafHelp {
    @'
============================================================
 GenerateLeafCertificate.ps1 - EV leaf certificate generator
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
============================================================

WHAT IT DOES
  Issues EV leaf certificates from the Intermediate CA of your PKI (.\pki, made by
  pki_setup.ps1, or any folder given with -AddPkiContentPath).

  One certificate and one file set is made per EKU:
    TLS      serverAuth + clientAuth          <name>.key .pub .csr .crt
                                              -fullchain.crt .pfx .txt
    others   codeSigning, emailProtection, timeStamping, smartCardLogon,
             ipsecIKE, ipsecEndSystem, ipsecTunnel, ipsecUser, msSGC, nsSGC
                                              <name>-<eku>.key .pub .csr .crt ...
  Files are written to  leafcerts\<name>\   (wildcard names: _wildcard.<domain>).

USAGE
  .\GenerateLeafCertificate.ps1 -Domain <name> [options]

  The PFX password is asked once (used for every certificate). For unattended
  runs set  $env:PKI_PFX_PASSWORD  first.

NAMES (SAN)
  -Domain <name>               DNS name, repeatable. The first plain name is the CN.
                               Wildcards are allowed:  -Domain "*.lab.local"
  -WildcardDomain <name>       Adds both <name> and *.<name>.
  -CommonName <name>           Choose the CN (must also be one of the -Domain names).
  -IP4 <address>               IPv4 SAN, repeatable.
  -IP6 <address>               IPv6 SAN, repeatable.
  -Email <address>             E-mail SAN, repeatable.
  -AddDevelopmentSAN           Adds this development set to every certificate:
      DNS   localhost, local.dev, nextmantra.local, nextmantra.developer,
            nextmantra.internal, nextmantra.api, raksakateknologi.local,
            raksakateknologi.developer, raksakateknologi.internal,
            raksakateknologi.api
      IPv4  127.0.0.1, 10.10.2.2, 192.168.0.1
      IPv6  ::1
      Wildcard DNS  *.raksakateknologi.local / .developer / .internal / .api
                    *.nextmantra.local / .developer / .internal / .api
      Without -Domain the common name is localhost.

EV SUBJECT  (default: ev_pki.cnf, then the built-in EV defaults)
  -Organization <text>         O
  -OU <text>                   OU.            Default: BizDevSecOps
  -Locality <text>             L.             Default: Tallinn (when no -State)
  -State <text>                ST
  -Street <text>               Street address
  -PostalCode <text>           Postal code
  -Country <cc>                C.             Default: EE
  -JurisdictionCountry <cc>    jurisdictionC. Default: EE
  -JurisdictionState <text>    jurisdictionST
  -JurisdictionLocality <text> jurisdictionL
  -Serial <text>               serialNumber (registration number)
  -BusinessCategory <text>     Private Organization | Government Entity |
                               Business Entity | Non-Commercial Entity
  -ContactName <text>          name.            Default: Application Administrator
  -ContactEmail <text>         emailAddress.    Default: info@nextmantra.com
  -ContactPhone <text>         telephoneNumber. Default: (+372)53194019
  -CpsUrl <url>                CPS URI in the certificate policy

KEY AND SIGNATURE
  -Algorithm RSA|ECC           Default: RSA
  -Bit <n>                     RSA: 2048, 3072, 4096, 8192 (default 2048).
                               ECC: 256, 384, 521 (default 256).
                               A value that is not allowed (for example 1024) is
                               raised to the next allowed size, with a warning.
  -Curve P-256|P-384|P-521     ECC curve (alternative to -Bit).
  -Hash SHA256|SHA384|SHA512   Signature hash. Default: SHA256
  Code signing certificates are always RSA with at least 4096 bits: a missing
  -Bit, 1024, 2048 or 3072 becomes 4096; -Algorithm ECC still gives RSA 4096 for
  code signing.

EKU SELECTION
  (nothing)                    TLS certificate + one certificate per other EKU
  -TlsOnly                     TLS certificate only
  -Eku <name>                  TLS + the named EKU, repeatable:
                               codeSigning, emailProtection, timeStamping,
                               smartCardLogon, ipsecIKE, ipsecEndSystem,
                               ipsecTunnel, ipsecUser, msSGC, nsSGC

REVOCATION AND ISSUER INFORMATION (from ev_pki.cnf)
  Every certificate carries CRL distribution points, OCSP responders and CA
  Issuers locations:
      CRL     http://crl-01.nextmantra.com/agantra-rsa-ev-ca-g1.crl
              http://crl-02.nextmantra.com/agantra-rsa-ev-ca-g1.crl
              http://crl-dev.nextmantra.internal/agantra-rsa-ev-ca-g1.crl
      OCSP    http://ocsp.nextmantra.internal   http://ocsp.nextmantra.com
      Issuer  http://crt-01.nextmantra.com/agantra-rsa-ev-ca-g1.crt (and -02, -dev)
  -NoRevocationInfo            Leave all of them out (use when the hosts do not
                               exist: Windows reports "revocation server offline"
                               for client certificates until one is reachable).

PKI LOCATION
  -AddPkiContentPath <folder>  Issue from an existing PKI folder instead of .\pki.
                               Needs root\root.crt, intermediate\intermediate.crt
                               and intermediate\intermediate.key.
                               (pki_reuse.ps1 -Help checks / adopts / trusts a folder.)

OTHER
  -Days <n>                    Validity. Default: 397, EV maximum: 398
  -Force                       Replace an existing output folder
  -NoPfx                       Do not create PFX files
  -LegacyPfx                   Legacy PFX encryption (3DES/RC2/SHA1, needs the OpenSSL
                               legacy provider): PHP 5 / very old software
  -NoVerify                    Skip the chain / EV / compatibility verification
  -Help                        This help

EXAMPLES
  Default TLS + all other EKUs, RSA 2048 (codeSigning RSA 4096):
    .\GenerateLeafCertificate.ps1 -Domain nextmantra.com -Domain www.nextmantra.com -Force

  Development certificate with the full development SAN set, TLS only:
    .\GenerateLeafCertificate.ps1 -Domain nextmantra.com -AddDevelopmentSAN -TlsOnly -Force

  ECC P-384 + SHA-384, TLS and code signing:
    .\GenerateLeafCertificate.ps1 -Domain app.example.com -Algorithm ECC -Bit 384 `
        -Hash SHA384 -Eku codeSigning -Force

  Wildcard for a lab domain, RSA 3072, no revocation URLs:
    .\GenerateLeafCertificate.ps1 -WildcardDomain lab.example.local -Bit 3072 `
        -NoRevocationInfo -TlsOnly -Force

  Different OU, address and contact:
    .\GenerateLeafCertificate.ps1 -Domain shop.example.com -OU "Web Platform" `
        -Locality Narva -ContactName "Jane Doe" -ContactEmail jane@example.com

  Issue from a PKI that lives elsewhere:
    .\GenerateLeafCertificate.ps1 -AddPkiContentPath D:\Backup\pki -Domain api.example.com

COMPATIBILITY
  The TLS certificate meets the certificate requirements of Chrome / Edge / Brave,
  Firefox, Safari (macOS, iOS) and Android WebView, and of OpenSSL (Apache, nginx),
  Schannel (IIS, Kestrel), Node.js, Go, Java and PHP. The Root CA must be installed on
  every device. See COMPATIBILITY.md for installation steps per platform and
  configuration snippets per web server.

NOTES
  * Private PKI: browsers show the company name under "Show certificate"; the
    "Issued to: <company>" line is only shown for roots in the browser's EV list.
  * Wildcards, internal names, IP addresses and e-mail SANs are not EV-compliant for
    public use. They are allowed here and listed as warnings.
'@ | Write-Host
}

function Fail {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[FAIL] $Message" -ForegroundColor Red
    exit 1
}

function Info {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[INFO] $Message" -ForegroundColor Gray
}

function Success {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[ OK ] $Message" -ForegroundColor Green
}

function Warn {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Test-CommandArgumentValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ParameterName,

        [Parameter(Mandatory = $true)]
        [int]$Index,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    if (($Index + 1) -ge $Arguments.Count) {
        Fail "Parameter '$ParameterName' requires a value."
    }

    $Value = $Arguments[$Index + 1]

    if ([string]::IsNullOrWhiteSpace($Value)) {
        Fail "Parameter '$ParameterName' requires a non-empty value."
    }

    if ($Value.StartsWith('-')) {
        Fail "Parameter '$ParameterName' requires a value. Received '$Value'."
    }

    return $Value
}

function Add-UniqueValue {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$List,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    if (-not $List.Contains($Value)) {
        [void]$List.Add($Value)
    }
}

function Test-DnsName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }

    if ($Name.Length -gt 253) {
        return $false
    }

    if ($Name -eq 'localhost') {
        return $true
    }

    # Wildcard: *.example.com (a single leading label only).
    if ($Name.StartsWith('*.')) {
        $Name = $Name.Substring(2)

        if ($Name.Length -eq 0 -or $Name.Contains('*')) {
            return $false
        }
    }

    if ($Name -match '^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$') {
        return $true
    }

    return $false
}

function Test-IPv4 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Address
    )

    try {
        $Parsed = [System.Net.IPAddress]::Parse($Address)

        return (
            $Parsed.AddressFamily -eq
            [System.Net.Sockets.AddressFamily]::InterNetwork
        )
    }
    catch {
        return $false
    }
}

function Test-IPv6 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Address
    )

    try {
        $Parsed = [System.Net.IPAddress]::Parse($Address)

        return (
            $Parsed.AddressFamily -eq
            [System.Net.Sockets.AddressFamily]::InterNetworkV6
        )
    }
    catch {
        return $false
    }
}

function Test-EmailAddress {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Email
    )

    if ($Email.Length -gt 320) {
        return $false
    }

    return (
        $Email -match
        '^[^@\s]+@[^@\s]+\.[^@\s]+$'
    )
}

function Convert-ToOpenSSLConfigValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return $Value.Replace('\', '\\')
}

function Invoke-OpenSSL {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Operation
    )

    Info "OpenSSL: $Operation"

    $Output = & $OpenSSL @Arguments 2>&1

    $ExitCode = $LASTEXITCODE

    if ($Output) {
        foreach ($Line in $Output) {
            if (-not [string]::IsNullOrWhiteSpace([string]$Line)) {
                Write-Host "       $Line" -ForegroundColor DarkGray
            }
        }
    }

    if ($ExitCode -ne 0) {
        throw "OpenSSL failed during '$Operation' with exit code $ExitCode."
    }

    return $Output
}

function New-RandomCertificateSerial {
    $Bytes = New-Object byte[] 16

    $Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    try {
        $Rng.GetBytes($Bytes)
    }
    finally {
        $Rng.Dispose()
    }

    # Make the serial positive.
    $Bytes[0] = $Bytes[0] -band 0x7F

    if (($Bytes | Where-Object { $_ -ne 0 }).Count -eq 0) {
        $Bytes[15] = 1
    }

    return (
        [System.BitConverter]::ToString($Bytes).
        Replace('-', '').
        ToLowerInvariant()
    )
}

function ConvertTo-SafeFileName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $InvalidChars = [System.IO.Path]::GetInvalidFileNameChars()

    $Result = $Name

    # A wildcard name becomes _wildcard.example.com
    $Result = $Result.Replace('*', '_wildcard')

    foreach ($Char in $InvalidChars) {
        $Result = $Result.Replace([string]$Char, '_')
    }

    return $Result
}

function Get-CertificateSubjectMap {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $Text = & $OpenSSL x509 -in $Path -noout -subject -nameopt 'multiline,utf8' 2>&1

    $Map = @{}

    foreach ($Line in ($Text -split "`r?`n")) {
        if ($Line -match '^\s+(\S+)\s*=\s*(.*?)\s*$') {
            $Map[$Matches[1]] = $Matches[2]
        }
    }

    return $Map
}

function Resolve-RsaBits {
    # Requested size -> an allowed RSA size (2048 / 3072 / 4096 / 8192)
    # that is not smaller than $Minimum.
    #
    #   not defined (<= 0)  -> $Default
    #   1024                -> 2048  (next allowed size), then $Minimum
    #   5000                -> 8192
    param(
        [int]$Requested,
        [int]$Minimum,
        [int]$Default
    )

    if ($Requested -le 0) {
        $Result = $Default
    }
    else {
        $Result = $RsaSizes[-1]

        foreach ($Size in $RsaSizes) {
            if ($Size -ge $Requested) {
                $Result = $Size
                break
            }
        }
    }

    if ($Result -lt $Minimum) {
        $Result = $Minimum
    }

    return $Result
}

function Get-CertificateKeySpec {
    # Key type and size for ONE certificate.
    #
    #   TLS / other EKUs : -Algorithm (RSA default), -Bit / -Curve
    #   codeSigning      : always RSA, at least 4096 bits. A missing or
    #                      too small -Bit (for example 1024) becomes 4096.
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    $IsCodeSigning = ($Target -eq 'codesigning')

    if ($IsCodeSigning -or $Algorithm -eq 'RSA') {

        $Minimum = if ($IsCodeSigning) { $CodeSigningMinimumBits } else { 2048 }
        $Default = $Minimum

        $Requested = if ($Algorithm -eq 'RSA') { $Bit } else { 0 }

        $Bits = Resolve-RsaBits -Requested $Requested -Minimum $Minimum -Default $Default

        $Note = ''

        if ($IsCodeSigning -and $Algorithm -eq 'ECC') {
            $Note = "Code signing always uses RSA with at least $CodeSigningMinimumBits bits (selected key type was ECC)."
        }
        elseif ($Requested -gt 0 -and $Bits -ne $Requested) {
            $Note = "RSA $Requested bits is not allowed for this certificate; using RSA $Bits."
        }

        return @{
            Algorithm    = 'RSA'
            Bit          = $Bits
            Curve        = ''
            OpenSslCurve = ''
            Note         = $Note
        }
    }

    return @{
        Algorithm    = 'ECC'
        Bit          = $Bit
        Curve        = $Curve
        OpenSslCurve = $OpenSslCurve
        Note         = ''
    }
}

function New-OpenSSLLeafConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        $Spec,

        [Parameter(Mandatory = $true)]
        $KeySpec
    )

    $Lines = New-Object System.Collections.Generic.List[string]

    # --------------------------------------------------------
    # OIDs
    # --------------------------------------------------------

    $Lines.Add('oid_section = new_oids')
    $Lines.Add('')
    $Lines.Add('[ new_oids ]')
    $Lines.Add('evPolicy = 2.23.140.1.1')
    $Lines.Add('evCodeSigningPolicy = 2.23.140.1.3')
    $Lines.Add('')

    # --------------------------------------------------------
    # REQUEST
    # --------------------------------------------------------

    $Lines.Add('[ req ]')
    $Lines.Add('prompt = no')
    $Lines.Add('utf8 = yes')
    $Lines.Add('string_mask = utf8only')
    $Lines.Add("default_md = $Hash")
    $Lines.Add('distinguished_name = dn_leaf')
    $Lines.Add('')

    # --------------------------------------------------------
    # EV SUBJECT (ev_pki.cnf + defaults + command-line overrides)
    # --------------------------------------------------------

    $Lines.Add('[ dn_leaf ]')

    foreach ($Field in $EvProfile.DnFields) {
        $Lines.Add("$($Field.Key) = $($Field.Raw)")
    }

    $Lines.Add('')

    # --------------------------------------------------------
    # FINAL CERTIFICATE EXTENSIONS
    # --------------------------------------------------------

    $KeyUsage = if ($KeySpec.Algorithm -eq 'ECC') { $Spec.KeyUsageEcc } else { $Spec.KeyUsageRsa }

    $EkuPrefix = if ($Spec.Critical) { 'critical,' } else { '' }

    $Lines.Add('[ v3_leaf ]')
    $Lines.Add('basicConstraints = critical,CA:false')
    $Lines.Add("keyUsage = critical,$KeyUsage")

    # IMPORTANT:
    # Keep the EKU declaration on ONE physical line.
    $Lines.Add("extendedKeyUsage = $EkuPrefix$($Spec.Oids -join ',')")

    $Lines.Add('subjectKeyIdentifier = hash')
    $Lines.Add('authorityKeyIdentifier = keyid,issuer')
    $Lines.Add('subjectAltName = @leaf_san')
    $Lines.Add('certificatePolicies = @ev_policy')

    if (-not $NoRevocationInfo) {
        $Lines.Add('crlDistributionPoints = @leaf_crl')
        $Lines.Add('authorityInfoAccess = @leaf_aia')
    }

    $Lines.Add('')

    # --------------------------------------------------------
    # POLICY
    # --------------------------------------------------------

    $Lines.Add('[ ev_policy ]')
    $Lines.Add("policyIdentifier = $($Spec.Policy)")

    foreach ($Entry in $EvProfile.PolicyEntries) {
        if ($Entry.Key -match '^CPS\.\d+$') {
            $Lines.Add("$($Entry.Key) = $($Entry.Raw)")
        }
    }

    $Lines.Add('')

    # --------------------------------------------------------
    # CRL distribution points + authority information access
    # (OCSP and CA Issuers) from ev_pki.cnf
    # --------------------------------------------------------

    if (-not $NoRevocationInfo) {

        $Lines.Add('[ leaf_crl ]')

        $Number = 1

        foreach ($Uri in $EvProfile.CrlUris) {
            $Lines.Add("URI.$Number = $Uri")
            $Number++
        }

        $Lines.Add('')
        $Lines.Add('[ leaf_aia ]')

        $Number = 1

        foreach ($Uri in $EvProfile.OcspUris) {
            $Lines.Add("OCSP;URI.$Number = $Uri")
            $Number++
        }

        $Number = 1

        foreach ($Uri in $EvProfile.CaIssuerUris) {
            $Lines.Add("caIssuers;URI.$Number = $Uri")
            $Number++
        }

        $Lines.Add('')
    }

    # --------------------------------------------------------
    # SAN
    # --------------------------------------------------------

    $Lines.Add('[ leaf_san ]')

    $DnsIndex = 1

    foreach ($Domain in $Domains) {
        $SafeDomain = Convert-ToOpenSSLConfigValue $Domain
        $Lines.Add("DNS.$DnsIndex = $SafeDomain")
        $DnsIndex++
    }

    $IpIndex = 1

    foreach ($IPv4 in $IPv4Addresses) {
        $Lines.Add("IP.$IpIndex = $IPv4")
        $IpIndex++
    }

    foreach ($IPv6 in $IPv6Addresses) {
        $Lines.Add("IP.$IpIndex = $IPv6")
        $IpIndex++
    }

    $EmailIndex = 1

    foreach ($Email in $EmailAddresses) {
        $SafeEmail = Convert-ToOpenSSLConfigValue $Email
        $Lines.Add("email.$EmailIndex = $SafeEmail")
        $EmailIndex++
    }

    # --------------------------------------------------------
    # WRITE UTF-8 WITHOUT BOM
    # --------------------------------------------------------

    $Content = ($Lines -join [Environment]::NewLine) + [Environment]::NewLine

    [System.IO.File]::WriteAllText(
        $Path,
        $Content,
        (New-Object System.Text.UTF8Encoding($false))
    )
}

function Test-IssuedEvCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CertificatePath,

        [Parameter(Mandatory = $true)]
        $Spec,

        [Parameter(Mandatory = $true)]
        $KeySpec
    )

    $Problems = New-Object System.Collections.Generic.List[string]

    $Text = (
        (& $OpenSSL x509 -in $CertificatePath -text -noout 2>&1) -join [Environment]::NewLine
    )

    if ($Text -notmatch 'CA:FALSE') {
        [void]$Problems.Add('not marked CA:FALSE')
    }

    if ($Text -notmatch 'X509v3 Key Usage: critical') {
        [void]$Problems.Add('Key Usage missing or not critical')
    }

    if ($Text -notmatch 'Subject Alternative Name') {
        [void]$Problems.Add('Subject Alternative Name missing')
    }

    if (-not $NoRevocationInfo) {

        if ($Text -notmatch 'CRL Distribution Points') {
            [void]$Problems.Add('CRL Distribution Points missing')
        }

        if ($Text -notmatch 'Authority Information Access') {
            [void]$Problems.Add('Authority Information Access (OCSP / CA Issuers) missing')
        }

        foreach ($Uri in (@($EvProfile.CrlUris) + @($EvProfile.OcspUris) + @($EvProfile.CaIssuerUris))) {
            if ($Text -notmatch ('URI:' + [regex]::Escape($Uri))) {
                [void]$Problems.Add("URI $Uri missing")
            }
        }
    }

    if ($Text -notmatch ('Policy:\s+' + [regex]::Escape($Spec.Policy))) {
        [void]$Problems.Add("EV policy OID $($Spec.Policy) missing")
    }

    if ($KeySpec.Algorithm -eq 'RSA') {
        if ($Text -notmatch "Public-Key:\s+\($($KeySpec.Bit) bit\)") {
            [void]$Problems.Add("RSA key is not $($KeySpec.Bit) bit")
        }
    }
    else {
        if ($Text -notmatch 'id-ecPublicKey') {
            [void]$Problems.Add('public key is not ECC')
        }
    }

    # --------------------------------------------------------
    # Platform compatibility of the TLS certificate (browsers, OS
    # trust stores and web servers): the certificate properties
    # that Chrome / Edge / Brave, Firefox, Safari (macOS / iOS),
    # Android WebView and the OpenSSL / Schannel / Go / .NET TLS
    # stacks require of a TLS server certificate.
    # --------------------------------------------------------

    if ($Spec.Slug -eq '') {

        if ($Text -notmatch 'DNS:' -and $Text -notmatch 'IP Address:') {
            [void]$Problems.Add('compatibility: SAN needs a DNS or IP entry (browsers ignore the common name)')
        }

        if ($Text -notmatch 'Signature Algorithm:\s+(sha256|sha384|sha512)') {
            [void]$Problems.Add('compatibility: signature must be SHA-2 (SHA-256 or stronger)')
        }

        if ($Text -notmatch 'Digital Signature') {
            [void]$Problems.Add('compatibility: keyUsage must contain digitalSignature')
        }

        if ($Text -notmatch 'X509v3 Subject Key Identifier' -or $Text -notmatch 'X509v3 Authority Key Identifier') {
            [void]$Problems.Add('compatibility: Subject / Authority Key Identifier missing (chain building)')
        }

        $SerialLine = (& $OpenSSL x509 -in $CertificatePath -noout -serial 2>&1) -join ''

        if ($SerialLine -match 'serial=([0-9A-Fa-f]+)') {
            if ($Matches[1].Length -gt 40) {
                [void]$Problems.Add('compatibility: serial number is longer than 20 octets')
            }
        }
    }

    $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)

    try {
        $Actual = @(
            $Cert.Extensions |
                Where-Object { $_.Oid.Value -eq '2.5.29.37' } |
                ForEach-Object {
                    ([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$_).EnhancedKeyUsages |
                        ForEach-Object { $_.Value }
                }
        )

        foreach ($Needed in $Spec.Check) {
            if ($Needed -notin $Actual) {
                [void]$Problems.Add("EKU $Needed missing")
            }
        }

        foreach ($Found in $Actual) {
            if ($Found -notin $Spec.Check) {
                [void]$Problems.Add("EKU $Found must not be in this certificate")
            }
        }

        $Lifetime = [math]::Ceiling(($Cert.NotAfter - $Cert.NotBefore).TotalDays)

        if ($Lifetime -gt $EvMaxDays) {
            [void]$Problems.Add("validity $Lifetime days exceeds the EV maximum of $EvMaxDays")
        }
    }
    finally {
        $Cert.Dispose()
    }

    $Subject = Get-CertificateSubjectMap -Path $CertificatePath

    foreach ($Required in @(
        'businessCategory',
        'jurisdictionCountryName',
        'serialNumber',
        'countryName',
        'organizationName',
        'organizationalUnitName',
        'commonName',
        'name',
        'emailAddress',
        'telephoneNumber'
    )) {
        if (-not $Subject.ContainsKey($Required)) {
            [void]$Problems.Add("subject field $Required missing")
        }
    }

    if (
        -not $Subject.ContainsKey('localityName') -and
        -not $Subject.ContainsKey('stateOrProvinceName')
    ) {
        [void]$Problems.Add('subject needs localityName or stateOrProvinceName')
    }

    if ($Problems.Count -gt 0) {
        throw "EV verification failed for ${CertificatePath}: $($Problems -join '; ')."
    }
}

# ============================================================
# HEADER
# ============================================================

Write-Header

# ============================================================
# PARSE REPEATED PARAMETERS
# ============================================================

$Arguments = @($args)

if ($Arguments.Count -eq 0) {
    Show-LeafHelp
    Fail 'No parameters supplied. At least one -Domain is required.'
}

$ParsedHashMap = @{
    'sha256' = 'sha256'; 'sha-256' = 'sha256'; '256' = 'sha256'
    'sha384' = 'sha384'; 'sha-384' = 'sha384'; '384' = 'sha384'
    'sha512' = 'sha512'; 'sha-512' = 'sha512'; '512' = 'sha512'
}

$CurveMap = @{
    'p-256' = 'P-256'; 'p256' = 'P-256'; 'prime256v1' = 'P-256'; 'secp256r1' = 'P-256'; '256' = 'P-256'
    'p-384' = 'P-384'; 'p384' = 'P-384'; 'secp384r1' = 'P-384'; '384' = 'P-384'
    'p-521' = 'P-521'; 'p521' = 'P-521'; 'secp521r1' = 'P-521'; '521' = 'P-521'
}

$Index = 0

while ($Index -lt $Arguments.Count) {

    $Token = [string]$Arguments[$Index]

    switch -Regex ($Token.ToLowerInvariant()) {

        '^-(help|\?|h)$' {

            $ShowHelp = $true

            $Index++
            continue
        }

        '^-domain$' {

            $Value = Test-CommandArgumentValue `
                -ParameterName '-Domain' `
                -Index $Index `
                -Arguments $Arguments

            if (-not (Test-DnsName $Value)) {
                Fail "Invalid DNS domain: $Value"
            }

            Add-UniqueValue -List $Domains -Value $Value.ToLowerInvariant()

            $Index += 2
            continue
        }

        '^-wildcarddomain$|^-wildcard$' {

            # -WildcardDomain example.com  ->  *.example.com and example.com
            $Value = Test-CommandArgumentValue `
                -ParameterName $Token `
                -Index $Index `
                -Arguments $Arguments

            $BaseDomain = $Value.ToLowerInvariant()

            if ($BaseDomain.StartsWith('*.')) {
                $BaseDomain = $BaseDomain.Substring(2)
            }

            if (-not (Test-DnsName $BaseDomain)) {
                Fail "Invalid DNS domain: $Value"
            }

            Add-UniqueValue -List $Domains -Value $BaseDomain
            Add-UniqueValue -List $Domains -Value ('*.' + $BaseDomain)

            $Index += 2
            continue
        }

        '^-adddevelopmentsan$' {

            $AddDevelopmentSAN = $true

            $Index++
            continue
        }

        '^-norevocationinfo$' {

            $NoRevocationInfo = $true

            $Index++
            continue
        }

        '^-legacypfx$' {

            $LegacyPfx = $true

            $Index++
            continue
        }

        '^-(addpkicontentpath|pkipath)$' {

            $PkiContentPath = Test-CommandArgumentValue `
                -ParameterName $Token `
                -Index $Index `
                -Arguments $Arguments

            $Index += 2
            continue
        }

        '^-contactname$' {
            $EvOverrides['ContactName'] = Test-CommandArgumentValue -ParameterName $Token -Index $Index -Arguments $Arguments
            $Index += 2
            continue
        }

        '^-contactemail$' {
            $EvOverrides['ContactEmail'] = Test-CommandArgumentValue -ParameterName $Token -Index $Index -Arguments $Arguments
            $Index += 2
            continue
        }

        '^-contactphone$' {
            $EvOverrides['ContactPhone'] = Test-CommandArgumentValue -ParameterName $Token -Index $Index -Arguments $Arguments
            $Index += 2
            continue
        }

        '^-ip4$' {

            $Value = Test-CommandArgumentValue `
                -ParameterName '-IP4' `
                -Index $Index `
                -Arguments $Arguments

            if (-not (Test-IPv4 $Value)) {
                Fail "Invalid IPv4 address: $Value"
            }

            Add-UniqueValue `
                -List $IPv4Addresses `
                -Value $Value

            $Index += 2
            continue
        }

        '^-ip6$' {

            $Value = Test-CommandArgumentValue `
                -ParameterName '-IP6' `
                -Index $Index `
                -Arguments $Arguments

            if (-not (Test-IPv6 $Value)) {
                Fail "Invalid IPv6 address: $Value"
            }

            Add-UniqueValue `
                -List $IPv6Addresses `
                -Value $Value

            $Index += 2
            continue
        }

        '^-email$' {

            $Value = Test-CommandArgumentValue `
                -ParameterName '-Email' `
                -Index $Index `
                -Arguments $Arguments

            if (-not (Test-EmailAddress $Value)) {
                Fail "Invalid email address: $Value"
            }

            Add-UniqueValue `
                -List $EmailAddresses `
                -Value $Value

            $Index += 2
            continue
        }

        '^-(algorithm|alg|type)$' {

            $Value = Test-CommandArgumentValue `
                -ParameterName $Token `
                -Index $Index `
                -Arguments $Arguments

            switch ($Value.ToUpperInvariant()) {
                'RSA'   { $Algorithm = 'RSA' }
                'ECC'   { $Algorithm = 'ECC' }
                'ECDSA' { $Algorithm = 'ECC' }
                'EC'    { $Algorithm = 'ECC' }
                default { Fail "Invalid -Algorithm '$Value'. Use RSA or ECC." }
            }

            $Index += 2
            continue
        }

        '^-bit$' {

            $Value = Test-CommandArgumentValue `
                -ParameterName '-Bit' `
                -Index $Index `
                -Arguments $Arguments

            $ParsedBit = 0

            if (-not [int]::TryParse($Value, [ref]$ParsedBit)) {
                Fail "Invalid -Bit value: $Value"
            }

            $Bit = $ParsedBit

            $Index += 2
            continue
        }

        '^-curve$' {

            $Value = Test-CommandArgumentValue `
                -ParameterName '-Curve' `
                -Index $Index `
                -Arguments $Arguments

            if (-not $CurveMap.ContainsKey($Value.ToLowerInvariant())) {
                Fail "Invalid -Curve '$Value'. Use P-256, P-384 or P-521."
            }

            $Curve = $CurveMap[$Value.ToLowerInvariant()]

            $Index += 2
            continue
        }

        '^-(hash|sha|digest)$' {

            $Value = Test-CommandArgumentValue `
                -ParameterName $Token `
                -Index $Index `
                -Arguments $Arguments

            if (-not $ParsedHashMap.ContainsKey($Value.ToLowerInvariant())) {
                Fail "Invalid -Hash '$Value'. Use SHA256, SHA384 or SHA512."
            }

            $Hash = $ParsedHashMap[$Value.ToLowerInvariant()]

            $Index += 2
            continue
        }

        '^-eku$' {

            $Value = Test-CommandArgumentValue `
                -ParameterName '-Eku' `
                -Index $Index `
                -Arguments $Arguments

            $EkuKey = ($Value.ToLowerInvariant() -replace '[-_ ]', '')

            if (-not $EkuAliases.ContainsKey($EkuKey)) {
                Fail "Unknown EKU '$Value'. Use: codeSigning, emailProtection, timeStamping, smartCardLogon, ipsecIKE, ipsecEndSystem, ipsecTunnel, ipsecUser, msSGC, nsSGC."
            }

            Add-UniqueValue -List $SelectedEku -Value $EkuAliases[$EkuKey]

            $Index += 2
            continue
        }

        '^-tlsonly$' {

            $TlsOnly = $true

            $Index++
            continue
        }

        '^-days$' {

            $Value = Test-CommandArgumentValue `
                -ParameterName '-Days' `
                -Index $Index `
                -Arguments $Arguments

            $ParsedDays = 0

            if (-not [int]::TryParse($Value, [ref]$ParsedDays)) {
                Fail "Invalid -Days value: $Value"
            }

            if ($ParsedDays -lt 1 -or $ParsedDays -gt $EvMaxDays) {
                Fail "-Days must be between 1 and $EvMaxDays. EV certificates may be valid for at most $EvMaxDays days."
            }

            $Days = $ParsedDays

            $Index += 2
            continue
        }

        '^-commonname$' {

            $Value = Test-CommandArgumentValue `
                -ParameterName '-CommonName' `
                -Index $Index `
                -Arguments $Arguments

            $CommonName = $Value.ToLowerInvariant()

            $Index += 2
            continue
        }

        '^-(organization|org|o)$' {
            $EvOverrides['Organization'] = Test-CommandArgumentValue -ParameterName $Token -Index $Index -Arguments $Arguments
            $Index += 2
            continue
        }

        '^-(ou|organizationalunit|organizationunit)$' {
            $EvOverrides['OrganizationalUnit'] = Test-CommandArgumentValue -ParameterName $Token -Index $Index -Arguments $Arguments
            $Index += 2
            continue
        }

        '^-(locality|l)$' {
            $EvOverrides['Locality'] = Test-CommandArgumentValue -ParameterName $Token -Index $Index -Arguments $Arguments
            $Index += 2
            continue
        }

        '^-(state|st)$' {
            $EvOverrides['State'] = Test-CommandArgumentValue -ParameterName $Token -Index $Index -Arguments $Arguments
            $Index += 2
            continue
        }

        '^-(street|address)$' {
            $EvOverrides['Street'] = Test-CommandArgumentValue -ParameterName $Token -Index $Index -Arguments $Arguments
            $Index += 2
            continue
        }

        '^-postalcode$' {
            $EvOverrides['PostalCode'] = Test-CommandArgumentValue -ParameterName $Token -Index $Index -Arguments $Arguments
            $Index += 2
            continue
        }

        '^-(country|c)$' {
            $EvOverrides['Country'] = Test-CommandArgumentValue -ParameterName $Token -Index $Index -Arguments $Arguments
            $Index += 2
            continue
        }

        '^-(jurisdictioncountry|jurisdictionc|jurisdiction)$' {
            $EvOverrides['JurisdictionCountry'] = Test-CommandArgumentValue -ParameterName $Token -Index $Index -Arguments $Arguments
            $Index += 2
            continue
        }

        '^-jurisdictionstate$' {
            $EvOverrides['JurisdictionState'] = Test-CommandArgumentValue -ParameterName $Token -Index $Index -Arguments $Arguments
            $Index += 2
            continue
        }

        '^-jurisdictionlocality$' {
            $EvOverrides['JurisdictionLocality'] = Test-CommandArgumentValue -ParameterName $Token -Index $Index -Arguments $Arguments
            $Index += 2
            continue
        }

        '^-(serial|serialnumber)$' {
            $EvOverrides['Serial'] = Test-CommandArgumentValue -ParameterName $Token -Index $Index -Arguments $Arguments
            $Index += 2
            continue
        }

        '^-businesscategory$' {
            $EvOverrides['BusinessCategory'] = Test-CommandArgumentValue -ParameterName $Token -Index $Index -Arguments $Arguments
            $Index += 2
            continue
        }

        '^-cpsurl$' {
            $EvOverrides['CpsUrl'] = Test-CommandArgumentValue -ParameterName $Token -Index $Index -Arguments $Arguments
            $Index += 2
            continue
        }

        '^-force$' {

            $Force = $true

            $Index++
            continue
        }

        '^-nopfx$' {

            $NoPfx = $true

            $Index++
            continue
        }

        '^-noverify$' {

            $NoVerify = $true

            $Index++
            continue
        }

        default {

            Fail "Unknown parameter: $Token"
        }
    }
}

if ($ShowHelp) {
    Show-LeafHelp
    exit 0
}

# ============================================================
# PKI LOCATION  (-AddPkiContentPath)
#
# Use an existing PKI folder instead of .\pki next to this script.
# The folder needs root\root.crt, intermediate\intermediate.crt and
# intermediate\intermediate.key (the layout pki_setup.ps1 creates).
# ============================================================

if ($PkiContentPath -ne '') {

    if (-not (Test-Path -LiteralPath $PkiContentPath -PathType Container)) {
        Fail "-AddPkiContentPath folder not found: $PkiContentPath"
    }

    $PKIRoot = (Resolve-Path -LiteralPath $PkiContentPath).Path

    $RootCertificate = Join-Path $PKIRoot 'root/root.crt'

    $IntermediateCertificate = Join-Path $PKIRoot 'intermediate/intermediate.crt'

    $IntermediatePrivateKey = Join-Path $PKIRoot 'intermediate/intermediate.key'

    Info "Using the existing PKI: $PKIRoot"
}

# ============================================================
# ENVIRONMENT CHECK
# ============================================================

if (-not (Test-Path -LiteralPath $OpenSSL -PathType Leaf)) {
    Fail "OpenSSL executable not found: $OpenSSL"
}

foreach ($Required in @(
    @($ConfigFile, 'EV PKI configuration'),
    @($ProfileModule, 'EV profile module (scripts\03_RuntimeConfig.ps1)'),
    @($RootCertificate, 'Root CA certificate'),
    @($IntermediateCertificate, 'Intermediate CA certificate'),
    @($IntermediatePrivateKey, 'Intermediate CA private key')
)) {
    if (-not (Test-Path -LiteralPath $Required[0] -PathType Leaf)) {
        Fail "$($Required[1]) not found: $($Required[0]). Run pki_setup.ps1 first, or point -AddPkiContentPath at an existing PKI folder (see -Help)."
    }
}

# ============================================================
# VALIDATE INPUT
# ============================================================

if ($AddDevelopmentSAN) {

    if ($Domains.Count -eq 0) {
        Info 'No -Domain given: the common name will be localhost.'
        Add-UniqueValue -List $Domains -Value 'localhost'
    }

    foreach ($Name in ($DevelopmentDns + $DevelopmentWildcardDns)) {
        Add-UniqueValue -List $Domains -Value $Name
    }

    foreach ($Address in $DevelopmentIPv4) {
        Add-UniqueValue -List $IPv4Addresses -Value $Address
    }

    foreach ($Address in $DevelopmentIPv6) {
        Add-UniqueValue -List $IPv6Addresses -Value $Address
    }
}

if ($Domains.Count -eq 0) {
    Fail 'At least one -Domain is required (or use -AddDevelopmentSAN).'
}

if ([string]::IsNullOrWhiteSpace($CommonName)) {

    # The first name that is not a wildcard; otherwise the first name.
    $FirstPlain = @($Domains | Where-Object { -not $_.Contains('*') } | Select-Object -First 1)

    if ($FirstPlain.Count -gt 0) {
        $CommonName = [string]$FirstPlain[0]
    }
    else {
        $CommonName = $Domains[0]
    }
}
elseif ($CommonName -notin $Domains) {
    Fail "-CommonName '$CommonName' must also be given as a -Domain."
}

if (-not (Test-DnsName $CommonName)) {
    Fail "Invalid Common Name: $CommonName"
}

if ($TlsOnly -and $SelectedEku.Count -gt 0) {
    Fail '-TlsOnly cannot be combined with -Eku.'
}

# ---------- key size / curve ----------

if ($Algorithm -eq 'RSA') {

    if ($Curve -ne '') {
        Fail '-Curve is only valid with -Algorithm ECC.'
    }

    # The RSA size is resolved per certificate (Get-CertificateKeySpec):
    # not defined -> 2048 (code signing: 4096); a size that is not allowed,
    # for example 1024, is raised to the next allowed size (code signing:
    # at least 4096).
}
else {

    if ($Bit -ne 0) {

        $BitCurve = $CurveMap[[string]$Bit]

        if ($null -eq $BitCurve) {
            Fail "-Bit $Bit is not valid for ECC. Use 256, 384 or 521."
        }

        if ($Curve -ne '' -and $Curve -ne $BitCurve) {
            Fail "-Bit $Bit ($BitCurve) conflicts with -Curve $Curve."
        }

        $Curve = $BitCurve
    }

    if ($Curve -eq '') {
        $Curve = 'P-256'
    }

    $Bit = [int]($Curve -replace '^P-', '')
}

$OpenSslCurve = switch ($Curve) {
    'P-256' { 'prime256v1' }
    'P-384' { 'secp384r1' }
    'P-521' { 'secp521r1' }
    default { '' }
}

# ---------- which certificates ----------

$Targets = New-Object System.Collections.Generic.List[string]

[void]$Targets.Add('tls')

if ($TlsOnly) {
    # TLS only.
}
elseif ($SelectedEku.Count -gt 0) {
    foreach ($Name in $SelectedEku) {
        if ($Name -ne 'tls') {
            Add-UniqueValue -List $Targets -Value $Name
        }
    }
}
else {
    foreach ($Name in $EkuCatalog.Keys) {
        if ($Name -ne 'tls') {
            [void]$Targets.Add($Name)
        }
    }
}

# ============================================================
# LOAD EV PROFILE (ev_pki.cnf + defaults + overrides)
# ============================================================

. $ProfileModule

$EvOverrides['Domain'] = $CommonName

try {
    $EvProfile = Get-EvProfile -MasterConfig $ConfigFile -Overrides $EvOverrides
}
catch {
    Write-Host ''
    Write-Host '[FAIL] EV profile is not valid.' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

if ($EvProfile.DnFields.Count -eq 0) {
    Fail 'The EV subject is empty.'
}

# ============================================================
# KEY SPECIFICATION PER CERTIFICATE
# ============================================================

$KeySpecs = @{}

foreach ($Name in $Targets) {
    $KeySpecs[$Name] = Get-CertificateKeySpec -Target $Name
}

# ============================================================
# NOTICES (private / lab PKI)
# ============================================================

$WildcardNames = @($Domains | Where-Object { $_.Contains('*') })

$InternalNames = @($Domains | Where-Object { -not $_.Contains('*') -and ($_ -eq 'localhost' -or $_ -notmatch '\.') })

if ($WildcardNames.Count -gt 0) {
    Warn "$($WildcardNames.Count) wildcard name(s) in the SAN: $($WildcardNames -join ', '). Public EV certificates may not contain wildcards; allowed here because this is a private / lab PKI."
}

if ($InternalNames.Count -gt 0) {
    Warn "Internal name(s) in the SAN: $($InternalNames -join ', '). Allowed because this is a private PKI."
}

if ($IPv4Addresses.Count + $IPv6Addresses.Count -gt 0) {
    Warn "IP address SAN(s): $((@($IPv4Addresses) + @($IPv6Addresses)) -join ', '). Allowed because this is a private PKI."
}

if ($EmailAddresses.Count -gt 0) {
    Warn "E-mail SAN(s): $($EmailAddresses -join ', '). EV TLS certificates normally carry DNS names only; allowed because this is a private PKI."
}

foreach ($Name in $Targets) {
    if ($KeySpecs[$Name].Note -ne '') {
        Warn "$($EkuCatalog[$Name].Label): $($KeySpecs[$Name].Note)"
    }
}

if (-not $NoRevocationInfo) {
    Warn 'The certificates name CRL / OCSP / CA Issuers URLs (ev_pki.cnf). Windows reports "revocation server offline" for client certificates (IIS, Kestrel mTLS) until one of them is reachable; use -NoRevocationInfo to leave them out.'
}

# ============================================================
# DISPLAY REQUEST
# ============================================================

Write-Host ''
Write-Host 'Certificate Request' -ForegroundColor Yellow
Write-Host '------------------------------------------------------------'

Write-Host "Common Name       : $CommonName"
Write-Host "Algorithm         : $Algorithm$(if ($Algorithm -eq 'ECC') { " ($Curve)" })"
Write-Host "Signature Hash    : $($Hash.ToUpperInvariant())"
Write-Host "Validity          : $Days days (EV maximum $EvMaxDays)"
Write-Host "PKI folder        : $PKIRoot"
Write-Host "Development SAN   : $AddDevelopmentSAN"
Write-Host "CRL / OCSP / AIA  : $(-not $NoRevocationInfo)"
Write-Host "Force             : $Force"
Write-Host "Generate PFX      : $(-not $NoPfx)$(if ($LegacyPfx) { ' (legacy encryption)' })"
Write-Host "Verify            : $(-not $NoVerify)"

Write-Host ''
Write-Host 'EV Subject:' -ForegroundColor Yellow

foreach ($Field in $EvProfile.DnFields) {
    Write-Host ("  {0,-26} = {1}" -f $Field.Key, (ConvertFrom-OpenSslConfValue -Raw $Field.Raw))
}

if ($EvProfile.AppliedDefaults.Count -gt 0) {
    Write-Host ''
    Write-Host 'Defaults applied:' -ForegroundColor Yellow

    foreach ($Default in $EvProfile.AppliedDefaults) {
        if ($Default -notmatch '^(Root|Intermediate) ') {
            Write-Host "  $Default"
        }
    }
}

Write-Host ''
Write-Host 'Certificates to generate:' -ForegroundColor Yellow

foreach ($Name in $Targets) {

    $Key = $KeySpecs[$Name]

    $KeyText = if ($Key.Algorithm -eq 'RSA') { "RSA $($Key.Bit)" } else { "ECC $($Key.Curve)" }

    Write-Host ("  {0,-16} {1,-38} {2}" -f $Name, $EkuCatalog[$Name].Label, $KeyText)
}

Write-Host ''
Write-Host "DNS SAN ($($Domains.Count)):" -ForegroundColor Yellow

foreach ($Domain in $Domains) {
    Write-Host "  DNS : $Domain"
}

if ($IPv4Addresses.Count -gt 0) {
    Write-Host ''
    Write-Host 'IPv4 SAN:' -ForegroundColor Yellow

    foreach ($IPv4 in $IPv4Addresses) {
        Write-Host "  IP4 : $IPv4"
    }
}

if ($IPv6Addresses.Count -gt 0) {
    Write-Host ''
    Write-Host 'IPv6 SAN:' -ForegroundColor Yellow

    foreach ($IPv6 in $IPv6Addresses) {
        Write-Host "  IP6 : $IPv6"
    }
}

if ($EmailAddresses.Count -gt 0) {
    Write-Host ''
    Write-Host 'Email SAN:' -ForegroundColor Yellow

    foreach ($Email in $EmailAddresses) {
        Write-Host "  MAIL: $Email"
    }
}

# ============================================================
# OUTPUT DIRECTORY
# ============================================================

New-Item -ItemType Directory -Force -Path $LeafRoot | Out-Null
New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null

$BaseName = ConvertTo-SafeFileName $CommonName

$LeafDirectory = Join-Path $LeafRoot $BaseName

if (Test-Path -LiteralPath $LeafDirectory) {

    if (-not $Force) {
        Fail @"
Certificate output directory already exists:

$LeafDirectory

Use -Force to replace it.
"@
    }

    Info 'Removing existing certificate directory.'

    Remove-Item `
        -LiteralPath $LeafDirectory `
        -Recurse `
        -Force
}

New-Item `
    -ItemType Directory `
    -Force `
    -Path $LeafDirectory |
    Out-Null

# ============================================================
# PFX PASSWORD (asked once, used for every certificate)
# ============================================================

$PlainPassword = $null

if (-not $NoPfx) {

    if (-not [string]::IsNullOrEmpty($env:PKI_PFX_PASSWORD)) {

        # Same environment variable the PKI setup scripts use.
        # Useful for unattended runs.
        Info 'Using the PFX password from environment variable PKI_PFX_PASSWORD.'

        $PlainPassword = $env:PKI_PFX_PASSWORD
    }
    else {

        Write-Host ''
        Write-Host 'PFX Password Required' -ForegroundColor Yellow

        $SecurePassword = Read-Host 'Enter PFX password'   -AsSecureString
        $SecureConfirm  = Read-Host 'Confirm PFX password' -AsSecureString

        $PlainPassword = ConvertFrom-SecureString -SecureString $SecurePassword -AsPlainText
        $PlainConfirm  = ConvertFrom-SecureString -SecureString $SecureConfirm  -AsPlainText

        if ([string]::IsNullOrEmpty($PlainPassword)) {
            Fail 'PFX password cannot be empty.'
        }

        if ($PlainPassword -cne $PlainConfirm) {
            Fail 'PFX passwords do not match.'
        }

        $PlainConfirm = $null
    }
}

# ============================================================
# GENERATE ONE CERTIFICATE PER EKU
# ============================================================

$Results = New-Object System.Collections.Generic.List[object]

$PasswordFile = Join-Path $TempRoot "$([Guid]::NewGuid().ToString('N')).pwd"

$TempConfigs = New-Object System.Collections.Generic.List[string]

try {

    if (-not $NoPfx) {

        # UTF-8 WITHOUT BOM, and no trailing newline.
        # (Encoding.UTF8 adds a BOM, which silently becomes part of the password.)
        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

        [System.IO.File]::WriteAllBytes(
            $PasswordFile,
            $Utf8NoBom.GetBytes($PlainPassword)
        )
    }

    foreach ($Target in $Targets) {

        $Spec = $EkuCatalog[$Target]

        $KeySpec = $KeySpecs[$Target]

        Write-Host ''
        Write-Host '------------------------------------------------------------' -ForegroundColor Cyan
        Write-Host "$($Spec.Label)  [$(($Spec.Oids) -join ', ')]" -ForegroundColor Cyan
        Write-Host '------------------------------------------------------------' -ForegroundColor Cyan

        # ----------------------------------------------------
        # File names. TLS keeps the original names; every other
        # EKU gets its own -<eku> suffix.
        # ----------------------------------------------------

        $Stem = if ($Spec.Slug -eq '') { $BaseName } else { "$BaseName-$($Spec.Slug)" }

        $PrivateKey  = Join-Path $LeafDirectory "$Stem.key"
        $PublicKey   = Join-Path $LeafDirectory "$Stem.pub"
        $CSR         = Join-Path $LeafDirectory "$Stem.csr"
        $Certificate = Join-Path $LeafDirectory "$Stem.crt"
        $FullChain   = Join-Path $LeafDirectory "$Stem-fullchain.crt"
        $PFX         = Join-Path $LeafDirectory "$Stem.pfx"
        $Report      = Join-Path $LeafDirectory "$Stem.txt"

        $TempConfig = Join-Path $TempRoot "$Stem-$([Guid]::NewGuid().ToString('N')).cnf"

        [void]$TempConfigs.Add($TempConfig)

        Info 'Creating runtime OpenSSL configuration.'

        New-OpenSSLLeafConfig -Path $TempConfig -Spec $Spec -KeySpec $KeySpec

        # ----------------------------------------------------
        # Private key
        # ----------------------------------------------------

        if ($KeySpec.Algorithm -eq 'RSA') {

            $KeyArguments = @(
                'genpkey',
                '-algorithm', 'RSA',
                '-pkeyopt', "rsa_keygen_bits:$($KeySpec.Bit)",
                '-out', $PrivateKey
            )

            $KeyOperation = "Generate RSA $($KeySpec.Bit)-bit private key"
        }
        else {

            $KeyArguments = @(
                'genpkey',
                '-algorithm', 'EC',
                '-pkeyopt', "ec_paramgen_curve:$($KeySpec.OpenSslCurve)",
                '-pkeyopt', 'ec_param_enc:named_curve',
                '-out', $PrivateKey
            )

            $KeyOperation = "Generate ECC $($KeySpec.Curve) private key"
        }

        Invoke-OpenSSL -Arguments $KeyArguments -Operation $KeyOperation | Out-Null

        if (-not (Test-Path -LiteralPath $PrivateKey -PathType Leaf)) {
            throw 'Private key was not created.'
        }

        Success "Private key created: $PrivateKey"

        # ----------------------------------------------------
        # Public key
        # ----------------------------------------------------

        Invoke-OpenSSL `
            -Arguments @('pkey', '-in', $PrivateKey, '-pubout', '-out', $PublicKey) `
            -Operation 'Generate public key' | Out-Null

        if (-not (Test-Path -LiteralPath $PublicKey -PathType Leaf)) {
            throw 'Public key was not created.'
        }

        Success "Public key created: $PublicKey"

        # ----------------------------------------------------
        # CSR (complete EV subject)
        # ----------------------------------------------------

        Invoke-OpenSSL `
            -Arguments @(
                'req', '-new', "-$Hash",
                '-config', $TempConfig,
                '-key', $PrivateKey,
                '-out', $CSR
            ) `
            -Operation 'Generate certificate signing request' | Out-Null

        if (-not (Test-Path -LiteralPath $CSR -PathType Leaf)) {
            throw 'CSR was not created.'
        }

        Success "CSR created: $CSR"

        # ----------------------------------------------------
        # Sign with the Intermediate CA
        # ----------------------------------------------------

        $CertificateSerial = New-RandomCertificateSerial

        Info "Certificate serial: $CertificateSerial"

        Invoke-OpenSSL `
            -Arguments @(
                'x509', '-req', "-$Hash",
                '-days', $Days.ToString(),
                '-in', $CSR,
                '-CA', $IntermediateCertificate,
                '-CAkey', $IntermediatePrivateKey,
                '-set_serial', "0x$CertificateSerial",
                '-extfile', $TempConfig,
                '-extensions', 'v3_leaf',
                '-out', $Certificate
            ) `
            -Operation 'Sign leaf certificate with Intermediate CA' | Out-Null

        if (-not (Test-Path -LiteralPath $Certificate -PathType Leaf)) {
            throw 'Leaf certificate was not created.'
        }

        Success "Leaf certificate created: $Certificate"

        # ----------------------------------------------------
        # Full chain (leaf + intermediate)
        # ----------------------------------------------------

        $LeafContent = Get-Content -LiteralPath $Certificate -Raw
        $IntermediateContent = Get-Content -LiteralPath $IntermediateCertificate -Raw

        $FullChainContent =
            $LeafContent.TrimEnd() +
            [Environment]::NewLine +
            $IntermediateContent.TrimEnd() +
            [Environment]::NewLine

        [System.IO.File]::WriteAllText(
            $FullChain,
            $FullChainContent,
            [System.Text.Encoding]::ASCII
        )

        Success "Full chain created: $FullChain"

        # ----------------------------------------------------
        # PFX
        # ----------------------------------------------------

        if (-not $NoPfx) {

            $FriendlyName = if ($Spec.Slug -eq '') { $CommonName } else { "$CommonName ($($Spec.Slug))" }

            $PfxArguments = @(
                'pkcs12', '-export'
            )

            if ($LegacyPfx) {
                # Same switch as pki_setup.ps1 -LegacyPfx. Needs the OpenSSL
                # legacy provider (3DES / RC2 PFX encryption).
                $PfxArguments += '-legacy'
            }

            $PfxArguments += @(
                '-out', $PFX,
                '-inkey', $PrivateKey,
                '-in', $Certificate,
                '-certfile', $IntermediateCertificate,
                '-name', $FriendlyName,
                '-passout', "file:$PasswordFile"
            )

            Invoke-OpenSSL `
                -Arguments $PfxArguments `
                -Operation 'Generate password-protected PFX' | Out-Null

            if (-not (Test-Path -LiteralPath $PFX -PathType Leaf)) {
                throw 'PFX was not created.'
            }

            # Prove the password actually opens the PFX before reporting success.
            $PfxCheckArguments = @('pkcs12', '-info')

            if ($LegacyPfx) {
                $PfxCheckArguments += '-legacy'
            }

            $PfxCheckArguments += @('-in', $PFX, '-noout', '-passin', "file:$PasswordFile")

            Invoke-OpenSSL `
                -Arguments $PfxCheckArguments `
                -Operation 'Verify PFX password' | Out-Null

            Success "PFX created and password verified: $PFX"
        }

        # ----------------------------------------------------
        # Verification
        # ----------------------------------------------------

        if (-not $NoVerify) {

            Invoke-OpenSSL `
                -Arguments @('verify', '-CAfile', $RootCertificate, '-untrusted', $IntermediateCertificate, $Certificate) `
                -Operation 'Verify certificate chain' | Out-Null

            Test-IssuedEvCertificate -CertificatePath $Certificate -Spec $Spec -KeySpec $KeySpec

            Success "EV verification passed ($($Spec.Label); policy $($Spec.Policy))."
        }

        # ----------------------------------------------------
        # Report
        # ----------------------------------------------------

        $ReportLines = New-Object System.Collections.Generic.List[string]

        $ReportLines.Add('============================================================')
        $ReportLines.Add('NextMantra Private PKI EV Leaf Certificate Report')
        $ReportLines.Add('============================================================')
        $ReportLines.Add("Generated            : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        $ReportLines.Add("Certificate          : $($Spec.Label)")
        $ReportLines.Add("Common Name          : $CommonName")
        $ReportLines.Add("Algorithm            : $($KeySpec.Algorithm)")

        if ($KeySpec.Algorithm -eq 'RSA') {
            $ReportLines.Add("Key Size             : RSA $($KeySpec.Bit)")
        }
        else {
            $ReportLines.Add("Curve                : $($KeySpec.Curve)")
        }

        $ReportLines.Add("Signature Hash       : $($Hash.ToUpperInvariant())")
        $ReportLines.Add("Validity Days        : $Days")
        $ReportLines.Add("Certificate Serial   : $CertificateSerial")
        $ReportLines.Add('')
        $ReportLines.Add('EV Subject:')

        foreach ($Field in $EvProfile.DnFields) {
            $ReportLines.Add(("  {0,-26} = {1}" -f $Field.Key, (ConvertFrom-OpenSslConfValue -Raw $Field.Raw)))
        }

        if (-not $NoRevocationInfo) {
            $ReportLines.Add('')
            $ReportLines.Add('CRL Distribution Points:')
            foreach ($Uri in $EvProfile.CrlUris) { $ReportLines.Add("  $Uri") }
            $ReportLines.Add('OCSP:')
            foreach ($Uri in $EvProfile.OcspUris) { $ReportLines.Add("  $Uri") }
            $ReportLines.Add('CA Issuers:')
            foreach ($Uri in $EvProfile.CaIssuerUris) { $ReportLines.Add("  $Uri") }
        }

        $ReportLines.Add('')
        $ReportLines.Add('DNS SAN:')
        foreach ($Domain in $Domains) { $ReportLines.Add("  DNS: $Domain") }

        if ($IPv4Addresses.Count -gt 0) {
            $ReportLines.Add('')
            $ReportLines.Add('IPv4 SAN:')
            foreach ($IPv4 in $IPv4Addresses) { $ReportLines.Add("  IP4: $IPv4") }
        }

        if ($IPv6Addresses.Count -gt 0) {
            $ReportLines.Add('')
            $ReportLines.Add('IPv6 SAN:')
            foreach ($IPv6 in $IPv6Addresses) { $ReportLines.Add("  IP6: $IPv6") }
        }

        if ($EmailAddresses.Count -gt 0) {
            $ReportLines.Add('')
            $ReportLines.Add('Email SAN:')
            foreach ($Email in $EmailAddresses) { $ReportLines.Add("  MAIL: $Email") }
        }

        $ReportLines.Add('')
        $ReportLines.Add("Private Key : $PrivateKey")
        $ReportLines.Add("Public Key  : $PublicKey")
        $ReportLines.Add("CSR         : $CSR")
        $ReportLines.Add("Certificate : $Certificate")
        $ReportLines.Add("Full Chain  : $FullChain")

        if (-not $NoPfx) {
            $ReportLines.Add("PFX         : $PFX")
        }

        $ReportLines.Add('')
        $ReportLines.Add('Issuer:')
        $ReportLines.Add('  Agantra Inovatif OÜ Private Intermediate CA')
        $ReportLines.Add('')
        $ReportLines.Add('Policy:')
        $ReportLines.Add("  $($Spec.Policy)")
        $ReportLines.Add('')
        $ReportLines.Add('EKU:')
        foreach ($EkuValue in $Spec.Oids) { $ReportLines.Add("  $EkuValue") }

        [System.IO.File]::WriteAllLines(
            $Report,
            $ReportLines,
            (New-Object System.Text.UTF8Encoding($false))
        )

        Success "Certificate report created: $Report"

        [void]$Results.Add(
            [pscustomobject]@{
                Name        = $Target
                Label       = $Spec.Label
                Key         = $PrivateKey
                Certificate = $Certificate
                FullChain   = $FullChain
                Pfx         = $PFX
                Report      = $Report
            }
        )
    }
}
catch {

    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Red
    Write-Host 'CERTIFICATE GENERATION FAILED' -ForegroundColor Red
    Write-Host '============================================================' -ForegroundColor Red
    Write-Host ''
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ''

    exit 1
}
finally {

    $PlainPassword = $null

    if (Test-Path -LiteralPath $PasswordFile) {
        Remove-Item -LiteralPath $PasswordFile -Force -ErrorAction SilentlyContinue
    }

    foreach ($TempConfig in $TempConfigs) {
        if (Test-Path -LiteralPath $TempConfig) {
            Remove-Item -LiteralPath $TempConfig -Force -ErrorAction SilentlyContinue
        }
    }
}

# ============================================================
# FINAL OUTPUT
# ============================================================

Write-Host ''
Write-Host '============================================================' -ForegroundColor Green
Write-Host 'CERTIFICATE GENERATION COMPLETED' -ForegroundColor Green
Write-Host '============================================================' -ForegroundColor Green
Write-Host ''

Write-Host 'Output Directory:' -ForegroundColor Cyan
Write-Host "  $LeafDirectory"
Write-Host ''

foreach ($Result in $Results) {

    Write-Host "$($Result.Label):" -ForegroundColor Cyan
    Write-Host "  Private Key : $($Result.Key)"
    Write-Host "  Certificate : $($Result.Certificate)"
    Write-Host "  Full Chain  : $($Result.FullChain)"

    if (-not $NoPfx) {
        Write-Host "  PFX         : $($Result.Pfx)"
    }

    Write-Host "  Report      : $($Result.Report)"
    Write-Host ''
}

Write-Host '============================================================' -ForegroundColor Green
