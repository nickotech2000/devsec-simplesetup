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
# Purpose:
#   Every certificate this script issues is an EV certificate:
#     - EV subject (businessCategory, jurisdictionC, serialNumber,
#       C, L, O, OU, CN) read from ev_pki.cnf
#     - EV certificate policy (2.23.140.1.1; 2.23.140.1.3 for
#       code signing)
#     - CA:FALSE, SAN, at most 398 days, no wildcard names
#
#   One certificate (one set of files) is generated per EKU:
#
#     TLS EV certificate  (serverAuth + clientAuth)   <name>.*
#     codeSigning                                     <name>-codesigning.*
#     emailProtection                                 <name>-emailprotection.*
#     timeStamping                                    <name>-timestamping.*
#     smartCardLogon                                  <name>-smartcardlogon.*
#     ipsecIKE / ipsecEndSystem / ipsecTunnel / ipsecUser
#     msSGC / nsSGC
#
#   File set per certificate:
#     .key  .pub  .csr  .crt  -fullchain.crt  .pfx  .txt
#
# IMPORTANT:
#   This is a PRIVATE PKI. It is NOT a publicly trusted EV
#   certificate. Chrome / Edge show "Issued to: <company>" only for
#   EV certificates that chain to a root in the browser's built-in
#   EV list, so a private root can never trigger that line. The
#   company name is always visible under "Show certificate".
#
# Repeated parameters are supported:
#
#   -Domain example.com -Domain www.example.com
#   -IP4 127.0.0.1  -IP6 ::1
#   -Email nicko@example.com
#
# Subject parameters (default comes from ev_pki.cnf, then from the
# built-in EV defaults):
#
#   -Organization  -OU  -Locality  -State  -Street  -PostalCode
#   -Country (EE)  -JurisdictionCountry (EE)  -JurisdictionState
#   -JurisdictionLocality  -Serial  -BusinessCategory  -CpsUrl
#   OU defaults to BizDevSecOps, Locality to Tallinn.
#
# Key / signature parameters:
#
#   -Algorithm RSA|ECC   default RSA
#   -Bit 2048|3072|4096|8192     (RSA, default 2048)
#   -Bit 256|384|521 or -Curve P-256|P-384|P-521   (ECC, default P-256)
#   -Hash SHA256|SHA384|SHA512   default SHA256
#
# EKU selection:
#
#   (nothing)        TLS certificate + one certificate per other EKU
#   -TlsOnly         TLS certificate only
#   -Eku codeSigning -Eku emailProtection   TLS + the chosen EKUs
#
# Example:
#
# .\GenerateLeafCertificate.ps1 `
#     -Domain nextmantra.com `
#     -Domain www.nextmantra.com `
#     -IP4 127.0.0.1 `
#     -Algorithm ECC -Bit 384 -Hash SHA384 `
#     -Eku codeSigning `
#     -Days 397 `
#     -Force
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
USAGE
  .\GenerateLeafCertificate.ps1 -Domain example.com [options]

NAMES
  -Domain <name>                DNS name (repeatable). First one is the CN.
  -CommonName <name>            Override the CN (must also be a -Domain).
  -IP4 <address>                IPv4 SAN (repeatable).
  -IP6 <address>                IPv6 SAN (repeatable).
  -Email <address>              E-mail SAN (repeatable).
  Wildcard names are rejected: EV certificates may not contain them.

EV SUBJECT (default: ev_pki.cnf, then the built-in EV defaults)
  -Organization <text>          O
  -OU <text>                    OU.            Default: BizDevSecOps
  -Locality <text>              L.             Default: Tallinn
  -State <text>                 ST
  -Street <text>                street address
  -PostalCode <text>            postal code
  -Country <cc>                 C.             Default: EE
  -JurisdictionCountry <cc>     jurisdictionC. Default: EE
  -JurisdictionState <text>     jurisdictionST
  -JurisdictionLocality <text>  jurisdictionL
  -Serial <text>                serialNumber (registration number)
  -BusinessCategory <text>      Private Organization | Government Entity |
                                Business Entity | Non-Commercial Entity
  -CpsUrl <url>                 CPS URI in the certificate policy

KEY AND SIGNATURE
  -Algorithm RSA|ECC            Default: RSA
  -Bit <n>                      RSA: 2048, 3072, 4096, 8192 (default 2048)
                                ECC: 256, 384, 521 (default 256)
  -Curve P-256|P-384|P-521      ECC curve (alternative to -Bit)
  -Hash SHA256|SHA384|SHA512    Signature hash. Default: SHA256

EKU SELECTION
  (nothing)                     TLS certificate + one certificate per other EKU
  -TlsOnly                      TLS certificate (serverAuth + clientAuth) only
  -Eku <name>                   TLS + the named EKU (repeatable):
                                codeSigning, emailProtection, timeStamping,
                                smartCardLogon, ipsecIKE, ipsecEndSystem,
                                ipsecTunnel, ipsecUser, msSGC, nsSGC

OTHER
  -Days <n>                     Validity. Default: 397, EV maximum: 398
  -Force                        Replace an existing output directory
  -NoPfx                        Do not create PFX files
                                (the PFX password is asked once; set
                                 PKI_PFX_PASSWORD for unattended runs)
  -NoVerify                     Skip verification
  -Help                         This help

FILES (leafcerts\<name>\)
  TLS            <name>.key .pub .csr .crt -fullchain.crt .pfx .txt
  other EKU      <name>-<eku>.key .pub .csr .crt -fullchain.crt .pfx .txt
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

function New-OpenSSLLeafConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        $Spec
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

    $KeyUsage = if ($Algorithm -eq 'ECC') { $Spec.KeyUsageEcc } else { $Spec.KeyUsageRsa }

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
        $Spec
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

    if ($Text -match 'DNS:\*') {
        [void]$Problems.Add('SAN contains a wildcard name')
    }

    if ($Text -notmatch ('Policy:\s+' + [regex]::Escape($Spec.Policy))) {
        [void]$Problems.Add("EV policy OID $($Spec.Policy) missing")
    }

    if ($Algorithm -eq 'RSA') {
        if ($Text -notmatch "Public-Key:\s+\($Bit bit\)") {
            [void]$Problems.Add("RSA key is not $Bit bit")
        }
    }
    else {
        if ($Text -notmatch 'id-ecPublicKey') {
            [void]$Problems.Add('public key is not ECC')
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
        'commonName'
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

            if ($Value.Contains('*')) {
                Fail "Wildcard names are not allowed in an EV certificate: $Value"
            }

            if (-not (Test-DnsName $Value)) {
                Fail "Invalid DNS domain: $Value"
            }

            Add-UniqueValue -List $Domains -Value $Value.ToLowerInvariant()

            $Index += 2
            continue
        }

        '^-wildcarddomain$|^-wildcard$' {

            Fail "Wildcard names are not allowed in an EV certificate ($Token). Use explicit -Domain names."
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
        Fail "$($Required[1]) not found: $($Required[0])"
    }
}

# ============================================================
# VALIDATE INPUT
# ============================================================

if ($Domains.Count -eq 0) {
    Fail 'At least one -Domain is required.'
}

if ([string]::IsNullOrWhiteSpace($CommonName)) {
    $CommonName = $Domains[0]
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

    if ($Bit -eq 0) {
        $Bit = 2048
    }

    if ($Bit -notin @(2048, 3072, 4096, 8192)) {
        Fail "-Bit $Bit is not valid for RSA. Use 2048, 3072, 4096 or 8192."
    }
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
# EV WARNINGS
# ============================================================

foreach ($Domain in $Domains) {
    if ($Domain -eq 'localhost' -or $Domain -notmatch '\.') {
        Warn "DNS:$Domain is an internal name. Public EV certificates may not contain it; allowed here because this is a private PKI."
    }
}

foreach ($IPv4 in $IPv4Addresses) {
    Warn "IP:$IPv4 is an IP address. Public EV certificates may not contain it; allowed here because this is a private PKI."
}

foreach ($IPv6 in $IPv6Addresses) {
    Warn "IP:$IPv6 is an IP address. Public EV certificates may not contain it; allowed here because this is a private PKI."
}

foreach ($Email in $EmailAddresses) {
    Warn "email:$Email is an e-mail name. EV TLS certificates normally carry only DNS names; allowed here because this is a private PKI."
}

if ('codesigning' -in $Targets -and $Algorithm -eq 'RSA' -and $Bit -lt 3072) {
    Warn 'EV code signing requires RSA 3072 bits or more; use -Bit 3072 or higher for the code signing certificate.'
}

# ============================================================
# DISPLAY REQUEST
# ============================================================

Write-Host ''
Write-Host 'Certificate Request' -ForegroundColor Yellow
Write-Host '------------------------------------------------------------'

Write-Host "Common Name       : $CommonName"
Write-Host "Algorithm         : $Algorithm"

if ($Algorithm -eq 'RSA') {
    Write-Host "Key Size          : RSA $Bit bit"
}
else {
    Write-Host "Curve             : $Curve (ECC $Bit bit)"
}

Write-Host "Signature Hash    : $($Hash.ToUpperInvariant())"
Write-Host "Validity          : $Days days (EV maximum $EvMaxDays)"
Write-Host "Force             : $Force"
Write-Host "Generate PFX      : $(-not $NoPfx)"
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
    Write-Host ("  {0,-16} {1}" -f $Name, $EkuCatalog[$Name].Label)
}

Write-Host ''
Write-Host 'DNS SAN:' -ForegroundColor Yellow

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

        New-OpenSSLLeafConfig -Path $TempConfig -Spec $Spec

        # ----------------------------------------------------
        # Private key
        # ----------------------------------------------------

        if ($Algorithm -eq 'RSA') {

            $KeyArguments = @(
                'genpkey',
                '-algorithm', 'RSA',
                '-pkeyopt', "rsa_keygen_bits:$Bit",
                '-out', $PrivateKey
            )

            $KeyOperation = "Generate RSA $Bit-bit private key"
        }
        else {

            $KeyArguments = @(
                'genpkey',
                '-algorithm', 'EC',
                '-pkeyopt', "ec_paramgen_curve:$OpenSslCurve",
                '-pkeyopt', 'ec_param_enc:named_curve',
                '-out', $PrivateKey
            )

            $KeyOperation = "Generate ECC $Curve private key"
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

            Invoke-OpenSSL `
                -Arguments @(
                    'pkcs12', '-export',
                    '-out', $PFX,
                    '-inkey', $PrivateKey,
                    '-in', $Certificate,
                    '-certfile', $IntermediateCertificate,
                    '-name', $FriendlyName,
                    '-passout', "file:$PasswordFile"
                ) `
                -Operation 'Generate password-protected PFX' | Out-Null

            if (-not (Test-Path -LiteralPath $PFX -PathType Leaf)) {
                throw 'PFX was not created.'
            }

            # Prove the password actually opens the PFX before reporting success.
            Invoke-OpenSSL `
                -Arguments @('pkcs12', '-info', '-in', $PFX, '-noout', '-passin', "file:$PasswordFile") `
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

            Test-IssuedEvCertificate -CertificatePath $Certificate -Spec $Spec

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
        $ReportLines.Add("Algorithm            : $Algorithm")

        if ($Algorithm -eq 'RSA') {
            $ReportLines.Add("Key Size             : RSA $Bit")
        }
        else {
            $ReportLines.Add("Curve                : $Curve")
        }

        $ReportLines.Add("Signature Hash       : $($Hash.ToUpperInvariant())")
        $ReportLines.Add("Validity Days        : $Days")
        $ReportLines.Add("Certificate Serial   : $CertificateSerial")
        $ReportLines.Add('')
        $ReportLines.Add('EV Subject:')

        foreach ($Field in $EvProfile.DnFields) {
            $ReportLines.Add(("  {0,-26} = {1}" -f $Field.Key, (ConvertFrom-OpenSslConfValue -Raw $Field.Raw)))
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
