# ============================================================
# GenerateLeafCertificate.ps1
#
# Standalone Windows Local PKI Leaf Certificate Generator
#
# Author  : Nicko Satria Utama
# Company : Agantra Inovatif OÜ (NextMantra)
# Email   : nicko@nextmantra.com
#
# Purpose:
#   - Generate leaf private key
#   - Generate leaf public key
#   - Generate CSR
#   - Generate dynamic SAN certificate
#   - Sign leaf certificate using Intermediate CA
#   - Generate full chain
#   - Generate PFX
#   - Verify certificate chain
#
# IMPORTANT:
#   This is a PRIVATE PKI.
#   It is NOT a publicly trusted EV certificate.
#
# Repeated parameters are intentionally supported:
#
#   -Domain example.com
#   -Domain localhost
#   -Domain www.example.com
#
#   -WildcardDomain "*.example.com"
#   -WildcardDomain "*.internal.example.com"
#
#   -IP4 127.0.0.1
#   -IP4 192.168.1.100
#
#   -IP6 ::1
#   -IP6 fe80::1
#
#   -Email nicko@example.com
#   -Email admin@example.com
#
# Example:
#
# .\GenerateLeafCertificate.ps1 `
#     -Domain nextmantra.com `
#     -Domain localhost `
#     -Domain www.nextmantra.com `
#     -WildcardDomain "*.aaa.com" `
#     -WildcardDomain "*.bbbbbbb.net" `
#     -IP4 127.0.0.1 `
#     -IP6 ::1 `
#     -Bit 2048 `
#     -Days 825 `
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

$ConfigFile = Join-Path $ProjectRoot 'ev_pki.cnf'

$PKIRoot = Join-Path $ProjectRoot 'pki'

$RootCertificate = Join-Path $PKIRoot 'root\root.crt'

$IntermediateCertificate = Join-Path $PKIRoot 'intermediate\intermediate.crt'

$IntermediatePrivateKey = Join-Path $PKIRoot 'intermediate\intermediate.key'

$LeafRoot = Join-Path $ProjectRoot 'leafcerts'

$TempRoot = Join-Path $LeafRoot '_temp'

# ============================================================
# DEFAULT VALUES
# ============================================================

$Domains = New-Object System.Collections.Generic.List[string]

$WildcardDomains = New-Object System.Collections.Generic.List[string]

$IPv4Addresses = New-Object System.Collections.Generic.List[string]

$IPv6Addresses = New-Object System.Collections.Generic.List[string]

$EmailAddresses = New-Object System.Collections.Generic.List[string]

$Bit = 2048

$Days = 825

$CommonName = ''

$Force = $false

$NoPfx = $false

$NoVerify = $false

# ============================================================
# FUNCTIONS
# ============================================================

function Write-Header {
    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host 'GenerateLeafCertificate.ps1' -ForegroundColor Cyan
    Write-Host 'Standalone Windows Local PKI Leaf Generator' -ForegroundColor Cyan
    Write-Host 'Author : Nicko Satria Utama' -ForegroundColor Cyan
    Write-Host 'Company: Agantra Inovatif OÜ (NextMantra)' -ForegroundColor Cyan
    Write-Host 'Email  : nicko@nextmantra.com' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ''
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

    if ($Name -match '^\*\.[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$') {
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

    $Result = $Result.Replace('*', 'wildcard')

    return $Result
}

function New-OpenSSLLeafConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$LeafCommonName
    )

    $Lines = New-Object System.Collections.Generic.List[string]

    # --------------------------------------------------------
    # OIDs
    # --------------------------------------------------------

    $Lines.Add('oid_section = new_oids')
    $Lines.Add('')
    $Lines.Add('[ new_oids ]')
    $Lines.Add('evPolicy = 2.23.140.1.1')
    $Lines.Add('')

    # --------------------------------------------------------
    # REQUEST
    # --------------------------------------------------------

    $Lines.Add('[ req ]')
    $Lines.Add('prompt = no')
    $Lines.Add('utf8 = yes')
    $Lines.Add('string_mask = utf8only')
    $Lines.Add('default_md = sha256')
    $Lines.Add('distinguished_name = dn_leaf')
    $Lines.Add('req_extensions = v3_req')
    $Lines.Add('')

    # --------------------------------------------------------
    # SUBJECT
    # --------------------------------------------------------

    $Lines.Add('[ dn_leaf ]')
    $Lines.Add('businessCategory = Private Organization')
    $Lines.Add('jurisdictionCountryName = EE')
    $Lines.Add('serialNumber = 17344131')
    $Lines.Add('C = EE')
    $Lines.Add('L = Tallinn')
    $Lines.Add('O = Agantra Inovatif OU')
    $Lines.Add("CN = $(Convert-ToOpenSSLConfigValue $LeafCommonName)")
    $Lines.Add('')

    # --------------------------------------------------------
    # CSR EXTENSIONS
    # --------------------------------------------------------

    $Lines.Add('[ v3_req ]')
    $Lines.Add('basicConstraints = critical,CA:false')
    $Lines.Add('keyUsage = critical,digitalSignature,keyEncipherment')

    # IMPORTANT:
    # Keep the EKU declaration on ONE physical line.
    $Lines.Add(
        'extendedKeyUsage = serverAuth,clientAuth,codeSigning,emailProtection,timeStamping,1.3.6.1.4.1.311.20.2.2,1.3.6.1.5.5.7.3.17,1.3.6.1.5.5.7.3.5,1.3.6.1.5.5.7.3.6,1.3.6.1.5.5.7.3.7,1.3.6.1.4.1.311.10.3.3,2.16.840.1.113730.4.1'
    )

    $Lines.Add('subjectKeyIdentifier = hash')
    $Lines.Add('subjectAltName = @leaf_san')
    $Lines.Add('')

    # --------------------------------------------------------
    # FINAL CERTIFICATE EXTENSIONS
    # --------------------------------------------------------

    $Lines.Add('[ v3_leaf ]')
    $Lines.Add('basicConstraints = critical,CA:false')
    $Lines.Add('keyUsage = critical,digitalSignature,keyEncipherment')

    # IMPORTANT:
    # Keep the EKU declaration on ONE physical line.
    $Lines.Add(
        'extendedKeyUsage = serverAuth,clientAuth,codeSigning,emailProtection,timeStamping,1.3.6.1.4.1.311.20.2.2,1.3.6.1.5.5.7.3.17,1.3.6.1.5.5.7.3.5,1.3.6.1.5.5.7.3.6,1.3.6.1.5.5.7.3.7,1.3.6.1.4.1.311.10.3.3,2.16.840.1.113730.4.1'
    )

    $Lines.Add('subjectKeyIdentifier = hash')
    $Lines.Add('authorityKeyIdentifier = keyid,issuer')
    $Lines.Add('subjectAltName = @leaf_san')
    $Lines.Add('certificatePolicies = @ev_policy')
    $Lines.Add('')

    # --------------------------------------------------------
    # POLICY
    # --------------------------------------------------------

    $Lines.Add('[ ev_policy ]')
    $Lines.Add('policyIdentifier = 2.23.140.1.1')
    $Lines.Add('CPS.1 = https://cps.nextmantra.com/ev_cps.pdf')
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

    foreach ($Wildcard in $WildcardDomains) {
        $SafeWildcard = Convert-ToOpenSSLConfigValue $Wildcard
        $Lines.Add("DNS.$DnsIndex = $SafeWildcard")
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
    # WRITE ASCII
    #
    # Avoid UTF-8 BOM because OpenSSL configuration parsing
    # can be sensitive to encoding.
    # --------------------------------------------------------

    $Content = $Lines -join [Environment]::NewLine

    [System.IO.File]::WriteAllText(
        $Path,
        $Content,
        [System.Text.Encoding]::ASCII
    )
}

# ============================================================
# HEADER
# ============================================================

Write-Header

# ============================================================
# OPENSSL CHECK
# ============================================================

if (-not (Test-Path -LiteralPath $OpenSSL -PathType Leaf)) {
    Fail "OpenSSL executable not found: $OpenSSL"
}

if (-not (Test-Path -LiteralPath $ConfigFile -PathType Leaf)) {
    Fail "OpenSSL PKI configuration not found: $ConfigFile"
}

if (-not (Test-Path -LiteralPath $RootCertificate -PathType Leaf)) {
    Fail "Root CA certificate not found: $RootCertificate"
}

if (-not (Test-Path -LiteralPath $IntermediateCertificate -PathType Leaf)) {
    Fail "Intermediate CA certificate not found: $IntermediateCertificate"
}

if (-not (Test-Path -LiteralPath $IntermediatePrivateKey -PathType Leaf)) {
    Fail "Intermediate CA private key not found: $IntermediatePrivateKey"
}

# ============================================================
# PARSE REPEATED PARAMETERS
# ============================================================

$Arguments = @($args)

if ($Arguments.Count -eq 0) {
    Fail @"
No parameters supplied.

Example:

.\GenerateLeafCertificate.ps1 `
    -Domain nextmantra.com `
    -Domain localhost `
    -Domain www.nextmantra.com `
    -WildcardDomain "*.aaa.com" `
    -WildcardDomain "*.bbbbbbb.net" `
    -IP4 127.0.0.1 `
    -IP6 ::1 `
    -Bit 2048 `
    -Days 825 `
    -Force
"@
}

$Index = 0

while ($Index -lt $Arguments.Count) {

    $Token = [string]$Arguments[$Index]

    switch -Regex ($Token.ToLowerInvariant()) {

        '^-domain$' {

            $Value = Test-CommandArgumentValue `
                -ParameterName '-Domain' `
                -Index $Index `
                -Arguments $Arguments

            if (-not (Test-DnsName $Value)) {
                Fail "Invalid DNS domain: $Value"
            }

            Add-UniqueValue -List $Domains -Value $Value

            $Index += 2
            continue
        }

        '^\-wildcarddomain$|^\-wildcard$' {

            $Value = Test-CommandArgumentValue `
                -ParameterName $Token `
                -Index $Index `
                -Arguments $Arguments

            if (-not $Value.StartsWith('*.')) {
                Fail "Wildcard domain must start with '*.' : $Value"
            }

            if (-not (Test-DnsName $Value)) {
                Fail "Invalid wildcard DNS domain: $Value"
            }

            Add-UniqueValue `
                -List $WildcardDomains `
                -Value $Value

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

        '^-bit$' {

            $Value = Test-CommandArgumentValue `
                -ParameterName '-Bit' `
                -Index $Index `
                -Arguments $Arguments

            $ParsedBit = 0

            if (-not [int]::TryParse($Value, [ref]$ParsedBit)) {
                Fail "Invalid -Bit value: $Value"
            }

            if ($ParsedBit -lt 2048 -or $ParsedBit -gt 16384) {
                Fail "-Bit must be between 2048 and 16384."
            }

            $Bit = $ParsedBit

            $Index += 2
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

            if ($ParsedDays -lt 1 -or $ParsedDays -gt 3650) {
                Fail "-Days must be between 1 and 3650."
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

            $CommonName = $Value

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

# ============================================================
# VALIDATE INPUT
# ============================================================

if ($Domains.Count -eq 0 -and $WildcardDomains.Count -eq 0) {
    Fail "At least one -Domain or -WildcardDomain is required."
}

if ($Domains.Count -eq 0) {
    $CommonName = $WildcardDomains[0]
}
elseif ([string]::IsNullOrWhiteSpace($CommonName)) {
    $CommonName = $Domains[0]
}

if (-not (Test-DnsName $CommonName)) {
    Fail "Invalid Common Name: $CommonName"
}

# ============================================================
# DISPLAY REQUEST
# ============================================================

Write-Host ''
Write-Host 'Certificate Request' -ForegroundColor Yellow
Write-Host '------------------------------------------------------------'

Write-Host "Common Name       : $CommonName"
Write-Host "Key Size          : $Bit"
Write-Host "Validity          : $Days days"
Write-Host "Force             : $Force"
Write-Host "Generate PFX      : $(-not $NoPfx)"
Write-Host "Verify            : $(-not $NoVerify)"

Write-Host ''
Write-Host 'DNS SAN:' -ForegroundColor Yellow

foreach ($Domain in $Domains) {
    Write-Host "  DNS : $Domain"
}

foreach ($Wildcard in $WildcardDomains) {
    Write-Host "  DNS : $Wildcard"
}

Write-Host ''
Write-Host 'IPv4 SAN:' -ForegroundColor Yellow

foreach ($IPv4 in $IPv4Addresses) {
    Write-Host "  IP4 : $IPv4"
}

Write-Host ''
Write-Host 'IPv6 SAN:' -ForegroundColor Yellow

foreach ($IPv6 in $IPv6Addresses) {
    Write-Host "  IP6 : $IPv6"
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

# ============================================================
# OUTPUT FILE NAME
# ============================================================

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

    Info "Removing existing certificate directory."

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
# OUTPUT FILES
# ============================================================

$PrivateKey = Join-Path $LeafDirectory "$BaseName.key"

$PublicKey = Join-Path $LeafDirectory "$BaseName.pub"

$CSR = Join-Path $LeafDirectory "$BaseName.csr"

$Certificate = Join-Path $LeafDirectory "$BaseName.crt"

$FullChain = Join-Path $LeafDirectory "$BaseName-fullchain.crt"

$PFX = Join-Path $LeafDirectory "$BaseName.pfx"

$Report = Join-Path $LeafDirectory "$BaseName.txt"

$TempConfig = Join-Path `
    $TempRoot `
    "$BaseName-$([Guid]::NewGuid().ToString('N')).cnf"

# ============================================================
# CREATE TEMP OPENSSL CONFIG
# ============================================================

Info 'Creating runtime OpenSSL configuration.'

New-OpenSSLLeafConfig `
    -Path $TempConfig `
    -LeafCommonName $CommonName

# ============================================================
# GENERATE PRIVATE KEY
# ============================================================

try {

    $KeyArguments = @(
        'genpkey',
        '-algorithm', 'RSA',
        '-pkeyopt', "rsa_keygen_bits:$Bit",
        '-out', $PrivateKey
    )

    Invoke-OpenSSL `
        -Arguments $KeyArguments `
        -Operation "Generate RSA $Bit-bit private key"

    if (-not (Test-Path -LiteralPath $PrivateKey -PathType Leaf)) {
        throw 'Private key was not created.'
    }

    Success "Private key created: $PrivateKey"

    # ========================================================
    # GENERATE PUBLIC KEY
    # ========================================================

    $PublicKeyArguments = @(
        'pkey',
        '-in', $PrivateKey,
        '-pubout',
        '-out', $PublicKey
    )

    Invoke-OpenSSL `
        -Arguments $PublicKeyArguments `
        -Operation 'Generate public key'

    if (-not (Test-Path -LiteralPath $PublicKey -PathType Leaf)) {
        throw 'Public key was not created.'
    }

    Success "Public key created: $PublicKey"

    # ========================================================
    # GENERATE CSR
    # ========================================================

    $CSRArguments = @(
        'req',
        '-new',
        '-sha256',
        '-config', $TempConfig,
        '-key', $PrivateKey,
        '-out', $CSR
    )

    Invoke-OpenSSL `
        -Arguments $CSRArguments `
        -Operation 'Generate certificate signing request'

    if (-not (Test-Path -LiteralPath $CSR -PathType Leaf)) {
        throw 'CSR was not created.'
    }

    Success "CSR created: $CSR"

    # ========================================================
    # GENERATE UNIQUE CERTIFICATE SERIAL
    # ========================================================

    $CertificateSerial = New-RandomCertificateSerial

    Info "Certificate serial: $CertificateSerial"

    # ========================================================
    # SIGN LEAF CERTIFICATE
    # ========================================================

    $CertificateArguments = @(
        'x509',
        '-req',
        '-sha256',
        '-days', $Days.ToString(),
        '-in', $CSR,
        '-CA', $IntermediateCertificate,
        '-CAkey', $IntermediatePrivateKey,
        '-set_serial', "0x$CertificateSerial",
        '-extfile', $TempConfig,
        '-extensions', 'v3_leaf',
        '-out', $Certificate
    )

    Invoke-OpenSSL `
        -Arguments $CertificateArguments `
        -Operation 'Sign leaf certificate with Intermediate CA'

    if (-not (Test-Path -LiteralPath $Certificate -PathType Leaf)) {
        throw 'Leaf certificate was not created.'
    }

    Success "Leaf certificate created: $Certificate"

    # ========================================================
    # CREATE FULL CHAIN
    # ========================================================

    Info 'Creating full certificate chain.'

    $LeafContent = Get-Content `
        -LiteralPath $Certificate `
        -Raw

    $IntermediateContent = Get-Content `
        -LiteralPath $IntermediateCertificate `
        -Raw

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

    if (-not (Test-Path -LiteralPath $FullChain -PathType Leaf)) {
        throw 'Full chain was not created.'
    }

    Success "Full chain created: $FullChain"

    # ========================================================
    # GENERATE PFX
    # ========================================================

       if (-not $NoPfx) {

        Write-Host ''
        Write-Host 'PFX Password Required' -ForegroundColor Yellow

        $SecurePassword  = Read-Host 'Enter PFX password'   -AsSecureString
        $SecureConfirm   = Read-Host 'Confirm PFX password' -AsSecureString

        $PlainPassword = ConvertFrom-SecureString -SecureString $SecurePassword -AsPlainText
        $PlainConfirm  = ConvertFrom-SecureString -SecureString $SecureConfirm  -AsPlainText

        $PasswordFile = Join-Path $TempRoot "$([Guid]::NewGuid().ToString('N')).pwd"

        try {

            if ([string]::IsNullOrEmpty($PlainPassword)) {
                throw 'PFX password cannot be empty.'
            }

            if ($PlainPassword -cne $PlainConfirm) {
                throw 'PFX passwords do not match.'
            }

            # UTF-8 WITHOUT BOM, and no trailing newline.
            # (Encoding.UTF8 adds a BOM, which silently becomes part of the password.)
            $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

            [System.IO.File]::WriteAllBytes(
                $PasswordFile,
                $Utf8NoBom.GetBytes($PlainPassword)
            )

            $PFXArguments = @(
                'pkcs12',
                '-export',
                '-out', $PFX,
                '-inkey', $PrivateKey,
                '-in', $Certificate,
                '-certfile', $IntermediateCertificate,
                '-name', $CommonName,
                '-passout', "file:$PasswordFile"
            )

            Invoke-OpenSSL `
                -Arguments $PFXArguments `
                -Operation 'Generate password-protected PFX'

            if (-not (Test-Path -LiteralPath $PFX -PathType Leaf)) {
                throw 'PFX was not created.'
            }

            # Prove the password actually opens the PFX before reporting success.
            $PFXCheckArguments = @(
                'pkcs12',
                '-info',
                '-in', $PFX,
                '-noout',
                '-passin', "file:$PasswordFile"
            )

            Invoke-OpenSSL `
                -Arguments $PFXCheckArguments `
                -Operation 'Verify PFX password'

            Success "PFX created and password verified: $PFX"
        }
        finally {

            if (Test-Path -LiteralPath $PasswordFile) {
                Remove-Item -LiteralPath $PasswordFile -Force -ErrorAction SilentlyContinue
            }

            $PlainPassword = $null
            $PlainConfirm  = $null
        }
    }
    else {
        Info 'PFX generation disabled by -NoPfx.'
    }

    # ========================================================
    # VERIFY CERTIFICATE
    # ========================================================

    if (-not $NoVerify) {

        Write-Host ''
        Write-Host 'Certificate Verification' -ForegroundColor Yellow

        $VerifyArguments = @(
            'verify',
            '-CAfile', $RootCertificate,
            '-untrusted', $IntermediateCertificate,
            $Certificate
        )

        Invoke-OpenSSL `
            -Arguments $VerifyArguments `
            -Operation 'Verify certificate chain'

        Success 'Certificate chain verification passed.'

        # ----------------------------------------------------
        # CERTIFICATE TEXT
        # ----------------------------------------------------

        $CertificateTextArguments = @(
            'x509',
            '-in', $Certificate,
            '-text',
            '-noout'
        )

        $CertificateText = Invoke-OpenSSL `
            -Arguments $CertificateTextArguments `
            -Operation 'Inspect certificate'

        $CertificateTextString = (
            $CertificateText -join [Environment]::NewLine
        )

        # ----------------------------------------------------
        # REQUIRED VALIDATIONS
        # ----------------------------------------------------

        if ($CertificateTextString -notmatch 'CA:FALSE') {
            throw 'Validation failed: certificate is not marked CA:FALSE.'
        }

        if ($CertificateTextString -notmatch 'Digital Signature') {
            throw 'Validation failed: Digital Signature key usage missing.'
        }

        if ($CertificateTextString -notmatch 'Key Encipherment') {
            throw 'Validation failed: Key Encipherment key usage missing.'
        }

        if ($CertificateTextString -notmatch 'TLS Web Server Authentication') {
            throw 'Validation failed: serverAuth EKU missing.'
        }

        if ($CertificateTextString -notmatch 'Certificate Policies') {
            throw 'Validation failed: Certificate Policies extension missing.'
        }

        if ($CertificateTextString -notmatch '2\.23\.140\.1\.1') {
            throw 'Validation failed: EV policy OID 2.23.140.1.1 missing.'
        }

        if ($CertificateTextString -notmatch 'Subject Alternative Name') {
            throw 'Validation failed: Subject Alternative Name missing.'
        }

        Success 'CA:FALSE validation passed.'
        Success 'Key Usage validation passed.'
        Success 'Server Authentication EKU validation passed.'
        Success 'Certificate Policy validation passed.'
        Success 'Subject Alternative Name validation passed.'
    }
    else {

        Warn 'Certificate verification disabled by -NoVerify.'
    }

    # ========================================================
    # WRITE REPORT
    # ========================================================

    $ReportLines = New-Object System.Collections.Generic.List[string]

    $ReportLines.Add(
        '============================================================'
    )

    $ReportLines.Add(
        'NextMantra Private PKI Leaf Certificate Report'
    )

    $ReportLines.Add(
        '============================================================'
    )

    $ReportLines.Add("Generated            : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $ReportLines.Add("Common Name          : $CommonName")
    $ReportLines.Add("Key Size             : $Bit")
    $ReportLines.Add("Validity Days        : $Days")
    $ReportLines.Add("Certificate Serial   : $CertificateSerial")
    $ReportLines.Add('')

    $ReportLines.Add('DNS SAN:')

    foreach ($Domain in $Domains) {
        $ReportLines.Add("  DNS: $Domain")
    }

    foreach ($Wildcard in $WildcardDomains) {
        $ReportLines.Add("  DNS: $Wildcard")
    }

    $ReportLines.Add('')

    $ReportLines.Add('IPv4 SAN:')

    foreach ($IPv4 in $IPv4Addresses) {
        $ReportLines.Add("  IP4: $IPv4")
    }

    $ReportLines.Add('')

    $ReportLines.Add('IPv6 SAN:')

    foreach ($IPv6 in $IPv6Addresses) {
        $ReportLines.Add("  IP6: $IPv6")
    }

    $ReportLines.Add('')

    $ReportLines.Add('Email SAN:')

    foreach ($Email in $EmailAddresses) {
        $ReportLines.Add("  MAIL: $Email")
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
    $ReportLines.Add('  2.23.140.1.1')

    $ReportLines.Add('')
    $ReportLines.Add('EKU:')
    $ReportLines.Add('  serverAuth')
    $ReportLines.Add('  clientAuth')
    $ReportLines.Add('  codeSigning')
    $ReportLines.Add('  emailProtection')
    $ReportLines.Add('  timeStamping')
    $ReportLines.Add('  1.3.6.1.4.1.311.20.2.2')
    $ReportLines.Add('  1.3.6.1.5.5.7.3.17')
    $ReportLines.Add('  1.3.6.1.5.5.7.3.5')
    $ReportLines.Add('  1.3.6.1.5.5.7.3.6')
    $ReportLines.Add('  1.3.6.1.5.5.7.3.7')
    $ReportLines.Add('  1.3.6.1.4.1.311.10.3.3')
    $ReportLines.Add('  2.16.840.1.113730.4.1')

    [System.IO.File]::WriteAllLines(
        $Report,
        $ReportLines,
        [System.Text.Encoding]::UTF8
    )

    Success "Certificate report created: $Report"

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

    # ========================================================
    # REMOVE TEMP CONFIG
    # ========================================================

    if (Test-Path -LiteralPath $TempConfig) {

        Remove-Item `
            -LiteralPath $TempConfig `
            -Force `
            -ErrorAction SilentlyContinue
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

Write-Host "Output Directory:" -ForegroundColor Cyan
Write-Host "  $LeafDirectory"
Write-Host ''

Write-Host "Files:" -ForegroundColor Cyan
Write-Host "  Private Key : $PrivateKey"
Write-Host "  Public Key  : $PublicKey"
Write-Host "  CSR         : $CSR"
Write-Host "  Certificate : $Certificate"
Write-Host "  Full Chain  : $FullChain"

if (-not $NoPfx) {
    Write-Host "  PFX         : $PFX"
}

Write-Host "  Report      : $Report"

Write-Host ''
Write-Host '============================================================' -ForegroundColor Green