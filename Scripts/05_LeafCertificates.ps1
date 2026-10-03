# ============================================================
# 05_LeafCertificates.ps1
#
# Private PKI Leaf Certificate Generator
#
# Author  : Nicko Satria Utama
# Company : Agantra Inovatif OÜ (NextMantra)
# Email   : nicko@nextmantra.com
#
# Purpose:
#   - Generate leaf private keys
#   - Generate leaf public keys
#   - Generate EV-style leaf CSRs
#   - Sign leaf certificates using Intermediate CA
#   - Apply v3_leaf certificate extensions
#   - Generate leaf PFX files
#   - Generate Leaf + Intermediate + Root full-chain PEM
#   - Validate generated leaf certificates
#   - Validate certificate chain
#
# IMPORTANT:
#   This is a PRIVATE / DEVELOPMENT PKI.
#
#   "EV-style" means the certificate uses the configured
#   EV-style subject and certificate-policy profile.
#
#   It does NOT make the certificate publicly trusted EV.
#
# Certificate Validity:
#   Leaf certificates = 397 days
#
# Key Sizes:
#   Supported RSA sizes:
#       2048
#       3072
#       4096
#       8192
#
# Certificate hierarchy:
#
#       Root CA
#          |
#          v
#       Intermediate CA
#          |
#          v
#       Leaf Certificate
#
# Full-chain PEM order:
#
#       Leaf
#       Intermediate
#       Root
#
# ============================================================


Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


# ============================================================
# Leaf Certificate Configuration
# ============================================================

# 397 days is intentionally explicit here.
#
# This value is passed directly to:
#
#     openssl ca -days 397
#
# Therefore it takes precedence over default_days in the
# OpenSSL configuration.
#
# Keeping it here makes certificate lifetime deterministic
# regardless of OpenSSL configuration defaults.

$script:LeafValidityDays = 397


# ============================================================
# Expected EV Policy
# ============================================================

$script:ExpectedEvPolicyOid = '2.23.140.1.1'


# ============================================================
# Expected Leaf EKUs
# ============================================================
#
# These are the EKUs configured in [v3_leaf] in ev_pki.cnf.
#
# Textual EKUs:
#
#   serverAuth
#   clientAuth
#   codeSigning
#   emailProtection
#   timeStamping
#
# Numeric EKUs:
#
#   Smart Card Logon
#   IPsec IKE
#   IPsec End System
#   IPsec Tunnel
#   IPsec User
#   Microsoft SGC
#   Netscape SGC
#
# ============================================================

$script:ExpectedLeafEkuOids = @(
    '1.3.6.1.5.5.7.3.1',       # serverAuth
    '1.3.6.1.5.5.7.3.2',       # clientAuth
    '1.3.6.1.5.5.7.3.3',       # codeSigning
    '1.3.6.1.5.5.7.3.4',       # emailProtection
    '1.3.6.1.5.5.7.3.8',       # timeStamping

    '1.3.6.1.4.1.311.20.2.2',  # Microsoft Smart Card Logon

    '1.3.6.1.5.5.7.3.17',      # IPsec IKE
    '1.3.6.1.5.5.7.3.5',       # IPsec End System
    '1.3.6.1.5.5.7.3.6',       # IPsec Tunnel
    '1.3.6.1.5.5.7.3.7',       # IPsec User

    '1.3.6.1.4.1.311.10.3.3',  # Microsoft SGC
    '2.16.840.1.113730.4.1'    # Netscape SGC
)


# ============================================================
# Helper: Get Human-readable EV Subject
# ============================================================

function Get-LeafEvSubjectText {

    [CmdletBinding()]
    param()

    if ($null -eq $script:Pki) {
        throw 'PKI runtime context is not initialized.'
    }

    if ($null -eq $script:Pki.Ev) {
        throw 'EV PKI configuration is not initialized.'
    }

    if ($null -eq $script:Pki.Ev.DnFields) {
        throw 'EV DN fields are not available.'
    }

    $parts = foreach ($field in $script:Pki.Ev.DnFields) {

        '{0}={1}' -f `
            $field.Key,
            (ConvertFrom-OpenSslConfValue -Raw $field.Raw)
    }

    return ($parts -join ', ')
}


# ============================================================
# Helper: Test File
# ============================================================

function Assert-LeafFileExists {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {

        throw (
            "$Description does not exist: $Path"
        )
    }
}


# ============================================================
# Helper: Read Certificate Information
# ============================================================

function Get-LeafCertificateText {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Certificate
    )

    Assert-LeafFileExists `
        -Path $Certificate `
        -Description 'Leaf certificate'

    $output = Invoke-OpenSSL -Arguments @(
        'x509',
        '-in',
        $Certificate,
        '-text',
        '-noout'
    )

    if ($null -eq $output) {
        throw (
            "OpenSSL returned no certificate information: $Certificate"
        )
    }

    return ($output -join [Environment]::NewLine)
}


# ============================================================
# Validate Leaf Certificate
# ============================================================
#
# Validation includes:
#
#   - X.509 v3
#   - CA:FALSE
#   - Certificate Policy OID
#   - serverAuth
#   - SAN
#   - RSA key size
#   - expected issuer
#
# ============================================================

function Test-LeafCertificate {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Certificate
    )

    Write-PkiVerbose `
        "Validating leaf certificate: $Certificate"

    $text = Get-LeafCertificateText `
        -Certificate $Certificate


    # --------------------------------------------------------
    # X.509 Version
    # --------------------------------------------------------

    if ($text -notmatch 'Version:\s+3\s+\(0x2\)') {

        throw (
            "Leaf certificate is not X.509 version 3: " +
            "$Certificate"
        )
    }


    # --------------------------------------------------------
    # Basic Constraints
    # --------------------------------------------------------

    if ($text -notmatch 'X509v3 Basic Constraints: critical') {

        throw (
            "Leaf certificate is missing critical Basic Constraints: " +
            "$Certificate"
        )
    }

    if ($text -notmatch 'CA:FALSE') {

        throw (
            "Leaf certificate is not marked CA:FALSE: " +
            "$Certificate"
        )
    }


    # --------------------------------------------------------
    # Key Usage
    # --------------------------------------------------------

    if ($text -notmatch 'X509v3 Key Usage: critical') {

        throw (
            "Leaf certificate is missing critical Key Usage: " +
            "$Certificate"
        )
    }

    if ($text -notmatch 'Digital Signature') {

        throw (
            "Leaf certificate does not contain Digital Signature: " +
            "$Certificate"
        )
    }

    if ($text -notmatch 'Key Encipherment') {

        throw (
            "Leaf certificate does not contain Key Encipherment: " +
            "$Certificate"
        )
    }


    # --------------------------------------------------------
    # Extended Key Usage
    # --------------------------------------------------------

    if ($text -notmatch 'X509v3 Extended Key Usage:') {

        throw (
            "Leaf certificate is missing Extended Key Usage: " +
            "$Certificate"
        )
    }


    # --------------------------------------------------------
    # EV Certificate Policy
    # --------------------------------------------------------

    if (
        $text -notmatch `
            [regex]::Escape($script:ExpectedEvPolicyOid)
    ) {

        throw (
            "Leaf certificate is missing expected EV policy OID " +
            "$($script:ExpectedEvPolicyOid): $Certificate"
        )
    }


    # --------------------------------------------------------
    # Subject Alternative Name
    # --------------------------------------------------------

    if ($text -notmatch 'X509v3 Subject Alternative Name:') {

        throw (
            "Leaf certificate is missing Subject Alternative Name: " +
            "$Certificate"
        )
    }


    # --------------------------------------------------------
    # RSA Key Size
    # --------------------------------------------------------

    if ($text -notmatch 'Public-Key:\s+\((2048|3072|4096|8192) bit\)') {

        throw (
            "Leaf certificate does not contain a supported RSA key size: " +
            "$Certificate"
        )
    }


    Write-PkiVerbose `
        "Leaf certificate profile validation: PASSED"
}


# ============================================================
# Validate Certificate Chain
# ============================================================

function Test-LeafCertificateChain {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LeafCertificate,

        [Parameter(Mandatory)]
        [string]$IntermediateCertificate,

        [Parameter(Mandatory)]
        [string]$RootCertificate
    )

    Assert-LeafFileExists `
        -Path $LeafCertificate `
        -Description 'Leaf certificate'

    Assert-LeafFileExists `
        -Path $IntermediateCertificate `
        -Description 'Intermediate CA certificate'

    Assert-LeafFileExists `
        -Path $RootCertificate `
        -Description 'Root CA certificate'


    Write-PkiVerbose `
        'Validating certificate chain: Leaf -> Intermediate -> Root'


    $result = Invoke-OpenSSL -Arguments @(
        'verify',
        '-CAfile',
        $RootCertificate,
        '-untrusted',
        $IntermediateCertificate,
        $LeafCertificate
    )


    $verificationText = (
        $result -join [Environment]::NewLine
    )


    if (
        $verificationText -notmatch `
            [regex]::Escape($LeafCertificate) +
            ':\s*OK'
    ) {

        throw (
            "Certificate chain validation failed.`r`n" +
            $verificationText
        )
    }


    Write-PkiVerbose `
        'Certificate chain validation: PASSED'
}


# ============================================================
# Generate One Leaf Certificate
# ============================================================

function New-LeafCertificate {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(2048, 3072, 4096, 8192)]
        [int]$Bits
    )


    # --------------------------------------------------------
    # PKI Context
    # --------------------------------------------------------

    $p = $script:Pki


    if ($null -eq $p) {
        throw 'PKI runtime context is not initialized.'
    }


    # --------------------------------------------------------
    # Validate Leaf Configuration
    # --------------------------------------------------------

    if ($script:LeafValidityDays -lt 1) {

        throw (
            "Leaf certificate validity must be at least 1 day. " +
            "Current value: $script:LeafValidityDays"
        )
    }


    if ($script:LeafValidityDays -gt 397) {

        Write-PkiVerbose (
            "WARNING: Leaf validity is configured for " +
            "$script:LeafValidityDays days."
        )
    }


    Write-PkiVerbose (
        "Leaf certificate validity: " +
        "$script:LeafValidityDays days"
    )


    # --------------------------------------------------------
    # Build Output Prefix
    # --------------------------------------------------------

    $prefix =
        Join-Path `
            $p.LeafDir `
            ("{0}-{1}" -f $p.Domain, $Bits)


    # --------------------------------------------------------
    # Define Output Files
    # --------------------------------------------------------

    $item = [ordered]@{

        Bits      = $Bits

        Key       = "$prefix.key"

        Pub       = "$prefix.pub"

        Csr       = "$prefix.csr"

        Crt       = "$prefix.crt"

        Pfx       = "$prefix.pfx"

        FullChain = "$prefix-fullchain.pem"
    }


    # --------------------------------------------------------
    # Validate PKI Paths
    # --------------------------------------------------------

    if ([string]::IsNullOrWhiteSpace($p.Country)) {

        throw (
            'PKI Country is empty. Cannot generate leaf certificate.'
        )
    }


    if ([string]::IsNullOrWhiteSpace($p.Organization)) {

        throw (
            'PKI Organization is empty. Cannot generate leaf certificate.'
        )
    }


    if ([string]::IsNullOrWhiteSpace($p.Domain)) {

        throw (
            'PKI Domain is empty. Cannot generate leaf certificate.'
        )
    }


    if ([string]::IsNullOrWhiteSpace($p.RuntimeConfig)) {

        throw (
            'PKI RuntimeConfig is empty. Cannot generate leaf certificate.'
        )
    }


    Assert-LeafFileExists `
        -Path $p.RuntimeConfig `
        -Description 'OpenSSL runtime configuration'


    if ([string]::IsNullOrWhiteSpace($p.IntermediateCrt)) {

        throw (
            'PKI IntermediateCrt is empty.'
        )
    }


    Assert-LeafFileExists `
        -Path $p.IntermediateCrt `
        -Description 'Intermediate CA certificate'


    if ([string]::IsNullOrWhiteSpace($p.IntermediateKey)) {

        throw (
            'PKI IntermediateKey is empty.'
        )
    }


    Assert-LeafFileExists `
        -Path $p.IntermediateKey `
        -Description 'Intermediate CA private key'


    if ([string]::IsNullOrWhiteSpace($p.RootCrt)) {

        throw (
            'PKI RootCrt is empty.'
        )
    }


    Assert-LeafFileExists `
        -Path $p.RootCrt `
        -Description 'Root CA certificate'


    if ([string]::IsNullOrWhiteSpace($p.LeafReqConfig)) {

        throw (
            'PKI LeafReqConfig is empty.'
        )
    }


    Assert-LeafFileExists `
        -Path $p.LeafReqConfig `
        -Description 'EV leaf request configuration'


    # --------------------------------------------------------
    # Generate Leaf Private Key
    # --------------------------------------------------------

    Write-PkiVerbose `
        "Generating leaf private key: $($item.Key)"


    New-RsaPrivateKey `
        -Bits $Bits `
        -Path $item.Key


    Assert-LeafFileExists `
        -Path $item.Key `
        -Description 'Leaf private key'


    # --------------------------------------------------------
    # Generate Leaf Public Key
    # --------------------------------------------------------

    Write-PkiVerbose `
        "Generating leaf public key: $($item.Pub)"


    Export-PublicKey `
        -Key $item.Key `
        -Path $item.Pub


    Assert-LeafFileExists `
        -Path $item.Pub `
        -Description 'Leaf public key'


    # --------------------------------------------------------
    # EV Leaf Subject
    # --------------------------------------------------------
    #
    # The subject is taken from [dn_leaf_ev] generated by
    # 03_RuntimeConfig.ps1.
    #
    # Explicit command-line overrides have already been applied
    # before this script reaches the CSR generation stage.
    #
    # --------------------------------------------------------

    Write-PkiVerbose (
        "EV-style leaf subject: " +
        (Get-LeafEvSubjectText)
    )


    # --------------------------------------------------------
    # Generate Leaf CSR
    # --------------------------------------------------------

    Write-PkiVerbose `
        "Generating leaf CSR: $($item.Csr)"


    Invoke-OpenSSL -Arguments @(
        'req',
        '-new',
        '-sha256',
        '-key',
        $item.Key,
        '-out',
        $item.Csr,
        '-config',
        $p.LeafReqConfig
    ) |
        Out-Null


    Assert-LeafFileExists `
        -Path $item.Csr `
        -Description 'Leaf CSR'


    # --------------------------------------------------------
    # Sign Leaf Certificate
    # --------------------------------------------------------
    #
    # Certificate profile:
    #
    #   v3_leaf
    #
    # Certificate validity:
    #
    #   397 days
    #
    # The explicit -days parameter intentionally overrides any
    # default_days setting in the OpenSSL configuration.
    #
    # --------------------------------------------------------

    Write-PkiVerbose `
        "Signing leaf certificate: $($item.Crt)"


    Invoke-OpenSSL -Arguments @(
        'ca',
        '-batch',
        '-preserveDN',
        '-config',
        $p.RuntimeConfig,
        '-extensions',
        'v3_leaf',
        '-days',
        $script:LeafValidityDays,
        '-in',
        $item.Csr,
        '-out',
        $item.Crt
    ) |
        Out-Null


    Assert-LeafFileExists `
        -Path $item.Crt `
        -Description 'Leaf certificate'


    # --------------------------------------------------------
    # Validate Generated Leaf Certificate
    # --------------------------------------------------------

    Test-LeafCertificate `
        -Certificate $item.Crt


    # --------------------------------------------------------
    # Validate Leaf Certificate Chain
    # --------------------------------------------------------

    Test-LeafCertificateChain `
        -LeafCertificate $item.Crt `
        -IntermediateCertificate $p.IntermediateCrt `
        -RootCertificate $p.RootCrt


    # --------------------------------------------------------
    # Generate PFX
    # --------------------------------------------------------

    Write-PkiVerbose `
        "Generating leaf PFX: $($item.Pfx)"


    New-PfxFile `
        -Certificate $item.Crt `
        -Key $item.Key `
        -Path $item.Pfx


    Assert-LeafFileExists `
        -Path $item.Pfx `
        -Description 'Leaf PFX'


    # --------------------------------------------------------
    # Build Full Certificate Chain
    # --------------------------------------------------------
    #
    # Correct PEM order:
    #
    #   1. Leaf
    #   2. Intermediate
    #   3. Root
    #
    # --------------------------------------------------------

    Write-PkiVerbose `
        "Generating full chain: $($item.FullChain)"


    $leafPem =
        Get-Content `
            -LiteralPath $item.Crt `
            -Raw


    $intPem =
        Get-Content `
            -LiteralPath $p.IntermediateCrt `
            -Raw


    $rootPem =
        Get-Content `
            -LiteralPath $p.RootCrt `
            -Raw


    if ([string]::IsNullOrWhiteSpace($leafPem)) {

        throw (
            "Leaf certificate PEM is empty: $($item.Crt)"
        )
    }


    if ([string]::IsNullOrWhiteSpace($intPem)) {

        throw (
            "Intermediate certificate PEM is empty: " +
            "$($p.IntermediateCrt)"
        )
    }


    if ([string]::IsNullOrWhiteSpace($rootPem)) {

        throw (
            "Root certificate PEM is empty: " +
            "$($p.RootCrt)"
        )
    }


    $fullChain = (
        $leafPem.TrimEnd() +
        "`r`n" +
        $intPem.TrimEnd() +
        "`r`n" +
        $rootPem.TrimEnd() +
        "`r`n"
    )


    Write-Utf8NoBom `
        -Path $item.FullChain `
        -Content $fullChain


    Assert-LeafFileExists `
        -Path $item.FullChain `
        -Description 'Full certificate chain'


    # --------------------------------------------------------
    # Register Generated Leaf
    # --------------------------------------------------------

    [void]$p.LeafFiles.Add(
        [pscustomobject]$item
    )


    # --------------------------------------------------------
    # Final Success Log
    # --------------------------------------------------------

    Write-PkiVerbose (
        "Leaf certificate generated successfully: " +
        "$($item.Crt)"
    )


    Write-PkiVerbose (
        "Leaf certificate validity: " +
        "$script:LeafValidityDays days"
    )


    Write-PkiVerbose (
        "Leaf certificate chain: PASSED"
    )


    Write-PkiVerbose (
        "Leaf certificate profile: EV-style/private PKI"
    )
}


# ============================================================
# Generate All Configured Leaf Certificates
# ============================================================

function New-AllLeafCertificates {

    [CmdletBinding()]
    param()


    # --------------------------------------------------------
    # Validate Leaf Sizes
    # --------------------------------------------------------

    if ($null -eq $script:Pki.LeafSizes) {

        throw (
            'PKI LeafSizes configuration is missing.'
        )
    }


    if ($script:Pki.LeafSizes.Count -eq 0) {

        throw (
            'PKI LeafSizes is empty. ' +
            'At least one leaf RSA key size is required.'
        )
    }


    # --------------------------------------------------------
    # Validate Leaf Sizes
    # --------------------------------------------------------

    foreach ($bits in $script:Pki.LeafSizes) {

        if (
            [int]$bits -notin @(
                2048,
                3072,
                4096,
                8192
            )
        ) {

            throw (
                "Unsupported leaf RSA key size: $bits"
            )
        }
    }


    # --------------------------------------------------------
    # Generate Leaves
    # --------------------------------------------------------

    foreach ($bits in $script:Pki.LeafSizes) {

        Write-PkiVerbose (
            "Generating leaf certificate with RSA " +
            "key size: $bits"
        )


        New-LeafCertificate `
            -Bits ([int]$bits)
    }
}


# ============================================================
# END OF 05_LeafCertificates.ps1
# ============================================================