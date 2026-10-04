# ============================================================
# 04_CertificateAuthority.ps1
#
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
#
# Purpose:
#   - Generate Root CA
#   - Generate Intermediate CA
#   - Generate public keys
#   - Generate PFX files
#
# Certificate Identity (defaults; ev_pki.cnf [ dn_root_ev ] and
# [ dn_intermediate_ev ] override every value):
#
# Root CA
#   jurisdictionC   = EE
#   serialNumber    = EEARIREG.17344131
#   C               = EE
#   L               = Tallinn
#   O               = Agantra Inovatif OU
#   OU              = Root-Certs
#   CN              = Agantra Inovatif Global Root G1
#   name            = Nicko Satria Utama      (contact name)
#   emailAddress    = nicko@nextmantra.com    (contact e-mail)
#   telephoneNumber = (+372)53194019          (contact phone)
#
# Intermediate CA
#   same, with OU = Intermediate-CA and
#   CN = Agantra Inovatif EV RSA CA G1
#
# The subject is written to pki\root-ca.req.cnf and
# pki\intermediate-ca.req.cnf by 03_RuntimeConfig.ps1, so every
# attribute keeps its proper ASN.1 string type.
#
# Certificate Validity:
#
#   Root CA          = 500 years
#   Intermediate CA  = 250 years
#
# Leaf certificate validity is handled by the leaf-generation
# script: 397 days by default, 398 days at most (EV limit).
#
# IMPORTANT:
#   OpenSSL-facing subject values are converted to ASCII-safe
#   values before being written to the CA request configuration.
#
#   Example:
#
#       Agantra Inovatif OÜ
#                |
#                v
#       Agantra Inovatif OU
#
#   The original PKI configuration value remains unchanged.
#
# ============================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


# ============================================================
# Certificate Validity Configuration
# ============================================================

$script:RootValidityYears =
    500

$script:IntermediateValidityYears =
    250


# ============================================================
# Calculate Certificate Validity Days
#
# OpenSSL -days accepts a number of days, not a calendar-year
# value.
#
# This function calculates the number of days between:
#
#   UTC now
#       and
#   UTC now + specified calendar years
#
# This handles leap years automatically when calculating the
# target date.
# ============================================================
function Get-CertificateValidityDays {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, 1000)]
        [int]$Years
    )

    $notBefore =
        [DateTime]::UtcNow

    $notAfter =
        $notBefore.AddYears($Years)

    $totalDays =
        ($notAfter - $notBefore).TotalDays

    $days =
        [int][Math]::Floor($totalDays)

    if ($days -lt 1) {

        throw (
            "Calculated certificate validity is invalid. " +
            "Years=$Years Days=$days"
        )
    }

    return $days
}


# ============================================================
# Generate RSA Private Key
# ============================================================
function New-RsaPrivateKey {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(2048, 3072, 4096, 8192)]
        [int]$Bits,

        [Parameter(Mandatory)]
        [string]$Path
    )

    Invoke-OpenSSL `
        -Arguments @(
            'genpkey',
            '-algorithm',
            'RSA',
            '-pkeyopt',
            "rsa_keygen_bits:$Bits",
            '-out',
            $Path
        ) |
        Out-Null
}


# ============================================================
# Export Public Key
# ============================================================
function Export-PublicKey {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Key,

        [Parameter(Mandatory)]
        [string]$Path
    )

    Invoke-OpenSSL `
        -Arguments @(
            'pkey',
            '-in',
            $Key,
            '-pubout',
            '-out',
            $Path
        ) |
        Out-Null
}


# ============================================================
# Create PFX File
# ============================================================
function New-PfxFile {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Certificate,

        [Parameter(Mandatory)]
        [string]$Key,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $args = @(
        'pkcs12',
        '-export',
        '-out',
        $Path,
        '-inkey',
        $Key,
        '-in',
        $Certificate,
        '-passout',
        'env:PKI_PFX_PASSWORD',
        '-name',
        (
            [IO.Path]::GetFileNameWithoutExtension(
                $Certificate
            )
        )
    )

    if ($script:Pki.LegacyPfx) {

        $args += '-legacy'
    }

    Invoke-OpenSSL `
        -Arguments $args |
        Out-Null
}


# ============================================================
# Get OpenSSL-Safe PKI Organization
# ============================================================
function Get-OpenSslOrganization {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Organization
    )

    # --------------------------------------------------------
    # Convert Unicode organization name to ASCII.
    #
    # Example:
    #
    #   Agantra Inovatif OÜ
    #
    # becomes:
    #
    #   Agantra Inovatif OU
    # --------------------------------------------------------
    $asciiOrganization =
        ConvertTo-Ascii `
            -Text $Organization

    return $asciiOrganization
}


# ============================================================
# Human-readable CA subject (verbose logging only)
# ============================================================
function Get-CaSubjectText {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Fields
    )

    $parts = foreach ($field in $Fields) {

        '{0}={1}' -f `
            $field.Key,
            (ConvertFrom-OpenSslConfValue -Raw $field.Raw)
    }

    return ($parts -join ', ')
}


# ============================================================
# Generate Root CA
# ============================================================
function New-RootCA {

    [CmdletBinding()]
    param()

    $p = $script:Pki


    # --------------------------------------------------------
    # Root CA validity
    #
    #   500 calendar years
    # --------------------------------------------------------
    $rootDays =
        Get-CertificateValidityDays `
            -Years $script:RootValidityYears


    Write-PkiVerbose (
        "Root CA validity: " +
        "$script:RootValidityYears years " +
        "($rootDays days)"
    )


    # --------------------------------------------------------
    # Root CA private key
    #
    # RSA 4096
    # --------------------------------------------------------
    New-RsaPrivateKey `
        -Bits 8192 `
        -Path $p.RootKey


    # --------------------------------------------------------
    # Root CA public key
    # --------------------------------------------------------
    Export-PublicKey `
        -Key $p.RootKey `
        -Path $p.RootPub


    # --------------------------------------------------------
    # Root CA certificate identity
    #
    # Complete EV-style subject from pki\root-ca.req.cnf
    # (generated from ev_pki.cnf [ dn_root_ev ] + defaults).
    # --------------------------------------------------------
    Assert-PkiFile -Path $p.RootReqConfig

    Write-PkiVerbose (
        "Root CA subject: " +
        (Get-CaSubjectText -Fields $p.Ev.RootDnFields)
    )


    # --------------------------------------------------------
    # Generate Root CA certificate
    # --------------------------------------------------------
    Invoke-OpenSSL `
        -Arguments @(
            'req',
            '-x509',
            '-new',
            '-sha256',
            '-days',
            $rootDays,
            '-key',
            $p.RootKey,
            '-out',
            $p.RootCrt,
            '-config',
            $p.RootReqConfig,
            '-extensions',
            'v3_root'
        ) |
        Out-Null


    # --------------------------------------------------------
    # Generate Root CA PFX
    # --------------------------------------------------------
    New-PfxFile `
        -Certificate $p.RootCrt `
        -Key $p.RootKey `
        -Path $p.RootPfx
}


# ============================================================
# Generate Intermediate CA
# ============================================================
function New-IntermediateCA {

    [CmdletBinding()]
    param()

    $p = $script:Pki


    # --------------------------------------------------------
    # Intermediate CA validity
    #
    #   250 calendar years
    # --------------------------------------------------------
    $intermediateDays =
        Get-CertificateValidityDays `
            -Years $script:IntermediateValidityYears


    Write-PkiVerbose (
        "Intermediate CA validity: " +
        "$script:IntermediateValidityYears years " +
        "($intermediateDays days)"
    )


    # --------------------------------------------------------
    # Intermediate CA private key
    #
    # RSA 4096
    # --------------------------------------------------------
    New-RsaPrivateKey `
        -Bits 8192 `
        -Path $p.IntermediateKey


    # --------------------------------------------------------
    # Intermediate CA public key
    # --------------------------------------------------------
    Export-PublicKey `
        -Key $p.IntermediateKey `
        -Path $p.IntermediatePub


    # --------------------------------------------------------
    # Intermediate CA certificate identity
    #
    # Complete EV-style subject from pki\intermediate-ca.req.cnf
    # (generated from ev_pki.cnf [ dn_intermediate_ev ] + defaults).
    # --------------------------------------------------------
    Assert-PkiFile -Path $p.IntermediateReqConfig

    Write-PkiVerbose (
        "Intermediate CA subject: " +
        (Get-CaSubjectText -Fields $p.Ev.IntermediateDnFields)
    )


    # --------------------------------------------------------
    # Generate Intermediate CA CSR
    # --------------------------------------------------------
    Invoke-OpenSSL `
        -Arguments @(
            'req',
            '-new',
            '-sha256',
            '-key',
            $p.IntermediateKey,
            '-out',
            $p.IntermediateCsr,
            '-config',
            $p.IntermediateReqConfig
        ) |
        Out-Null


    # --------------------------------------------------------
    # Sign Intermediate CA with Root CA
    #
    # Root:
    #   CA:TRUE
    #   pathLenConstraint:1
    #
    # Intermediate:
    #   CA:TRUE
    #   pathLenConstraint:0
    #
    # Therefore the Intermediate can sign leaf certificates
    # but cannot create another subordinate CA.
    # --------------------------------------------------------
    Invoke-OpenSSL `
        -Arguments @(
            'x509',
            '-req',
            '-sha256',
            '-days',
            $intermediateDays,
            '-in',
            $p.IntermediateCsr,
            '-CA',
            $p.RootCrt,
            '-CAkey',
            $p.RootKey,
            '-CAserial',
            $p.RootSerialFile,
            '-out',
            $p.IntermediateCrt,
            '-extfile',
            $p.RuntimeConfig,
            '-extensions',
            'v3_intermediate'
        ) |
        Out-Null


    # --------------------------------------------------------
    # Generate Intermediate CA PFX
    # --------------------------------------------------------
    New-PfxFile `
        -Certificate $p.IntermediateCrt `
        -Key $p.IntermediateKey `
        -Path $p.IntermediatePfx
}


# ============================================================
# END OF 04_CertificateAuthority.ps1
# ============================================================