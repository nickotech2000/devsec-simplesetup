# ============================================================
# 07_TrustStore.ps1
#
# Windows Local PKI Trust Store Management
#
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
#
# Purpose:
#   - Install Root CA
#   - Install Intermediate CA
#   - Install leaf certificates with private keys
#   - Import leaf PFX certificates
#   - Remove current PKI trust
#   - Remove all Agantra/NextMantra certificates
#   - Remove generated PKI folders after successful cleanup
#
# Windows Certificate Stores:
#   LocalMachine\Root
#   LocalMachine\CA
#   LocalMachine\My
#
# PKI identity:
#   - Agantra Inovatif
#   - NextMantra
#
# PFX password:
#   - Uses configured Password
#   - Uses configured PfxPassword
#   - Falls back to Abc12345!
#
# IMPORTANT:
#   PKI modules are dot-sourced from pki_setup.ps1.
#   Shared configuration is therefore read from $global:Pki.
#
# Certificate placement:
#
#   Root CA
#       -> LocalMachine\Root
#
#   Intermediate CA
#       -> LocalMachine\CA
#
#   Leaf certificate + private key
#       -> LocalMachine\My
#
# Root/Intermediate PFX files are NOT imported into
# LocalMachine\My. Their CRT files are used for trust.
#
# ============================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# Constants
# ============================================================

$script:PkiTrustOrganization = 'Agantra Inovatif OÜ (NextMantra)'

$script:PkiIdentityMarkers = @(
    'Agantra Inovatif'
    'NextMantra'
)

$script:DefaultPfxPassword = 'Abc12345!'

# ============================================================
# Logging
# ============================================================

function Write-TrustStoreLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO','OK','WARN','ERROR')]
        [string]$Level = 'INFO'
    )

    Write-Host ("[{0}] {1}" -f $Level, $Message)
}

# ============================================================
# Administrator check
# ============================================================

function Test-IsAdministrator {
    [CmdletBinding()]
    param()

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()

        if ($null -eq $identity) {
            return $false
        }

        $principal = New-Object Security.Principal.WindowsPrincipal($identity)

        return $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    }
    catch {
        return $false
    }
}

# ============================================================
# LocalMachine certificate store
# ============================================================

function Get-LocalMachineCertificateStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Root','CA','My')]
        [string]$Store
    )

    $path = "Cert:\LocalMachine\$Store"

    if (-not (Test-Path -LiteralPath $path)) {
        throw "Certificate store does not exist: $path"
    }

    return @(
        Get-ChildItem -LiteralPath $path -ErrorAction Stop
    )
}

# ============================================================
# Normalize thumbprint
# ============================================================

function ConvertTo-NormalizedThumbprint {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Thumbprint
    )

    if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
        return $null
    }

    $normalized = $Thumbprint -replace '[^0-9A-Fa-f]', ''
    $normalized = $normalized.ToUpperInvariant()

    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $null
    }

    return $normalized
}

# ============================================================
# Normalize certificate text
# ============================================================

function ConvertTo-NormalizedCertificateText {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $value = $Text

    try {
        $value = $value.Normalize(
            [System.Text.NormalizationForm]::FormKC
        )
    }
    catch {
    }

    $value = $value.Replace([char]0x00A0, ' ')
    $value = $value -replace '\s+', ' '

    return $value.Trim().ToLowerInvariant()
}

# ============================================================
# PKI certificate identity
# ============================================================

function Test-PkiCertificateIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $subject = ConvertTo-NormalizedCertificateText `
        -Text $Certificate.Subject

    $issuer = ConvertTo-NormalizedCertificateText `
        -Text $Certificate.Issuer

    if (
        [string]::IsNullOrWhiteSpace($subject) -and
        [string]::IsNullOrWhiteSpace($issuer)
    ) {
        return $false
    }

    foreach ($marker in $script:PkiIdentityMarkers) {

        $normalizedMarker = ConvertTo-NormalizedCertificateText `
            -Text $marker

        if ([string]::IsNullOrWhiteSpace($normalizedMarker)) {
            continue
        }

        if ($subject.Contains($normalizedMarker)) {
            return $true
        }

        if ($issuer.Contains($normalizedMarker)) {
            return $true
        }
    }

    return $false
}

# ============================================================
# CA certificate test
# ============================================================

function Test-CaCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    try {
        $extension = $Certificate.Extensions |
            Where-Object {
                $_.Oid.Value -eq '2.5.29.19'
            } |
            Select-Object -First 1

        if ($null -eq $extension) {
            return $false
        }

        $basicConstraints =
            [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$extension

        return [bool]$basicConstraints.CertificateAuthority
    }
    catch {
        return $false
    }
}

# ============================================================
# Self-signed certificate test
# ============================================================

function Test-SelfSignedCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $subject = ConvertTo-NormalizedCertificateText `
        -Text $Certificate.Subject

    $issuer = ConvertTo-NormalizedCertificateText `
        -Text $Certificate.Issuer

    if ([string]::IsNullOrWhiteSpace($subject)) {
        return $false
    }

    if ([string]::IsNullOrWhiteSpace($issuer)) {
        return $false
    }

    return ($subject -eq $issuer)
}

# ============================================================
# Load certificate from file
# ============================================================

function Get-CertificateFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CertificatePath
    )

    if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
        throw "Certificate file does not exist: $CertificatePath"
    }

    return New-Object `
        System.Security.Cryptography.X509Certificates.X509Certificate2(
            $CertificatePath
        )
}

# ============================================================
# Get shared PKI configuration
# ============================================================

function Get-TrustStorePkiConfiguration {
    [CmdletBinding()]
    param()

    # --------------------------------------------------------
    # Preferred configuration scope.
    # --------------------------------------------------------

    if ($null -ne $global:Pki) {
        return $global:Pki
    }

    # --------------------------------------------------------
    # Compatibility fallback.
    # --------------------------------------------------------

    if ($null -ne $script:Pki) {
        return $script:Pki
    }

    throw 'PKI configuration is not available.'
}

# ============================================================
# Get PFX password
# ============================================================

function Get-PkiPfxPassword {
    [CmdletBinding()]
    param()

    # --------------------------------------------------------
    # Always have a safe default.
    # --------------------------------------------------------

    $password = $script:DefaultPfxPassword

    # --------------------------------------------------------
    # Try shared global configuration.
    # --------------------------------------------------------

    try {
        if ($null -ne $global:Pki) {

            if ($global:Pki -is [System.Collections.IDictionary]) {

                if ($global:Pki.Contains('Password')) {

                    $configuredPassword =
                        [string]$global:Pki['Password']

                    if (
                        -not [string]::IsNullOrWhiteSpace(
                            $configuredPassword
                        )
                    ) {
                        return $configuredPassword
                    }
                }

                if ($global:Pki.Contains('PfxPassword')) {

                    $configuredPfxPassword =
                        [string]$global:Pki['PfxPassword']

                    if (
                        -not [string]::IsNullOrWhiteSpace(
                            $configuredPfxPassword
                        )
                    ) {
                        return $configuredPfxPassword
                    }
                }
            }
            else {

                $properties =
                    @($global:Pki.PSObject.Properties.Name)

                if ($properties -contains 'Password') {

                    $configuredPassword =
                        [string]$global:Pki.Password

                    if (
                        -not [string]::IsNullOrWhiteSpace(
                            $configuredPassword
                        )
                    ) {
                        return $configuredPassword
                    }
                }

                if ($properties -contains 'PfxPassword') {

                    $configuredPfxPassword =
                        [string]$global:Pki.PfxPassword

                    if (
                        -not [string]::IsNullOrWhiteSpace(
                            $configuredPfxPassword
                        )
                    ) {
                        return $configuredPfxPassword
                    }
                }
            }
        }
    }
    catch {
        # Continue to compatibility/fallback handling.
    }

    # --------------------------------------------------------
    # Compatibility fallback to local script configuration.
    # --------------------------------------------------------

    try {
        if ($null -ne $script:Pki) {

            if ($script:Pki -is [System.Collections.IDictionary]) {

                if ($script:Pki.Contains('Password')) {

                    $configuredPassword =
                        [string]$script:Pki['Password']

                    if (
                        -not [string]::IsNullOrWhiteSpace(
                            $configuredPassword
                        )
                    ) {
                        return $configuredPassword
                    }
                }

                if ($script:Pki.Contains('PfxPassword')) {

                    $configuredPfxPassword =
                        [string]$script:Pki['PfxPassword']

                    if (
                        -not [string]::IsNullOrWhiteSpace(
                            $configuredPfxPassword
                        )
                    ) {
                        return $configuredPfxPassword
                    }
                }
            }
        }
    }
    catch {
        # Use default.
    }

    return $password
}

# ============================================================
# Install certificate into LocalMachine store
# ============================================================

function Install-CertificateToStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CertificatePath,

        [Parameter(Mandatory)]
        [ValidateSet('Root','CA','My')]
        [string]$Store
    )

    if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
        throw "Certificate file not found: $CertificatePath"
    }

    $resolvedPath =
        (Resolve-Path -LiteralPath $CertificatePath).Path

    $certificate =
        Get-CertificateFromFile -CertificatePath $resolvedPath

    $thumbprint =
        ConvertTo-NormalizedThumbprint `
            -Thumbprint $certificate.Thumbprint

    if ([string]::IsNullOrWhiteSpace($thumbprint)) {
        throw "Unable to determine certificate thumbprint: $resolvedPath"
    }

    $storePath = "Cert:\LocalMachine\$Store"

    $certificatePathInStore =
        Join-Path $storePath $thumbprint

    Write-TrustStoreLog `
        "Installing certificate into LocalMachine\$Store" `
        'INFO'

    Write-TrustStoreLog `
        "  File       : $resolvedPath" `
        'INFO'

    Write-TrustStoreLog `
        "  Thumbprint : $thumbprint" `
        'INFO'

    Write-TrustStoreLog `
        "  Subject    : $($certificate.Subject)" `
        'INFO'

    Write-TrustStoreLog `
        "  Issuer     : $($certificate.Issuer)" `
        'INFO'

    if (Test-Path -LiteralPath $certificatePathInStore) {

        Write-TrustStoreLog `
            "Certificate already exists in LocalMachine\$Store." `
            'INFO'

        return $thumbprint
    }

    Import-Certificate `
        -FilePath $resolvedPath `
        -CertStoreLocation $storePath `
        -ErrorAction Stop |
        Out-Null

    if (-not (Test-Path -LiteralPath $certificatePathInStore)) {
        throw "Certificate installation could not be verified: $resolvedPath"
    }

    Write-TrustStoreLog `
        'Certificate installed successfully.' `
        'OK'

    return $thumbprint
}

# ============================================================
# Read PFX metadata
# ============================================================

function Get-PfxMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PfxPath,

        [Parameter(Mandatory)]
        [string]$Password
    )

    if (-not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) {
        throw "PFX file not found: $PfxPath"
    }

    $securePassword =
        ConvertTo-SecureString `
            -String $Password `
            -AsPlainText `
            -Force

    $pfxData =
        Get-PfxData `
            -FilePath $PfxPath `
            -Password $securePassword `
            -ErrorAction Stop

    $endEntityCertificates = @(
        $pfxData.EndEntityCertificates
    )

    $otherCertificates = @(
        $pfxData.OtherCertificates
    )

    $allCertificates = @(
        $endEntityCertificates
        $otherCertificates
    )

    return [PSCustomObject]@{
        Path                  = $PfxPath
        EndEntityCertificates = $endEntityCertificates
        OtherCertificates     = $otherCertificates
        Certificates          = $allCertificates
    }
}

# ============================================================
# Install leaf PFX into LocalMachine\My
# ============================================================

function Install-LeafPfxToMyStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PfxPath,

        [Parameter(Mandatory)]
        [string]$Password
    )

    if (-not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) {
        throw "PFX file not found: $PfxPath"
    }

    $resolvedPath =
        (Resolve-Path -LiteralPath $PfxPath).Path

    Write-TrustStoreLog `
        'Inspecting PFX file.' `
        'INFO'

    Write-TrustStoreLog `
        "  File: $resolvedPath" `
        'INFO'

    $metadata =
        Get-PfxMetadata `
            -PfxPath $resolvedPath `
            -Password $Password

    $endEntities =
        @($metadata.EndEntityCertificates)

    if ($endEntities.Count -eq 0) {

        Write-TrustStoreLog `
            'PFX contains no end-entity certificate. Skipping.' `
            'WARN'

        return @()
    }

    $leafCertificates = @()

    foreach ($certificate in $endEntities) {

        if (-not (Test-PkiCertificateIdentity -Certificate $certificate)) {

            Write-TrustStoreLog `
                'PFX certificate does not match PKI identity. Skipping.' `
                'WARN'

            Write-TrustStoreLog `
                "  Subject: $($certificate.Subject)" `
                'WARN'

            continue
        }

        $isCa =
            Test-CaCertificate `
                -Certificate $certificate

        if ($isCa) {

            Write-TrustStoreLog `
                'PFX contains a CA certificate. It will not be imported into LocalMachine\My.' `
                'INFO'

            Write-TrustStoreLog `
                "  Subject: $($certificate.Subject)" `
                'INFO'

            continue
        }

        $leafCertificates += $certificate
    }

    if ($leafCertificates.Count -eq 0) {
        return @()
    }

    Write-TrustStoreLog `
        'Importing leaf PFX into LocalMachine\My.' `
        'INFO'

    $securePassword =
        ConvertTo-SecureString `
            -String $Password `
            -AsPlainText `
            -Force

    $imported =
        Import-PfxCertificate `
            -FilePath $resolvedPath `
            -CertStoreLocation 'Cert:\LocalMachine\My' `
            -Password $securePassword `
            -Exportable `
            -ErrorAction Stop

    $importedCertificates = @($imported)

    if ($importedCertificates.Count -eq 0) {
        throw "PFX import returned no certificates: $resolvedPath"
    }

    $verified = @()

    foreach ($certificate in $importedCertificates) {

        if (-not (Test-PkiCertificateIdentity -Certificate $certificate)) {
            continue
        }

        if (Test-CaCertificate -Certificate $certificate) {
            continue
        }

        $thumbprint =
            ConvertTo-NormalizedThumbprint `
                -Thumbprint $certificate.Thumbprint

        Write-TrustStoreLog `
            'Leaf PFX certificate installed successfully.' `
            'OK'

        Write-TrustStoreLog `
            "  Thumbprint : $thumbprint" `
            'INFO'

        Write-TrustStoreLog `
            "  Subject    : $($certificate.Subject)" `
            'INFO'

        Write-TrustStoreLog `
            "  Issuer     : $($certificate.Issuer)" `
            'INFO'

        $verified += $certificate
    }

    return @($verified)
}

# ============================================================
# Locate PKI directory
# ============================================================

function Get-PkiDirectory {
    [CmdletBinding()]
    param()

    # --------------------------------------------------------
    # Preferred: shared configuration.
    # --------------------------------------------------------

    try {
        if ($null -ne $global:Pki) {

            if ($global:Pki -is [System.Collections.IDictionary]) {

                if ($global:Pki.Contains('PkiRoot')) {

                    $configuredPath =
                        [string]$global:Pki['PkiRoot']

                    if (
                        -not [string]::IsNullOrWhiteSpace(
                            $configuredPath
                        ) -and
                        (Test-Path -LiteralPath $configuredPath -PathType Container)
                    ) {
                        return (
                            Resolve-Path `
                                -LiteralPath $configuredPath
                        ).Path
                    }
                }
            }
            else {

                $properties =
                    @($global:Pki.PSObject.Properties.Name)

                if ($properties -contains 'PkiRoot') {

                    $configuredPath =
                        [string]$global:Pki.PkiRoot

                    if (
                        -not [string]::IsNullOrWhiteSpace(
                            $configuredPath
                        ) -and
                        (Test-Path -LiteralPath $configuredPath -PathType Container)
                    ) {
                        return (
                            Resolve-Path `
                                -LiteralPath $configuredPath
                        ).Path
                    }
                }
            }
        }
    }
    catch {
    }

    # --------------------------------------------------------
    # Compatibility fallback.
    # --------------------------------------------------------

    try {
        if ($null -ne $script:Pki) {

            if ($script:Pki -is [System.Collections.IDictionary]) {

                if ($script:Pki.Contains('PkiRoot')) {

                    $configuredPath =
                        [string]$script:Pki['PkiRoot']

                    if (
                        -not [string]::IsNullOrWhiteSpace(
                            $configuredPath
                        ) -and
                        (Test-Path -LiteralPath $configuredPath -PathType Container)
                    ) {
                        return (
                            Resolve-Path `
                                -LiteralPath $configuredPath
                        ).Path
                    }
                }
            }
        }
    }
    catch {
    }

    # --------------------------------------------------------
    # Default project location.
    # --------------------------------------------------------

    $projectRoot =
        Split-Path `
            -Path $PSScriptRoot `
            -Parent

    $defaultPkiDirectory =
        Join-Path $projectRoot 'pki'

    if (
        Test-Path `
            -LiteralPath $defaultPkiDirectory `
            -PathType Container
    ) {
        return (
            Resolve-Path `
                -LiteralPath $defaultPkiDirectory
        ).Path
    }

    throw "Unable to locate the generated PKI directory."
}

# ============================================================
# Find certificate files
# ============================================================

function Get-PkiCertificateFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PkiDirectory
    )

    if (
        -not (
            Test-Path `
                -LiteralPath $PkiDirectory `
                -PathType Container
        )
    ) {
        throw "PKI directory does not exist: $PkiDirectory"
    }

    return @(
        Get-ChildItem `
            -LiteralPath $PkiDirectory `
            -Recurse `
            -File `
            -ErrorAction Stop |
        Where-Object {
            $_.Extension -in @(
                '.crt'
                '.cer'
                '.pem'
            )
        }
    )
}

# ============================================================
# Find PFX files
# ============================================================

function Get-PkiPfxFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PkiDirectory
    )

    if (
        -not (
            Test-Path `
                -LiteralPath $PkiDirectory `
                -PathType Container
        )
    ) {
        throw "PKI directory does not exist: $PkiDirectory"
    }

    return @(
        Get-ChildItem `
            -LiteralPath $PkiDirectory `
            -Recurse `
            -File `
            -ErrorAction Stop |
        Where-Object {
            $_.Extension -in @(
                '.pfx'
                '.p12'
            )
        }
    )
}

# ============================================================
# Classify generated certificate files
# ============================================================

function Get-PkiGeneratedCertificateClassification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PkiDirectory
    )

    $certFiles =
        @(Get-PkiCertificateFiles -PkiDirectory $PkiDirectory)

    $rootCertificates = @()
    $intermediateCertificates = @()
    $leafCertificates = @()

    Write-TrustStoreLog `
        'Scanning generated certificate files...' `
        'INFO'

    Write-TrustStoreLog `
        "Certificate files found: $($certFiles.Count)" `
        'INFO'

    foreach ($file in $certFiles) {

        try {

            $certificate =
                Get-CertificateFromFile `
                    -CertificatePath $file.FullName

            if (
                -not (
                    Test-PkiCertificateIdentity `
                        -Certificate $certificate
                )
            ) {
                continue
            }

            $isCa =
                Test-CaCertificate `
                    -Certificate $certificate

            if ($isCa) {

                $selfSigned =
                    Test-SelfSignedCertificate `
                        -Certificate $certificate

                if ($selfSigned) {

                    $rootCertificates += [PSCustomObject]@{
                        File        = $file
                        Certificate = $certificate
                    }

                    continue
                }

                $intermediateCertificates += [PSCustomObject]@{
                    File        = $file
                    Certificate = $certificate
                }

                continue
            }

            $leafCertificates += [PSCustomObject]@{
                File        = $file
                Certificate = $certificate
            }
        }
        catch {

            Write-TrustStoreLog `
                "Skipping unreadable certificate file: $($file.FullName)" `
                'WARN'

            Write-TrustStoreLog `
                $_.Exception.Message `
                'WARN'
        }
    }

    Write-TrustStoreLog `
        "Generated Root CA certificates      : $($rootCertificates.Count)" `
        'INFO'

    Write-TrustStoreLog `
        "Generated Intermediate CA certificates: $($intermediateCertificates.Count)" `
        'INFO'

    Write-TrustStoreLog `
        "Generated Leaf certificates         : $($leafCertificates.Count)" `
        'INFO'

    return [PSCustomObject]@{
        Root         = @($rootCertificates)
        Intermediate = @($intermediateCertificates)
        Leaf         = @($leafCertificates)
    }
}

# ============================================================
# Install PKI trust
# ============================================================

function Install-PkiTrust {
    [CmdletBinding()]
    param()

    if (-not (Test-IsAdministrator)) {
        throw 'Install-PkiTrust requires an elevated Administrator PowerShell session.'
    }

    Write-TrustStoreLog `
        'START: Install PKI trust' `
        'INFO'

    $pkiDirectory =
        Get-PkiDirectory

    Write-TrustStoreLog `
        "PKI directory: $pkiDirectory" `
        'INFO'

    $classification =
        Get-PkiGeneratedCertificateClassification `
            -PkiDirectory $pkiDirectory

    $rootCertificates =
        @($classification.Root)

    $intermediateCertificates =
        @($classification.Intermediate)

    $leafCertificates =
        @($classification.Leaf)

    $pfxFiles =
        @(Get-PkiPfxFiles -PkiDirectory $pkiDirectory)

    Write-TrustStoreLog `
        "Generated PFX files: $($pfxFiles.Count)" `
        'INFO'

    # --------------------------------------------------------
    # Root CA
    # --------------------------------------------------------

    $rootInstalled = 0

    foreach ($item in $rootCertificates) {

        Install-CertificateToStore `
            -CertificatePath $item.File.FullName `
            -Store Root |
            Out-Null

        $rootInstalled++
    }

    # --------------------------------------------------------
    # Intermediate CA
    # --------------------------------------------------------

    $intermediateInstalled = 0

    foreach ($item in $intermediateCertificates) {

        Install-CertificateToStore `
            -CertificatePath $item.File.FullName `
            -Store CA |
            Out-Null

        $intermediateInstalled++
    }

    # --------------------------------------------------------
    # Leaf PFX
    # --------------------------------------------------------

    $pfxPassword =
        Get-PkiPfxPassword

    Write-TrustStoreLog `
        'PFX password configured successfully.' `
        'OK'

    $leafPfxInstalled = 0

    foreach ($pfxFile in $pfxFiles) {

        $installed =
            @(Install-LeafPfxToMyStore `
                -PfxPath $pfxFile.FullName `
                -Password $pfxPassword)

        foreach ($certificate in $installed) {
            if ($null -ne $certificate) {
                $leafPfxInstalled++
            }
        }
    }

    # --------------------------------------------------------
    # If no leaf PFX was available, install leaf CRT files.
    #
    # This is a fallback only. Normally the generated PFX files
    # should provide the private keys.
    # --------------------------------------------------------

    if ($leafPfxInstalled -eq 0) {

        if ($leafCertificates.Count -gt 0) {

            Write-TrustStoreLog `
                'No leaf PFX certificates were imported.' `
                'WARN'

            Write-TrustStoreLog `
                'Installing leaf certificate files into LocalMachine\My as fallback.' `
                'WARN'

            foreach ($item in $leafCertificates) {

                Install-CertificateToStore `
                    -CertificatePath $item.File.FullName `
                    -Store My |
                    Out-Null

                $leafPfxInstalled++
            }
        }
    }

    # --------------------------------------------------------
    # Verify LocalMachine stores.
    # --------------------------------------------------------

    Write-TrustStoreLog `
        'Verifying installed PKI certificates...' `
        'INFO'

    $installedCandidates =
        @(Get-PkiTrustStoreCandidates)

    $installedRoots =
        @(
            $installedCandidates |
            Where-Object {
                $_.Store -eq 'Root' -and
                $_.IsCA -eq $true -and
                $_.IsSelfSigned -eq $true
            }
        )

    $installedIntermediates =
        @(
            $installedCandidates |
            Where-Object {
                $_.Store -eq 'CA' -and
                $_.IsCA -eq $true -and
                $_.IsSelfSigned -eq $false
            }
        )

    $installedLeaves =
        @(
            $installedCandidates |
            Where-Object {
                $_.Store -eq 'My' -and
                $_.IsCA -eq $false
            }
        )

    Write-TrustStoreLog `
        "Verified Root CA certificates        : $($installedRoots.Count)" `
        'INFO'

    Write-TrustStoreLog `
        "Verified Intermediate CA certificates : $($installedIntermediates.Count)" `
        'INFO'

    Write-TrustStoreLog `
        "Verified Leaf certificates            : $($installedLeaves.Count)" `
        'INFO'

    # --------------------------------------------------------
    # Required verification
    # --------------------------------------------------------

    if ($rootInstalled -eq 0) {
        throw 'PKI installation failed: no Root CA certificate was installed.'
    }

    if ($intermediateInstalled -eq 0) {
        throw 'PKI installation failed: no Intermediate CA certificate was installed.'
    }

    if ($leafPfxInstalled -eq 0) {
        throw 'PKI installation failed: no Leaf certificate was installed.'
    }

    if ($installedRoots.Count -eq 0) {
        throw 'PKI installation verification failed: Root CA is not present in LocalMachine\Root.'
    }

    if ($installedIntermediates.Count -eq 0) {
        throw 'PKI installation verification failed: Intermediate CA is not present in LocalMachine\CA.'
    }

    if ($installedLeaves.Count -eq 0) {
        throw 'PKI installation verification failed: Leaf certificate is not present in LocalMachine\My.'
    }

    Write-TrustStoreLog `
        'Root CA installed successfully.' `
        'OK'

    Write-TrustStoreLog `
        'Intermediate CA installed successfully.' `
        'OK'

    Write-TrustStoreLog `
        "Leaf certificate(s) installed successfully: $leafPfxInstalled" `
        'OK'

    Write-TrustStoreLog `
        'DONE: Install PKI trust' `
        'OK'
}

# ============================================================
# Remove certificate by thumbprint
# ============================================================

function Remove-CertificateThumbprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Root','CA','My')]
        [string]$Store,

        [Parameter(Mandatory)]
        [string]$Thumbprint
    )

    $normalized =
        ConvertTo-NormalizedThumbprint `
            -Thumbprint $Thumbprint

    if ([string]::IsNullOrWhiteSpace($normalized)) {

        Write-TrustStoreLog `
            "Invalid thumbprint for LocalMachine\$Store." `
            'WARN'

        return $false
    }

    $path =
        "Cert:\LocalMachine\$Store\$normalized"

    try {

        if (-not (Test-Path -LiteralPath $path)) {

            Write-TrustStoreLog `
                "Certificate not found: LocalMachine\$Store\$normalized" `
                'INFO'

            return $false
        }

        $certificate =
            Get-Item `
                -LiteralPath $path `
                -ErrorAction Stop

        Write-TrustStoreLog `
            "Removing certificate from LocalMachine\$Store" `
            'INFO'

        Write-TrustStoreLog `
            "  Thumbprint : $normalized" `
            'INFO'

        Write-TrustStoreLog `
            "  Subject    : $($certificate.Subject)" `
            'INFO'

        Write-TrustStoreLog `
            "  Issuer     : $($certificate.Issuer)" `
            'INFO'

        Remove-Item `
            -LiteralPath $path `
            -Force `
            -ErrorAction Stop

        if (Test-Path -LiteralPath $path) {

            Write-TrustStoreLog `
                "Certificate still exists after removal: $path" `
                'ERROR'

            return $false
        }

        Write-TrustStoreLog `
            'Removed successfully.' `
            'OK'

        return $true
    }
    catch {

        Write-TrustStoreLog `
            "Failed to remove certificate $normalized from LocalMachine\$Store." `
            'ERROR'

        Write-TrustStoreLog `
            $_.Exception.Message `
            'ERROR'

        return $false
    }
}

# ============================================================
# Scan LocalMachine stores for matching PKI certificates
# ============================================================

function Get-PkiTrustStoreCandidates {
    [CmdletBinding()]
    param()

    $result = @()

    foreach ($storeName in @('My','CA','Root')) {

        $storePath =
            "Cert:\LocalMachine\$storeName"

        Write-TrustStoreLog `
            "Scanning LocalMachine\$storeName..." `
            'INFO'

        if (-not (Test-Path -LiteralPath $storePath)) {

            Write-TrustStoreLog `
                "Store does not exist: $storePath" `
                'WARN'

            continue
        }

        $certificates =
            @(
                Get-ChildItem `
                    -LiteralPath $storePath `
                    -ErrorAction Stop
            )

        Write-TrustStoreLog `
            "Certificates scanned in LocalMachine\$storeName : $($certificates.Count)" `
            'INFO'

        foreach ($certificate in $certificates) {

            if ($null -eq $certificate) {
                continue
            }

            if (
                -not (
                    Test-PkiCertificateIdentity `
                        -Certificate $certificate
                )
            ) {
                continue
            }

            $thumbprint =
                ConvertTo-NormalizedThumbprint `
                    -Thumbprint $certificate.Thumbprint

            if ([string]::IsNullOrWhiteSpace($thumbprint)) {
                continue
            }

            $isCa =
                Test-CaCertificate `
                    -Certificate $certificate

            $isSelfSigned =
                Test-SelfSignedCertificate `
                    -Certificate $certificate

            $result += [PSCustomObject]@{
                Store        = [string]$storeName
                Thumbprint   = [string]$thumbprint
                Subject      = [string]$certificate.Subject
                Issuer       = [string]$certificate.Issuer
                IsCA         = [bool]$isCa
                IsSelfSigned = [bool]$isSelfSigned
                HasPrivateKey = [bool]$certificate.HasPrivateKey
                NotBefore    = $certificate.NotBefore
                NotAfter     = $certificate.NotAfter
                Certificate  = $certificate
            }
        }
    }

    return @($result)
}

# ============================================================
# Remove current trust
# ============================================================

function Remove-CurrentTrust {
    [CmdletBinding()]
    param()

    return Remove-AllTrust
}

# ============================================================
# Get project root
# ============================================================

function Get-PkiProjectRoot {
    [CmdletBinding()]
    param()

    $scriptsDirectory =
        (Resolve-Path -LiteralPath $PSScriptRoot).Path

    return (
        Split-Path `
            -Path $scriptsDirectory `
            -Parent
    )
}

# ============================================================
# Safe cleanup directory validation
# ============================================================

function Test-SafePkiCleanupDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DirectoryPath,

        [Parameter(Mandatory)]
        [string]$ProjectRoot
    )

    try {

        $resolvedDirectory =
            [System.IO.Path]::GetFullPath(
                $DirectoryPath
            ).TrimEnd('\')

        $resolvedProjectRoot =
            [System.IO.Path]::GetFullPath(
                $ProjectRoot
            ).TrimEnd('\')

        if (
            $resolvedDirectory.Equals(
                $resolvedProjectRoot,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            return $false
        }

        $scriptsDirectory =
            Join-Path `
                $resolvedProjectRoot `
                'scripts'

        if (
            $resolvedDirectory.Equals(
                $scriptsDirectory,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            return $false
        }

        $prefix =
            $resolvedProjectRoot + '\'

        if (
            -not (
                $resolvedDirectory.StartsWith(
                    $prefix,
                    [System.StringComparison]::OrdinalIgnoreCase
                )
            )
        ) {
            return $false
        }

        return $true
    }
    catch {
        return $false
    }
}

# ============================================================
# Get generated PKI cleanup directories
# ============================================================

function Get-PkiCleanupDirectories {
    [CmdletBinding()]
    param()

    $projectRoot =
        Get-PkiProjectRoot

    $directories = @()

    # --------------------------------------------------------
    # Shared configuration.
    # --------------------------------------------------------

    try {

        if ($null -ne $global:Pki) {

            $propertyNames =
                @($global:Pki.PSObject.Properties.Name)

            foreach ($propertyName in $propertyNames) {

                if (
                    $propertyName -notmatch
                    '(?i)(Dir|Directory|Folder|Path|Root)$'
                ) {
                    continue
                }

                try {

                    $value =
                        [string]$global:Pki.$propertyName

                    if (
                        [string]::IsNullOrWhiteSpace($value)
                    ) {
                        continue
                    }

                    if (
                        Test-Path `
                            -LiteralPath $value `
                            -PathType Container
                    ) {

                        $fullPath =
                            (
                                Resolve-Path `
                                    -LiteralPath $value
                            ).Path

                        if (
                            Test-SafePkiCleanupDirectory `
                                -DirectoryPath $fullPath `
                                -ProjectRoot $projectRoot
                        ) {

                            if (
                                -not (
                                    $directories -contains $fullPath
                                )
                            ) {
                                $directories += $fullPath
                            }
                        }
                    }
                }
                catch {
                }
            }
        }
    }
    catch {
    }

    # --------------------------------------------------------
    # Always include the standard PKI directory.
    # --------------------------------------------------------

    $defaultPkiDirectory =
        Join-Path `
            $projectRoot `
            'pki'

    if (
        Test-Path `
            -LiteralPath $defaultPkiDirectory `
            -PathType Container
    ) {

        $fullPath =
            (
                Resolve-Path `
                    -LiteralPath $defaultPkiDirectory
            ).Path

        if (
            Test-SafePkiCleanupDirectory `
                -DirectoryPath $fullPath `
                -ProjectRoot $projectRoot
        ) {

            if (
                -not (
                    $directories -contains $fullPath
                )
            ) {
                $directories += $fullPath
            }
        }
    }

    return @($directories)
}

# ============================================================
# Remove generated PKI folders
# ============================================================

function Remove-PkiGeneratedFolders {
    [CmdletBinding()]
    param()

    $projectRoot =
        Get-PkiProjectRoot

    Write-TrustStoreLog `
        'Starting generated PKI folder cleanup...' `
        'INFO'

    Write-TrustStoreLog `
        "Project root: $projectRoot" `
        'INFO'

    $directories =
        @(Get-PkiCleanupDirectories)

    if ($directories.Count -eq 0) {

        Write-TrustStoreLog `
            'No generated PKI folders found to remove.' `
            'INFO'

        return $true
    }

    $directories =
        @(
            $directories |
            Sort-Object {
                $_.Length
            } -Descending
        )

    $removedCount = 0
    $failedCount = 0

    foreach ($directory in $directories) {

        if (
            -not (
                Test-SafePkiCleanupDirectory `
                    -DirectoryPath $directory `
                    -ProjectRoot $projectRoot
            )
        ) {

            Write-TrustStoreLog `
                "Skipping unsafe directory: $directory" `
                'WARN'

            $failedCount++

            continue
        }

        try {

            if (
                -not (
                    Test-Path `
                        -LiteralPath $directory `
                        -PathType Container
                )
            ) {
                continue
            }

            Write-TrustStoreLog `
                "Removing PKI folder: $directory" `
                'INFO'

            Remove-Item `
                -LiteralPath $directory `
                -Recurse `
                -Force `
                -ErrorAction Stop

            if (
                Test-Path `
                    -LiteralPath $directory
            ) {

                Write-TrustStoreLog `
                    "Folder still exists after removal: $directory" `
                    'ERROR'

                $failedCount++
            }
            else {

                Write-TrustStoreLog `
                    'PKI folder removed successfully.' `
                    'OK'

                $removedCount++
            }
        }
        catch {

            Write-TrustStoreLog `
                "Failed to remove PKI folder: $directory" `
                'ERROR'

            Write-TrustStoreLog `
                $_.Exception.Message `
                'ERROR'

            $failedCount++
        }
    }

    Write-TrustStoreLog `
        "PKI folders removed : $removedCount" `
        'INFO'

    Write-TrustStoreLog `
        "PKI folders failed  : $failedCount" `
        'INFO'

    if ($failedCount -eq 0) {

        Write-TrustStoreLog `
            'Generated PKI folder cleanup completed successfully.' `
            'OK'

        return $true
    }

    Write-TrustStoreLog `
        'Some PKI folders could not be removed.' `
        'WARN'

    return $false
}

# ============================================================
# Remove all matching trust
# ============================================================

function Remove-AllTrust {
    [CmdletBinding()]
    param()

    if (-not (Test-IsAdministrator)) {
        throw 'Remove-AllTrust requires an elevated Administrator PowerShell session.'
    }

    Write-TrustStoreLog `
        'START: Remove all matching PKI trust' `
        'INFO'

    Write-TrustStoreLog `
        'PKI Identity: Agantra Inovatif / NextMantra' `
        'INFO'

    Write-TrustStoreLog `
        'Scanning Windows Local Machine Certificate Stores...' `
        'INFO'

    $candidates =
        @(Get-PkiTrustStoreCandidates)

    Write-TrustStoreLog `
        '------------------------------------------------------------' `
        'INFO'

    $leafCandidates =
        @(
            $candidates |
            Where-Object {
                $_.Store -eq 'My' -and
                $_.IsCA -eq $false
            }
        )

    $intermediateCandidates =
        @(
            $candidates |
            Where-Object {
                $_.Store -eq 'CA'
            }
        )

    $rootCandidates =
        @(
            $candidates |
            Where-Object {
                $_.Store -eq 'Root'
            }
        )

    Write-TrustStoreLog `
        "Leaf certificate candidates found: $($leafCandidates.Count)" `
        'INFO'

    Write-TrustStoreLog `
        "Intermediate CA candidates found: $($intermediateCandidates.Count)" `
        'INFO'

    Write-TrustStoreLog `
        "Root CA candidates found: $($rootCandidates.Count)" `
        'INFO'

    Write-TrustStoreLog `
        '------------------------------------------------------------' `
        'INFO'

    foreach ($candidate in $candidates) {

        Write-TrustStoreLog `
            "MATCH: LocalMachine\$($candidate.Store)" `
            'INFO'

        Write-TrustStoreLog `
            "  Thumbprint : $($candidate.Thumbprint)" `
            'INFO'

        Write-TrustStoreLog `
            "  Subject    : $($candidate.Subject)" `
            'INFO'

        Write-TrustStoreLog `
            "  Issuer     : $($candidate.Issuer)" `
            'INFO'
    }

    # --------------------------------------------------------
    # Remove leaf first.
    # --------------------------------------------------------

    $leafRemoved = 0

    foreach ($candidate in $leafCandidates) {

        if (
            Remove-CertificateThumbprint `
                -Store My `
                -Thumbprint $candidate.Thumbprint
        ) {
            $leafRemoved++
        }
    }

    # --------------------------------------------------------
    # Remove intermediate CA.
    # --------------------------------------------------------

    $intermediateRemoved = 0

    foreach ($candidate in $intermediateCandidates) {

        if (
            Remove-CertificateThumbprint `
                -Store CA `
                -Thumbprint $candidate.Thumbprint
        ) {
            $intermediateRemoved++
        }
    }

    # --------------------------------------------------------
    # Remove root CA.
    # --------------------------------------------------------

    $rootRemoved = 0

    foreach ($candidate in $rootCandidates) {

        if (
            Remove-CertificateThumbprint `
                -Store Root `
                -Thumbprint $candidate.Thumbprint
        ) {
            $rootRemoved++
        }
    }

    # --------------------------------------------------------
    # Verify removal.
    # --------------------------------------------------------

    Write-TrustStoreLog `
        'Verifying certificate removal...' `
        'INFO'

    $remaining =
        @(Get-PkiTrustStoreCandidates)

    $remainingCount =
        $remaining.Count

    $totalRemoved =
        $leafRemoved +
        $intermediateRemoved +
        $rootRemoved

    Write-TrustStoreLog `
        '------------------------------------------------------------' `
        'INFO'

    Write-TrustStoreLog `
        "Leaf certificates removed      : $leafRemoved" `
        'INFO'

    Write-TrustStoreLog `
        "Intermediate CAs removed       : $intermediateRemoved" `
        'INFO'

    Write-TrustStoreLog `
        "Root CAs removed               : $rootRemoved" `
        'INFO'

    Write-TrustStoreLog `
        "TOTAL certificates removed     : $totalRemoved" `
        'OK'

    if ($remainingCount -gt 0) {

        Write-TrustStoreLog `
            "Matching certificates remaining: $remainingCount" `
            'WARN'

        foreach ($certificate in $remaining) {

            Write-TrustStoreLog `
                "REMAINING: LocalMachine\$($certificate.Store)" `
                'WARN'

            Write-TrustStoreLog `
                "  Thumbprint : $($certificate.Thumbprint)" `
                'WARN'

            Write-TrustStoreLog `
                "  Subject    : $($certificate.Subject)" `
                'WARN'

            Write-TrustStoreLog `
                "  Issuer     : $($certificate.Issuer)" `
                'WARN'
        }

        Write-TrustStoreLog `
            'PKI folders WILL NOT be removed because certificates remain.' `
            'WARN'

        return $totalRemoved
    }

    Write-TrustStoreLog `
        'Matching certificates remaining: 0' `
        'OK'

    Write-TrustStoreLog `
        'All matching Agantra/NextMantra certificates removed from LocalMachine.' `
        'OK'

    Write-TrustStoreLog `
        'Windows Local Machine certificate cleanup verified.' `
        'OK'

    # --------------------------------------------------------
    # Remove generated PKI directory only after successful
    # certificate-store cleanup.
    # --------------------------------------------------------

    Write-TrustStoreLog `
        'Starting PKI folder cleanup...' `
        'INFO'

    $folderCleanupResult =
        Remove-PkiGeneratedFolders

    Write-TrustStoreLog `
        '------------------------------------------------------------' `
        'INFO'

    if ($folderCleanupResult) {

        Write-TrustStoreLog `
            'RemoveAllTrust completed successfully.' `
            'OK'

        Write-TrustStoreLog `
            'All matching certificates removed.' `
            'OK'

        Write-TrustStoreLog `
            'Generated PKI folders removed.' `
            'OK'
    }
    else {

        Write-TrustStoreLog `
            'Certificate cleanup completed successfully.' `
            'OK'

        Write-TrustStoreLog `
            'Some generated PKI folders could not be removed.' `
            'WARN'
    }

    return $totalRemoved
}