# ============================================================
# 01_Configuration.ps1
#
# PKI Configuration
#
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
#
# Purpose:
#   - Initialize the shared PKI configuration
#   - Load the EV leaf profile from ev_pki.cnf
#   - Store PKI paths and certificate settings
#   - Store the PFX password supplied by pki_setup.ps1
#   - Provide the configuration to all dot-sourced PKI modules
#
# Password behavior:
#   - Default password is supplied by pki_setup.ps1:
#       Abc12345!
#   - Explicit -Password overrides the default.
#
# IMPORTANT:
#   The PKI modules are dot-sourced from pki_setup.ps1.
#   The shared configuration therefore uses $global:Pki.
#
#   $script:Pki is also maintained as a compatibility alias
#   because existing PKI modules may reference $script:Pki.
#
# ============================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Initialize-PkiConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ScriptRoot,

        # Domain / Organization / Country are optional. When omitted
        # they are taken from [ dn_leaf_ev ] in ev_pki.cnf.
        [string]$Domain,

        [string]$Organization,

        [string]$Country,

        # Explicit command-line EV overrides (Serial, Locality, ...).
        [hashtable]$EvOverrides = @{},

        [Parameter(Mandatory)]
        [int[]]$LeafSizes,

        [Parameter(Mandatory)]
        [int]$RootDays,

        [Parameter(Mandatory)]
        [int]$IntDays,

        [Parameter(Mandatory)]
        [int]$LeafDays,

        [Parameter(Mandatory)]
        [string]$Password,

        [switch]$LegacyPfx,

        [switch]$InstallTrust,

        [switch]$Clean,

        [switch]$RemoveTrust,

        [switch]$RemoveAllTrust,

        [bool]$VerboseOutput
    )

    # --------------------------------------------------------
    # Normalize script root
    # --------------------------------------------------------

    if ([string]::IsNullOrWhiteSpace($ScriptRoot)) {
        throw 'ScriptRoot cannot be empty.'
    }

    $resolvedScriptRoot = $ScriptRoot

    if (Test-Path -LiteralPath $ScriptRoot -PathType Container) {
        try {
            $resolvedScriptRoot = (Resolve-Path -LiteralPath $ScriptRoot -ErrorAction Stop).Path
        }
        catch {
            $resolvedScriptRoot = $ScriptRoot
        }
    }

    # --------------------------------------------------------
    # PKI root directories
    # --------------------------------------------------------

    $pkiRoot = Join-Path $resolvedScriptRoot 'pki'

    $rootDir         = Join-Path $pkiRoot 'root'
    $intermediateDir = Join-Path $pkiRoot 'intermediate'
    $leafDir         = Join-Path $pkiRoot 'leaf'
    $issuedDir       = Join-Path $pkiRoot 'issued'

    # --------------------------------------------------------
    # Configuration files
    # --------------------------------------------------------

    $masterConfig  = Join-Path $resolvedScriptRoot 'ev_pki.cnf'
    $runtimeConfig = Join-Path $pkiRoot 'openssl.runtime.cnf'
    $leafReqConfig = Join-Path $pkiRoot 'leaf-ev.req.cnf'

    # --------------------------------------------------------
    # PKI database / state files
    # --------------------------------------------------------

    $indexFile       = Join-Path $pkiRoot 'index.txt'
    $indexAttrFile   = Join-Path $pkiRoot 'index.txt.attr'
    $serialFile      = Join-Path $pkiRoot 'serial'
    $rootSerialFile  = Join-Path $pkiRoot 'root.serial'
    $manifestFile    = Join-Path $pkiRoot 'pki-manifest.json'
    $telemetryFile   = Join-Path $pkiRoot 'telemetry.json'

    # --------------------------------------------------------
    # Load the EV leaf profile from ev_pki.cnf.
    #
    # ev_pki.cnf supplies every default. Only parameters that
    # were explicitly passed on the command line override it.
    # Domain / Organization / Country are resolved from it too.
    # --------------------------------------------------------

    $overrides = @{}
    foreach ($key in $EvOverrides.Keys) { $overrides[$key] = $EvOverrides[$key] }

    foreach ($pair in @(
        @('Domain', $Domain),
        @('Organization', $Organization),
        @('Country', $Country)
    )) {
        if (-not [string]::IsNullOrWhiteSpace($pair[1])) {
            $overrides[$pair[0]] = $pair[1]
        }
    }

    $evProfile = Get-EvProfile `
        -MasterConfig $masterConfig `
        -Overrides $overrides

    $Domain       = $evProfile.Domain
    $Organization = $evProfile.Organization
    $Country      = $evProfile.Country

    # --------------------------------------------------------
    # Validate parameters
    # --------------------------------------------------------

    if ([string]::IsNullOrWhiteSpace($Domain)) {
        throw 'Domain cannot be empty.'
    }

    if ([string]::IsNullOrWhiteSpace($Organization)) {
        throw 'Organization cannot be empty.'
    }

    if ($Country -notmatch '^[A-Za-z]{2}$') {
        throw "Country must be exactly two letters: '$Country'."
    }

    if ($RootDays -lt 1) {
        throw "RootDays must be greater than zero: $RootDays."
    }

    if ($IntDays -lt 1) {
        throw "IntDays must be greater than zero: $IntDays."
    }

    if ($LeafDays -lt 1) {
        throw "LeafDays must be greater than zero: $LeafDays."
    }

    if ($IntDays -gt $RootDays) {
        throw "IntDays ($IntDays) cannot exceed RootDays ($RootDays)."
    }

    if ($LeafDays -ge $IntDays) {
        throw "LeafDays ($LeafDays) must be less than IntDays ($IntDays) so the leaf cannot outlive its issuing Intermediate CA."
    }

    if ($null -eq $LeafSizes) {
        throw 'LeafSizes cannot be null.'
    }

    if ($LeafSizes.Count -eq 0) {
        throw 'At least one leaf RSA size is required.'
    }

    foreach ($bits in $LeafSizes) {
        if ($bits -notin @(2048, 3072, 4096)) {
            throw "Unsupported leaf RSA size '$bits'. Use 2048, 3072 and/or 4096."
        }
    }

    # --------------------------------------------------------
    # PFX password
    #
    # pki_setup.ps1 already defines:
    #
    #   [string]$Password = 'Abc12345!'
    #
    # Therefore this function receives either the supplied
    # password or the default password from pki_setup.ps1.
    #
    # Keep the fallback here as an additional safety net.
    # --------------------------------------------------------

    if ([string]::IsNullOrWhiteSpace($Password)) {
        $Password = 'Abc12345!'
    }

    if ([string]::IsNullOrWhiteSpace($Password)) {
        throw 'PFX password cannot be empty.'
    }

    # --------------------------------------------------------
    # Start telemetry before configuration is finalized.
    # --------------------------------------------------------

    Start-PkiTelemetry -OutputDirectory $pkiRoot

    # --------------------------------------------------------
    # Build shared PKI configuration.
    #
    # IMPORTANT:
    #   Use an OrderedDictionary so existing code that calls
    #   .Contains() or accesses properties remains compatible.
    # --------------------------------------------------------

    $configuration = [ordered]@{
        ScriptRoot = $resolvedScriptRoot

        Domain = $Domain.Trim().ToLowerInvariant()

        Organization = $Organization.Trim()

        Country = $Country.Trim().ToUpperInvariant()

        LeafSizes = @(
            $LeafSizes |
                Sort-Object -Unique
        )

        RootDays = [int]$RootDays

        IntDays = [int]$IntDays

        LeafDays = [int]$LeafDays

        # ----------------------------------------------------
        # PFX password
        # ----------------------------------------------------
        Password = [string]$Password

        # Explicit alias used by some PKI modules.
        PfxPassword = [string]$Password

        LegacyPfx = [bool]$LegacyPfx

        InstallTrust = [bool]$InstallTrust

        Clean = [bool]$Clean

        RemoveTrust = [bool]$RemoveTrust

        RemoveAllTrust = [bool]$RemoveAllTrust

        VerboseOutput = [bool]$VerboseOutput

        # ----------------------------------------------------
        # Directory configuration
        # ----------------------------------------------------

        PkiRoot = $pkiRoot

        RootDir = $rootDir

        IntermediateDir = $intermediateDir

        LeafDir = $leafDir

        IssuedDir = $issuedDir

        # ----------------------------------------------------
        # OpenSSL configuration
        # ----------------------------------------------------

        MasterConfig = $masterConfig

        RuntimeConfig = $runtimeConfig

        LeafReqConfig = $leafReqConfig

        # EV leaf profile loaded from ev_pki.cnf (+ overrides).
        Ev = $evProfile

        OpenSslExe = $null

        OpenSslVersion = $null

        # ----------------------------------------------------
        # PKI database/state files
        # ----------------------------------------------------

        IndexFile = $indexFile

        IndexAttrFile = $indexAttrFile

        SerialFile = $serialFile

        RootSerialFile = $rootSerialFile

        ManifestFile = $manifestFile

        TelemetryFile = $telemetryFile

        # ----------------------------------------------------
        # Root CA files
        # ----------------------------------------------------

        RootKey = Join-Path $rootDir 'root.key'

        RootPub = Join-Path $rootDir 'root.pub'

        RootCrt = Join-Path $rootDir 'root.crt'

        RootPfx = Join-Path $rootDir 'root.pfx'

        # ----------------------------------------------------
        # Intermediate CA files
        # ----------------------------------------------------

        IntermediateKey = Join-Path $intermediateDir 'intermediate.key'

        IntermediatePub = Join-Path $intermediateDir 'intermediate.pub'

        IntermediateCsr = Join-Path $intermediateDir 'intermediate.csr'

        IntermediateCrt = Join-Path $intermediateDir 'intermediate.crt'

        IntermediatePfx = Join-Path $intermediateDir 'intermediate.pfx'

        # ----------------------------------------------------
        # Leaf certificate collection
        # ----------------------------------------------------

        LeafFiles = [System.Collections.Generic.List[object]]::new()
    }

    # --------------------------------------------------------
    # Publish the configuration to the shared global scope.
    #
    # All dot-sourced PKI modules can access:
    #
    #   $global:Pki
    #
    # --------------------------------------------------------

    $global:Pki = $configuration

    # --------------------------------------------------------
    # Compatibility alias.
    #
    # Existing modules currently use:
    #
    #   $script:Pki.Password
    #   $script:Pki.RootCrt
    #   $script:Pki.LeafDir
    #
    # Keep this assignment so existing code continues to work
    # without requiring an immediate rewrite of every module.
    # --------------------------------------------------------

    $script:Pki = $global:Pki

    # --------------------------------------------------------
    # Store the password in the existing secret environment
    # mechanism used by the PKI package.
    # --------------------------------------------------------

    Set-PkiSecretEnvironment -Password $Password

    # --------------------------------------------------------
    # Verbose diagnostics.
    #
    # NEVER print the actual password.
    # --------------------------------------------------------

    Write-PkiVerbose "Script root: $resolvedScriptRoot"

    Write-PkiVerbose "PKI root: $pkiRoot"

    Write-PkiVerbose "Domain: $($global:Pki.Domain)"

    Write-PkiVerbose "Organization: $($global:Pki.Organization)"

    Write-PkiVerbose "Country: $($global:Pki.Country)"

    Write-PkiVerbose "Leaf sizes: $($global:Pki.LeafSizes -join ', ')"

    Write-PkiVerbose "EV master config: $masterConfig"

    Write-PkiVerbose "EV policy OID: $($evProfile.PolicyOid)"

    Write-PkiVerbose "EV serialNumber: $(Get-EvDnValue -Fields $evProfile.DnFields -Canonical 'serialNumber')"

    Write-PkiVerbose "Leaf DNS names: $($evProfile.DnsNames -join ', ')"

    Write-PkiVerbose "PFX password configured: $([bool](-not [string]::IsNullOrWhiteSpace($global:Pki.Password)))"
}

function Get-MasterConfigMetadata {
    [CmdletBinding()]
    param()

    if ($null -eq $global:Pki) {
        throw 'PKI configuration has not been initialized.'
    }

    $result = [ordered]@{
        Organizations = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )

        DnsNames = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )

        CommonNames = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
    }

    if (-not (Test-Path -LiteralPath $global:Pki.MasterConfig -PathType Leaf)) {
        [void]$result.Organizations.Add($global:Pki.Organization)

        [void]$result.DnsNames.Add($global:Pki.Domain)

        [void]$result.DnsNames.Add(
            "www.$($global:Pki.Domain)"
        )

        [void]$result.CommonNames.Add($global:Pki.Domain)

        return [pscustomobject]$result
    }

    foreach ($rawLine in Get-Content -LiteralPath $global:Pki.MasterConfig -ErrorAction Stop) {

        $line = Remove-OpenSslConfComment -Text $rawLine

        if ($line -match '^\s*(?:O|organizationName)\s*=\s*(.+?)\s*$') {

            [void]$result.Organizations.Add(
                $matches[1].Trim()
            )
        }
        elseif ($line -match '^\s*DNS\.\d+\s*=\s*(.+?)\s*$') {

            [void]$result.DnsNames.Add(
                $matches[1].Trim()
            )
        }
        elseif ($line -match '^\s*(?:CN|commonName)\s*=\s*(.+?)\s*$') {

            [void]$result.CommonNames.Add(
                $matches[1].Trim()
            )
        }
    }

    # --------------------------------------------------------
    # Always include the active runtime configuration.
    # --------------------------------------------------------

    [void]$result.Organizations.Add(
        $global:Pki.Organization
    )

    [void]$result.DnsNames.Add(
        $global:Pki.Domain
    )

    [void]$result.DnsNames.Add(
        "www.$($global:Pki.Domain)"
    )

    [void]$result.CommonNames.Add(
        $global:Pki.Domain
    )

    return [pscustomobject]$result
}