# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Generates and manages the Agantra Inovatif DevSecOps Small Project local PKI.
.DESCRIPTION
    Creates a Root CA, Intermediate CA, RSA leaf certificates, PFX files,
    certificate chains, validation artifacts, and optional LocalMachine trust.

    Every leaf certificate is an EV certificate (CA/Browser Forum EV policy
    OID 2.23.140.1.1 plus the EV subject fields). All EV values are read from
    ev_pki.cnf. A command-line parameter overrides the file only when it is
    passed explicitly.
.AUTHOR
    Nicko Satria Utama
    Company: Agantra Inovatif OÜ
    Email: nicko@nextmantra.com
.NOTES
    Company: Agantra Inovatif OÜ (NextMantra)
    Email: nicko@nextmantra.com
    Project: Agantra Inovatif DevSecOps Small Project
#>
[CmdletBinding()]
param(
    # ---- Subject / EV values: default comes from ev_pki.cnf ----
    [string]$Domain,
    [string]$Organization,
    [string]$Country,
    [string]$Serial,
    [string]$BusinessCategory,
    [string]$JurisdictionCountry,
    [string]$JurisdictionState,
    [string]$JurisdictionLocality,
    [string]$State,
    [string]$Locality,
    [string]$Street,
    [string]$PostalCode,
    [string]$CpsUrl,

    # ---- Generation settings ----
    [int[]]$LeafSizes = @(2048, 3072, 4096),
    [int]$RootDays = 3650,
    [int]$IntDays = 3650,
    [int]$LeafDays = 3649,
    [string]$Password = 'Abc12345!',
    [switch]$LegacyPfx,
    [switch]$InstallTrust,
    [switch]$Clean,
    [switch]$RemoveTrust,
    [switch]$RemoveAllTrust,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Show-PkiHelp {
    @'
Local Windows PKI Generator (EV leaf certificates)
Author : Nicko Satria Utama
Company: Agantra Inovatif OÜ (NextMantra)
Email  : nicko@nextmantra.com

USAGE
  .\pki_setup.ps1
  .\pki_setup.ps1 -InstallTrust
  .\pki_setup.ps1 -Clean -InstallTrust
  .\pki_setup.ps1 -Serial 16543210 -Locality Tallinn
  .\pki_setup.ps1 -RemoveTrust
  .\pki_setup.ps1 -RemoveAllTrust
  .\pki_setup.ps1 -Verbose

EV SUBJECT OPTIONS
  Every value defaults to [ dn_leaf_ev ] in ev_pki.cnf. A parameter
  overrides the file only when it is passed explicitly.

  -Domain <string>              Leaf CN and DNS SAN (also adds www.<domain>).
  -Organization <string>        Subject O.
  -Country <string>             Subject C (ISO 3166 alpha-2).
  -Serial <string>              Subject serialNumber (registration number).
  -BusinessCategory <string>    Private Organization | Government Entity |
                                Business Entity | Non-Commercial Entity
  -JurisdictionCountry <string> jurisdictionC (ISO 3166 alpha-2).
  -JurisdictionState <string>   jurisdictionST.
  -JurisdictionLocality <string> jurisdictionL.
  -State <string>               Subject ST.
  -Locality <string>            Subject L.
  -Street <string>              Subject street address.
  -PostalCode <string>          Subject postal code.
  -CpsUrl <string>              CPS URI in the certificate policy.

GENERATION OPTIONS
  -LeafSizes <int[]>            RSA sizes. Default: 2048,3072,4096
  -RootDays <int>               Root validity. Default: 3650
  -IntDays <int>                Intermediate validity. Default: 3650
  -LeafDays <int>               Leaf validity. Default: 3649
  -Password <string>            PFX password. Default: Abc12345!
  -LegacyPfx                    Use OpenSSL legacy PFX algorithms.
  -InstallTrust                 Import Root/Intermediate/leaf certificates.
  -Clean                        Remove current trust/output before generation.
  -RemoveTrust                  Remove only the current generated PKI trust.
  -RemoveAllTrust               Remove matching PKI certificates from stores.
  -Verbose                      Show detailed execution information.
  -Help                         Show this help.
  -?                            PowerShell parameter help.

IMPORTANT
  ev_pki.cnf must sit next to this script (UTF-8, no BOM) and contain
  [ dn_leaf_ev ], [ v3_leaf ], [ ev_policy ] and [ leaf_san ].
  Certificate-store operations require an elevated PowerShell session.
  The script never prints the PFX password.
'@ | Write-Host
}

if ($Help) {
    Show-PkiHelp
    exit 0
}

# Only parameters passed explicitly override ev_pki.cnf.
$evOverrides = @{}
foreach ($name in @(
    'Domain', 'Organization', 'Country', 'Serial', 'BusinessCategory',
    'JurisdictionCountry', 'JurisdictionState', 'JurisdictionLocality',
    'State', 'Locality', 'Street', 'PostalCode', 'CpsUrl'
)) {
    if ($PSBoundParameters.ContainsKey($name)) {
        $evOverrides[$name] = [string]$PSBoundParameters[$name]
    }
}

Write-Host '============================================================'
Write-Host 'Author : Nicko Satria Utama'
Write-Host 'Company: Agantra Inovatif OÜ (NextMantra)'
Write-Host 'Email: nicko@nextmantra.com'
Write-Host '============================================================'
Write-Host ''

# Remove Windows/Internet Zone.Identifier marks from this PKI package before
# dot-sourcing the child scripts. This prevents repeated prompts for the
# individual scripts after the entry point has been allowed to run once.
# The very first launch of pki_setup.ps1 may still show Windows' own trust
# prompt because that decision happens before this script starts executing.
try {
    Get-ChildItem -Path $script:ScriptRoot -Recurse -File -ErrorAction SilentlyContinue |
        Unblock-File -ErrorAction SilentlyContinue
}
catch {
    Write-Host "[WARN] Automatic script unblocking failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

$moduleFiles = @(
    '00_Common.ps1',
    '01_Configuration.ps1',
    '02_OpenSSL.ps1',
    '03_RuntimeConfig.ps1',
    '04_CertificateAuthority.ps1',
    '05_LeafCertificates.ps1',
    '06_Validation.ps1',
    '07_TrustStore.ps1',
    '08_Cleanup.ps1',
    '09_Administrator.ps1',
    '10_Main.ps1'
)

try {
    foreach ($module in $moduleFiles) {
        $modulePath = Join-Path $script:ScriptRoot "scripts\$module"
        if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
            throw "Required module not found: $modulePath"
        }
        . $modulePath
    }

    Initialize-PkiConfiguration `
        -ScriptRoot $script:ScriptRoot `
        -EvOverrides $evOverrides `
        -LeafSizes $LeafSizes `
        -RootDays $RootDays `
        -IntDays $IntDays `
        -LeafDays $LeafDays `
        -Password $Password `
        -LegacyPfx:$LegacyPfx `
        -InstallTrust:$InstallTrust `
        -Clean:$Clean `
        -RemoveTrust:$RemoveTrust `
        -RemoveAllTrust:$RemoveAllTrust `
        -VerboseOutput:($VerbosePreference -eq 'Continue')

    Invoke-PkiMain
    exit 0
}
catch {
    $failure = $_
    if (Get-Command Write-PkiFatalError -ErrorAction SilentlyContinue) {
        try {
            Write-PkiFatalError -ErrorRecord $failure
        }
        catch {
            Write-Host "[FATAL] $($failure.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        $ii = $failure.InvocationInfo
        Write-Host ''
        Write-Host '[ERROR] PKI STARTUP FAILED' -ForegroundColor Red
        Write-Host "[ERROR] Exception: $($failure.Exception.GetType().FullName)" -ForegroundColor Red
        Write-Host "[ERROR] Details: $($failure.Exception.Message)" -ForegroundColor Red
        if ($ii.ScriptName) { Write-Host "[ERROR] Filename: $($ii.ScriptName)" -ForegroundColor Red }
        if ($ii.ScriptLineNumber) { Write-Host "[ERROR] Line: $($ii.ScriptLineNumber)" -ForegroundColor Red }
        if ($ii.OffsetInLine) { Write-Host "[ERROR] Column: $($ii.OffsetInLine)" -ForegroundColor Red }
        if ($ii.Line) { Write-Host "[ERROR] Code: $($ii.Line.Trim())" -ForegroundColor Red }
        if ($ii.PositionMessage) { Write-Host $ii.PositionMessage -ForegroundColor DarkRed }
        if ($failure.ScriptStackTrace) { Write-Host '[ERROR] Script stack:' -ForegroundColor Red; Write-Host $failure.ScriptStackTrace -ForegroundColor DarkRed }
    }
    exit 1
}
finally {
    if (Get-Command Clear-PkiSecretEnvironment -ErrorAction SilentlyContinue) {
        Clear-PkiSecretEnvironment
    }
}