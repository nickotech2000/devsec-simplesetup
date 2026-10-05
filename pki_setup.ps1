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

    Every leaf certificate is an EV TLS certificate (CA/Browser Forum EV
    policy OID 2.23.140.1.1, EKU = serverAuth + clientAuth, EV subject
    fields, contact name / e-mail / phone, CRL + OCSP + CA Issuers
    locations, at most 398 days). Wildcard names in the SAN are allowed
    (private / lab PKI) and only produce a warning. All EV values are read
    from ev_pki.cnf. A
    command-line parameter overrides the file only when it is passed
    explicitly. Values that are not defined anywhere default to
    OU = BizDevSecOps, Locality = Tallinn, Country = EE, Jurisdiction = EE.

    The Root and Intermediate CA subjects carry Locality, Jurisdiction,
    Serial Number and contact name / e-mail / phone
    ([ dn_root_ev ] and [ dn_intermediate_ev ] in ev_pki.cnf).

    Other EKUs (codeSigning, emailProtection, ...) are issued as separate
    certificates by GenerateLeafCertificate.ps1. An existing PKI folder is
    reused with pki_reuse.ps1 instead of generating a new one.

    Run  .\pki_setup.ps1 -Help  for the full parameter list and examples.
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
    [string]$OrganizationalUnit,
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
    [string]$ContactName,
    [string]$ContactEmail,
    [string]$ContactPhone,

    # ---- Generation settings ----
    [int[]]$LeafSizes = @(2048, 3072, 4096),
    [int]$RootDays = 3650,
    [int]$IntDays = 3650,
    [int]$LeafDays = 397,
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
============================================================
 pki_setup.ps1 - Local Windows PKI generator (EV leaf certificates)
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
============================================================

WHAT IT DOES
  Creates a new private PKI in .\pki :
    Root CA (RSA 8192) -> Intermediate CA (RSA 8192) -> EV leaf certificates
  plus PFX files, certificate chains, the CRL and CA-issuer files to publish,
  a validation report, and (optional) trust in the Windows certificate stores.

  Every leaf certificate is an EV TLS certificate:
    EKU = serverAuth + clientAuth, policy 2.23.140.1.1, full EV subject,
    contact name / e-mail / phone, CRL + OCSP + CA Issuers locations,
    at most 398 days. Wildcard SAN names are allowed (private / lab PKI).
  Other EKUs (codeSigning, emailProtection, ...) are made by
  GenerateLeafCertificate.ps1, one certificate and one file set per EKU.

USAGE
  .\pki_setup.ps1                              generate (RSA 2048, 3072, 4096 leaves)
  .\pki_setup.ps1 -LeafSizes 2048              one leaf size only
  .\pki_setup.ps1 -InstallTrust                generate, then trust in Windows (admin)
  .\pki_setup.ps1 -Clean -InstallTrust         remove the old PKI first, then regenerate
  .\pki_setup.ps1 -Domain app.example.com -Serial 16543210
  .\pki_setup.ps1 -RemoveTrust                 remove the current PKI from Windows
  .\pki_setup.ps1 -RemoveAllTrust              remove every matching PKI from Windows
  .\pki_setup.ps1 -Verbose                     show OpenSSL commands and details
  .\pki_setup.ps1 -Help                        this help

SUBJECT / EV OPTIONS
  Each value defaults to ev_pki.cnf. A parameter overrides the file only when
  it is passed on the command line.

  -Domain <name>               Leaf CN and DNS SAN (also adds www.<name>).
  -Organization <text>         O.
  -OrganizationalUnit <text>   OU.                       Default: BizDevSecOps
  -Country <cc>                C (ISO 3166 alpha-2).      Default: EE
  -Locality <text>             L.                         Default: Tallinn
  -State <text>                ST.
  -Street <text>               Street address.
  -PostalCode <text>           Postal code.
  -JurisdictionCountry <cc>    jurisdictionC.             Default: EE
  -JurisdictionState <text>    jurisdictionST.
  -JurisdictionLocality <text> jurisdictionL.
  -Serial <text>               serialNumber (registration number).
  -BusinessCategory <text>     Private Organization | Government Entity |
                               Business Entity | Non-Commercial Entity
  -CpsUrl <url>                CPS URI in the certificate policy.
  -ContactName <text>          Leaf contact name.         Default: Application Administrator
  -ContactEmail <text>         Leaf contact e-mail.       Default: info@nextmantra.com
  -ContactPhone <text>         Leaf contact phone.        Default: (+372)53194019

  Root and Intermediate CA subjects ([ dn_root_ev ] / [ dn_intermediate_ev ] in
  ev_pki.cnf) carry Locality Tallinn, Jurisdiction EE, Serial Number
  EEARIREG.17344131 and the CA contact name / e-mail / phone.

GENERATION OPTIONS
  -LeafSizes <int[]>   RSA leaf sizes.                    Default: 2048,3072,4096
  -RootDays <int>      Default 3650. Only used to check that -IntDays / -LeafDays fit;
  -IntDays <int>       Default 3650. the CA certificates themselves are valid 500 years
                       (Root) and 250 years (Intermediate), set in
                       scripts\04_CertificateAuthority.ps1.
  -LeafDays <int>      Leaf validity in days.             Default: 397 (EV maximum 398)
  -Password <text>     PFX password.                      Default: Abc12345!
  -LegacyPfx           Legacy PFX encryption (3DES/RC2/SHA1) for very old software.

TRUST / CLEANUP (need an elevated PowerShell)
  -InstallTrust        Root -> LocalMachine\Root, Intermediate -> LocalMachine\CA,
                       leaf PFX -> LocalMachine\My.
  -Clean               Remove the current PKI trust and output before generating.
  -RemoveTrust         Remove only the current PKI from the Windows stores.
  -RemoveAllTrust      Remove every certificate that matches this PKI's identity.

OTHER
  -Verbose             Detailed execution information.
  -Help                This help.      -?   PowerShell parameter help.

OUTPUT (.\pki)
  root\root.crt/.key/.pfx                 Root CA
  intermediate\intermediate.crt/.key/.pfx Intermediate CA
  leaf\<domain>-<size>.crt/.key/.pfx/...  EV leaf certificates
  publish\                                CRL (.crl), CA issuer (.crt), root.crt, README.txt
  openssl.runtime.cnf, *.req.cnf          generated OpenSSL configuration
  pki-manifest.json, telemetry.json       what was generated

RELATED SCRIPTS
  GenerateLeafCertificate.ps1 -Help   issue more leaf certificates (RSA/ECC, SHA-2,
                                      codeSigning ..., development SAN set)
  pki_reuse.ps1 -Help                 reuse an EXISTING PKI folder (check, adopt, trust)
  COMPATIBILITY.md                    browsers, devices, web servers

IMPORTANT
  * ev_pki.cnf must sit next to this script (UTF-8, no BOM). It holds [ dn_leaf_ev ],
    [ v3_leaf ], [ ev_policy ], [ leaf_san ], [ leaf_crl ] and [ leaf_aia ].
  * The CRL / OCSP / CA Issuers URLs in the certificates are only useful when the
    files in .\pki\publish are served there. Windows reports "revocation server
    offline" for client certificates until at least one is reachable.
  * This is a PRIVATE PKI. Browsers show the company name only under "Show
    certificate"; the "Issued to: <company>" line is reserved for EV certificates
    that chain to a root in the browser's built-in EV list.
  * Certificate-store operations require Administrator. The PFX password is never
    printed.
'@ | Write-Host
}

if ($Help) {
    Show-PkiHelp
    exit 0
}

# Only parameters passed explicitly override ev_pki.cnf.
$evOverrides = @{}
foreach ($name in @(
    'Domain', 'Organization', 'OrganizationalUnit', 'Country', 'Serial', 'BusinessCategory',
    'JurisdictionCountry', 'JurisdictionState', 'JurisdictionLocality',
    'State', 'Locality', 'Street', 'PostalCode', 'CpsUrl',
    'ContactName', 'ContactEmail', 'ContactPhone'
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