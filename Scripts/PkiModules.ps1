# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# PkiModules.ps1  -  the module loader (ONE place that knows the modules)
#
# pki_setup.ps1 and every later script (GenerateLeafCertificate.ps1 in Phase B, the transport /
# install script in Phase C ...) load the shared modules the same way. DOT-SOURCE this file:
#
#     $PkiModuleSet = 'All'                                   # optional, default 'All'
#     . (Join-Path $PSScriptRoot 'scripts\PkiModules.ps1')
#
# Sets:
#   All      every module (the generator, pki_setup.ps1)
#   Library  every module except the pki_setup orchestration (10_Main): for scripts that issue or
#            read certificates (Phase B)
#   Trust    only what is needed to install / remove certificates in the Windows stores
#            (00_Common, 07_TrustStore, 09_Administrator). Such a script calls Initialize-PkiMinimalContext first.
#   Transport  what the DESTINATION scripts (PkiTransport.ps1 -Install, Unpack-PkiTransport.ps1) need:
#            00_Common, 02_OpenSSL, 07_TrustStore, 09_Administrator, 16_CertPack, 17_Transport. A small kit.
#
# It must be dot-sourced (not called) so the functions land in the caller's scope.
# Module documentation: docs\scripts-README.txt
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:PkiModuleCatalog = @(
    @{ File = '00_Common.ps1';               Sets = 'All', 'Library', 'Trust', 'Transport'; Purpose = 'logging, steps, telemetry, PEM helpers, minimal context' }
    @{ File = '01_Configuration.ps1';        Sets = 'All', 'Library';          Purpose = 'configuration, CA catalog (the hierarchy), policies' }
    @{ File = '01b_CaNaming.ps1';            Sets = 'All', 'Library';          Purpose = 'names of all roots and intermediates' }
    @{ File = '02_OpenSSL.ps1';              Sets = 'All', 'Library', 'Transport'; Purpose = 'OpenSSL 4 gate, providers, keys' }
    @{ File = '03_RuntimeConfig.ps1';        Sets = 'All', 'Library';          Purpose = 'OpenSSL configuration files, policies, DN' }
    @{ File = '04_CertificateAuthority.ps1'; Sets = 'All', 'Library';          Purpose = 'builds the CAs, CRLs, publish files' }
    @{ File = '05_LeafCertificates.ps1';     Sets = 'All', 'Library';          Purpose = 'default EV leaves (Phase B reuses the helpers)' }
    @{ File = '06_Validation.ps1';           Sets = 'All', 'Library';          Purpose = 'validation of CAs, leaves, chains, manifest' }
    @{ File = '07_TrustStore.ps1';           Sets = 'All', 'Library', 'Trust', 'Transport'; Purpose = 'Windows certificate stores' }
    @{ File = '08_Cleanup.ps1';              Sets = 'All', 'Library';          Purpose = 'clean, safe folder deletion' }
    @{ File = '09_Administrator.ps1';        Sets = 'All', 'Library', 'Trust', 'Transport'; Purpose = 'administrator check' }
    @{ File = '10_Main.ps1';                 Sets = 'All';                     Purpose = 'orchestration of pki_setup.ps1' }
    @{ File = '11_Preflight.ps1';            Sets = 'All', 'Library';          Purpose = '-Check and -Verify' }
    @{ File = '12_ExistingPki.ps1';          Sets = 'All', 'Library';          Purpose = 'load an existing PKI from its manifest' }
    @{ File = '13_ExternalRoot.ps1';         Sets = 'All', 'Library';          Purpose = 'Enterprise Root signed by a public CA, cross-signing' }
    @{ File = '14_LeafGenerator.ps1';        Sets = 'All', 'Library';          Purpose = 'the leaf certificate generator (all levels, keys, formats)' }
    @{ File = '15_LeafGuidance.ps1';         Sets = 'All', 'Library';          Purpose = 'conversion script and TLS guidance written next to a leaf' }
    @{ File = '16_CertPack.ps1';             Sets = 'All', 'Library', 'Transport'; Purpose = 'password-protected archives (.certpacked): AES-256 zip engine, 7-Zip' }
    @{ File = '18_Revocation.ps1';           Sets = 'All', 'Library';          Purpose = 'CRL, revocation, OCSP responder and time stamp certificates, revocation information' }
    @{ File = '20_PersonLeaf.ps1';           Sets = 'All', 'Library';          Purpose = 'person (natural person) leaf certificates: subject, e-mail SAN, id code check, file import' }
    @{ File = '19_ExternalCaSigning.ps1';    Sets = 'All', 'Library';          Purpose = 'sign the CSR of another private CA with our intermediate or Quadrant Root' }
    @{ File = '21_DevKit.ps1';               Sets = 'All', 'Library';          Purpose = 'the DevKit: one archive with the PKI, installers and generators for developers (Windows and Ubuntu)' }
    @{ File = '22_CsrSigning.ps1';           Sets = 'All', 'Library';          Purpose = 'checks a CSR against the spec of the PKI and signs it (leaf certificates; CA requests use the same checker)' }
    @{ File = '17_Transport.ps1';            Sets = 'All', 'Library', 'Transport'; Purpose = 'Phase C: pack, unpack, scans, Windows trust install' }
)

$__pkiSet = 'All'
if (Test-Path variable:PkiModuleSet) { $__pkiSet = [string](Get-Variable -Name PkiModuleSet -ValueOnly) }
if ($__pkiSet -notin 'All', 'Library', 'Trust', 'Transport') { throw "PkiModuleSet must be All, Library, Trust or Transport (got '$__pkiSet')." }

foreach ($__pkiModule in $script:PkiModuleCatalog) {
    if ($__pkiModule.Sets -notcontains $__pkiSet) { continue }
    $__pkiPath = Join-Path $PSScriptRoot $__pkiModule.File
    if (-not (Test-Path -LiteralPath $__pkiPath -PathType Leaf)) { throw "Required module not found: $__pkiPath" }
    . $__pkiPath
}
Remove-Variable -Name __pkiSet, __pkiModule, __pkiPath -ErrorAction SilentlyContinue

function Get-PkiModuleInfo {
    # Lists the modules and the sets they belong to.
    $script:PkiModuleCatalog | ForEach-Object { [pscustomobject]@{ File = $_.File; Sets = ($_.Sets -join ', '); Purpose = $_.Purpose } }
}
