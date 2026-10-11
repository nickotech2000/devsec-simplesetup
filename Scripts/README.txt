====================================================================================================
 scripts\  -  SHARED MODULES OF THE AGANTRA PKI SCRIPTS
====================================================================================================
 Version 4.9.3-phaseC      Author: Nicko Satria Utama, Agantra Inovatif OU (NextMantra)
 Used by : pki_setup.ps1   GenerateLeafCertificate.ps1   PkiTransport.ps1   Unpack-PkiTransport.ps1

 This folder is a small library. Nothing in it runs by itself: every file only DEFINES functions.
 The scripts in the project folder load it and call the functions.

 CONTENTS
   1  How a script loads the modules          4  Shared state ($script:Pki)
   2  The modules (what each provides)        5  Rules for adding or changing a module
   3  Patterns for Phase B and Phase C        6  Where to change what


====================================================================================================
 1  HOW A SCRIPT LOADS THE MODULES
====================================================================================================
 ONE loader knows all modules: scripts\PkiModules.ps1. DOT-SOURCE it (a leading dot and a space):

     $PkiModuleSet = 'Library'                          # All | Library | Trust   (default All)
     . (Join-Path $PSScriptRoot 'scripts\PkiModules.ps1')

 It must be dot-sourced, not called, so the functions land in YOUR script's scope.

   Set      Loads                                       For
   -------  ------------------------------------------  --------------------------------------------
   All      every module                                pki_setup.ps1
   Library  every module except 10_Main                 scripts that issue or read certificates
                                                        (GenerateLeafCertificate.ps1, Phase B)
   Transport 00_Common, 02_OpenSSL, 07_TrustStore,       the DESTINATION scripts (PkiTransport.ps1 -Install,
             09_Administrator, 16_CertPack, 17_Transport   Unpack-PkiTransport.ps1): a small kit
   Trust    00_Common, 07_TrustStore, 09_Administrator   scripts that only install / remove trust in
                                                        the Windows stores (transport script, Phase C)

 Get-PkiModuleInfo lists the modules. Adding a module = one line in PkiModules.ps1.


====================================================================================================
 2  THE MODULES
====================================================================================================
 File                          Provides                                          Needs
 ----------------------------  ------------------------------------------------  --------------------
 00_Common.ps1                 Write-PkiLog, Invoke-PkiStep, telemetry, Unblock- nothing
                               PkiTree, Unlock-PkiTree, Invoke-PkiUnblockUnlock,
                               Ensure-
                               PkiDirectory, Write-Utf8NoBom, Assert-PkiFile,
                               PEM helpers (ConvertFrom-PkiPemToDer, Split-
                               PkiPemBundle, Get-PkiCertificateFingerprint),
                               Initialize-PkiMinimalContext, identity markers
 01_Configuration.ps1          Initialize-PkiConfiguration (command line > cnf   00
                               > default), Read-PkiIni, Get-PkiIniValue, the CA
                               CATALOG (New-PkiCatalog, Get-PkiCa), policy
                               helpers (Get-PkiExtraPolicies, Get-PkiLeafDays),
                               root key policy constants
 01b_CaNaming.ps1              NAMING of all CAs and of the LEAF folders / files: 00, 01
                               templates, tokens, Get-PkiCaCommonName, Get-PkiCaSlug,
                               Test-PkiNaming, Get-PkiLeafNames, New-PkiUniqueFolder
 02_OpenSSL.ps1                Find-OpenSSL (newest 4.x of all candidates),     00, 01
                               Initialize-OpenSSL (4.x gate, advice that names
                               Install-DevEnvironment.ps1), Invoke-OpenSSL (always
                               sets OPENSSL_CONF: PKI configuration or a neutral
                               one), providers, New-PkiPrivateKey (RSA, ECDSA,
                               ML-DSA), digest helpers
 03_RuntimeConfig.ps1          OpenSSL configuration files per CA, provider      00, 01, 01b, 02
                               header, DN, policies, CA database
 04_CertificateAuthority.ps1   New-PkiCa, New-PkiHierarchy, chain files, PFX,    00-03
                               CRL / publish
 05_LeafCertificates.ps1       leaf helpers (SAN, subject, key, issue, chain)    00-04
 06_Validation.ps1             Test-AllPkiArtifacts, Test-PkiLeaf, manifest      00-04
 07_TrustStore.ps1             Install-PkiTrust (roots -> Root, intermediates    00, 09
                               -> CA, moves misplaced ones, reads the stores back:
                               Get-PkiStorePlacement), Get-PkiTrustStoreOf,
                               Remove-CurrentTrust, Remove-AllTrust
 08_Cleanup.ps1                Remove-PkiOutput, folder safety                   00
 09_Administrator.ps1          Test-IsAdministrator, Assert-Administrator        nothing
 10_Main.ps1                   Invoke-PkiMain (orchestration of pki_setup.ps1)   all
 11_Preflight.ps1              -Check, -Verify, Assert-PkiGenerationCapabilities 00-06, 12
 12_ExistingPki.ps1            Import-PkiExisting [-SkipProviders]: load a PKI   00-03
                               from its manifest (-ReinstallTrust uses it)
 13_ExternalRoot.ps1           Enterprise Root signed by a public CA, cross-     00-04, 12
                               signing (see PUBLIC-CA-ENTERPRISE-ROOT.txt)
 14_LeafGenerator.ps1          THE leaf generator: New-PkiLeafSpec, New-Pki-     00-04, 06, 11-13
                               LeafCertificate, key floors, subject by level,
                               formats, validation, leaf index, OpenSSL readiness
                               (Assert-PkiLeafOpenSslReady)
 15_LeafGuidance.ps1           convert-formats.ps1 and tls-guidance.txt          14
 16_CertPack.ps1               .certpacked archives: AES-256 zip engine (.NET),   00
                               ZipCrypto, 7-Zip wrappers, archive type detection,
                               Find-PkiCompanionScript, Install-PkiSevenZip
 18_Revocation.ps1            CRL / OCSP responder / time stamping: Update-PkiCrl, Revoke-PkiCertificate,   00, 01, 03, 04, 14
                               New-PkiServiceCertificate, Invoke-PkiSignServiceCsr, Write-PkiRevocationInfo
 17_Transport.ps1              Phase C: scans (Windows 11 25H2+, OpenSSL 4.0.1+), 00, 02, 07, 09, 16
                               password policy, package plan / pack / open /
                               export, Windows trust install, chain proof, kit,
                               Install-PkiOpenSsl (via Install-DevEnvironment.*)


====================================================================================================
 3  PATTERNS FOR PHASE B AND PHASE C
====================================================================================================
 PHASE B - GenerateLeafCertificate.ps1 (DONE): issue a leaf from an existing intermediate. It is the model:

     param( ... its own parameters, no [CmdletBinding()] ... )
     $PkiModuleSet = 'Library'
     . (Join-Path $script:ScriptRoot 'scripts\PkiModules.ps1')

     Initialize-PkiConfiguration -ScriptRoot $script:ScriptRoot -Bound $PSBoundParameters     # cnf + defaults
     Test-PkiLeafNaming                                                                       # [ leaf_names ]
     Initialize-OpenSSL                                                                       # 4.x gate + advice
     [void](Assert-PkiLeafOpenSslReady -NeedFips $fips -NeedPqc $quantum)                     # FIPS + ML-DSA gate
     [void](Import-PkiExisting -SkipProviders)                                                # the PKI on disk
     $leafRoot = Get-PkiLeafRoot                                    # <script folder>\leafcerts
     $specs = New-PkiLeafSetSpecs -Base $base -Purposes $purposes   # one per purpose, validated before any write
     $res   = Invoke-PkiLeafSet -Specs $specs -LeafRoot $leafRoot   # folders, issue, validate, guidance; all or nothing
     # one certificate:  New-PkiLeafSpec / New-PkiUniqueFolder / New-PkiLeafCertificate / Test-PkiLeafResult

 PHASE C - transport / install script on another machine: only trust

     $PkiModuleSet = 'Trust'
     . (Join-Path $PSScriptRoot 'scripts\PkiModules.ps1')
     Initialize-PkiMinimalContext -PkiRoot $unpackedFolder -Password $pfxPassword
     $manifest = Get-Content (Join-Path $unpackedFolder 'pki-manifest.json') -Raw | ConvertFrom-Json
     Install-PkiTrust -Manifest $manifest          # roots -> Root, intermediates -> CA, leaves -> My
     Remove-AllTrust                               # or  Remove-CurrentTrust

 NOTE: the manifest stores the ABSOLUTE paths of the machine that generated the PKI. The Phase C script
 rewrites them to the folder it unpacked into before it calls Install-PkiTrust.
 Both patterns need no change in pki_setup.ps1. The manifest (pki-manifest.json) is the contract
 between the generator and the later scripts: certificateAuthorities[] (id, kind, store, sha1, files),
 leaves[], quadrants, mode, enterpriseRoot.


====================================================================================================
 4  SHARED STATE  ($script:Pki)
====================================================================================================
 Initialize-PkiConfiguration creates $script:Pki (an ordered dictionary) in the SCRIPT scope. Because the
 loader is dot-sourced, the caller and all modules share it. Important keys:
     Bound, Ini, PkiRoot, PublishDir, LeafDir, Quadrants, ClassicPki
     Catalog   list of CA definitions (Id, Kind, Parent, Family, Bits, Curve, PqcAlg, Fips, Years, PathLen,
               Validation, Gen, Slug, Actual = the key that really exists)
     Built     id -> manifest entry of each built CA          Leaves   list of built leaf certificates
     Naming    effective names (01b_CaNaming.ps1)             ExternalRoot   public-CA information or $null
     Password, OpenSslExe, OpenSslVersion, PqcFallbacks, CustomPolicies, IanaPen, ...
 Other script-scope values: $script:PkiPolicyOid (EV / OV / DV OIDs), $script:PkiRootRsaBits,
 $script:PkiRootCurve, $script:PkiRootPqc (the enforced root key policy), $script:PkiGeneratorVersion.
 A script that only needs trust uses Initialize-PkiMinimalContext (PkiRoot, Password, Built, Leaves).


====================================================================================================
 5  RULES FOR ADDING OR CHANGING A MODULE
====================================================================================================
 * Only define functions and script-scope constants. No code that runs at load time (the loader runs
   it in the caller's scope). Start with  Set-StrictMode -Version Latest  and  $ErrorActionPreference='Stop'.
 * Write a header: purpose, "Provides", "Requires". Keep the dependency direction: a module may use
   lower-numbered modules; call upward only through functions that exist at call time.
 * Functions return objects, they do not exit the script. Errors are thrown with a message that says
   what to do. User-facing text goes through Write-PkiLog.
 * Return a collection that may hold ONE item with a leading comma  (return ,$list)  so PowerShell does
   not unroll it. Wrap callers in @( ) when they need an array. (A one-pair subject list became the string "CN".)
 * PowerShell variables are case-INSENSITIVE: a parameter $R and a local $r are the same variable. Never reuse a
   parameter's name, in any case, for a local.
 * EVERY MAIN SCRIPT has the STANDARD BOOTSTRAP (Invoke-PkiBootstrapUnlock, same text in pki_setup.ps1 and
   GenerateLeafCertificate.ps1) at its top, before any module is loaded, and an -Unblock switch that calls
   Invoke-PkiUnblockUnlock. Copy it into the Phase C script.
 * Do not use [CmdletBinding()] in an entry script that has -EV or -OV: they are aliases of -ErrorVariable and
   -OutVariable.
 * 'openssl' arguments go through Invoke-OpenSSL (it sets OPENSSL_CONF, hides passwords, throws with the
   OpenSSL message). File arguments of  openssl verify  come LAST, after the provider options.
 * Run  -Check  and a full build with a real OpenSSL 4 after a change; -Verify must stay green.
 * Document every new parameter in pki_setup.ps1 -Help, the manual and the design file.


====================================================================================================
 6  WHERE TO CHANGE WHAT
====================================================================================================
 CA names, prefix, generation labels, file-name stems   agantra_pki.cnf [ ca_names ]  or  01b_CaNaming.ps1
 Validity, intermediate algorithms, subject, URLs, SAN  agantra_pki.cnf
 The shape of the PKI (which CAs exist, their keys)     01_Configuration.ps1  (New-PkiCatalog)
 Root key policy (RSA 8192 / P-521 / ML-DSA-87)         01_Configuration.ps1  (constants at the top)
 OpenSSL commands for CAs                               03_RuntimeConfig.ps1, 04_CertificateAuthority.ps1
 What counts as valid                                   06_Validation.ps1
 Windows store behaviour                                07_TrustStore.ps1
 Public-CA Enterprise Root, cross-signing               13_ExternalRoot.ps1
 Leaf certificates (any level, key, format)             14_LeafGenerator.ps1
 Leaf folder / file names / location                    agantra_pki.cnf [ leaf_names ]  or  01b_CaNaming.ps1
 Unblock / unlock                                       00_Common.ps1 (Unblock-PkiTree, Unlock-PkiTree)
 Conversion script and TLS guidance text                15_LeafGuidance.ps1
====================================================================================================
