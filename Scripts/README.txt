====================================================================================================
 scripts\  -  SHARED MODULES OF THE AGANTRA PKI SCRIPTS
====================================================================================================
 Version 4.5.2-phaseA      Author: Nicko Satria Utama, Agantra Inovatif OU (NextMantra)
 Used by : pki_setup.ps1 (now)    GenerateLeafCertificate.ps1 (Phase B)    transport / install script (Phase C)

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
   Trust    00_Common, 07_TrustStore, 09_Administrator   scripts that only install / remove trust in
                                                        the Windows stores (transport script, Phase C)

 Get-PkiModuleInfo lists the modules. Adding a module = one line in PkiModules.ps1.


====================================================================================================
 2  THE MODULES
====================================================================================================
 File                          Provides                                          Needs
 ----------------------------  ------------------------------------------------  --------------------
 00_Common.ps1                 Write-PkiLog, Invoke-PkiStep, telemetry, Ensure-  nothing
                               PkiDirectory, Write-Utf8NoBom, Assert-PkiFile,
                               PEM helpers (ConvertFrom-PkiPemToDer, Split-
                               PkiPemBundle, Get-PkiCertificateFingerprint),
                               Initialize-PkiMinimalContext, identity markers
 01_Configuration.ps1          Initialize-PkiConfiguration (command line > cnf   00
                               > default), Read-PkiIni, Get-PkiIniValue, the CA
                               CATALOG (New-PkiCatalog, Get-PkiCa), policy
                               helpers (Get-PkiExtraPolicies, Get-PkiLeafDays),
                               root key policy constants
 01b_CaNaming.ps1              NAMING of all CAs: templates, tokens, Get-        00, 01
                               PkiCaCommonName, Get-PkiCaSlug, Test-PkiNaming,
                               Show-PkiCaNames
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


====================================================================================================
 3  PATTERNS FOR PHASE B AND PHASE C
====================================================================================================
 PHASE B - GenerateLeafCertificate.ps1: issue a leaf from an existing intermediate

     [CmdletBinding()] param( ... its own parameters ... )
     $PkiModuleSet = 'Library'
     . (Join-Path $PSScriptRoot 'scripts\PkiModules.ps1')

     Initialize-PkiConfiguration -ScriptRoot $PSScriptRoot -Bound $PSBoundParameters   # cnf + defaults
     Initialize-OpenSSL                                                                # 4.x gate
     $manifest = Import-PkiExisting                       # catalog with the real keys, Built, Leaves
     $ca = Get-PkiCa -Id 'q1-ev'                          # DV / OV / EV intermediate of a quadrant
     # ... build the leaf configuration, issue with the CA's own configuration file:
     #     Get-PkiCaPaths -Ca $ca  (key, crt, cnf)     Get-PkiIssueMd, Get-PkiSigOpts, Get-PkiProviderArgs
     #     Get-PkiExtraPolicies -Level EV|OV|DV        Get-PkiLeafDays -Level EV|OV|DV
     #     Get-PkiTrustAnchor  (self-signed root or public chain)   Get-PkiExternalChainIntermediates

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
   not unroll it. Wrap callers in @( ) when they need an array.
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
====================================================================================================
