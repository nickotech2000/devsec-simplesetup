====================================================================================================
 scripts\  -  SHARED MODULES OF THE AGANTRA PKI SCRIPTS
====================================================================================================
 Version 7.6.7      Author: Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com
 Used by : pki_setup.ps1   GenerateLeafCertificate.ps1   PkiTransport.ps1   Unpack-PkiTransport.ps1

 This folder is a small library. Nothing in it runs by itself: every file only DEFINES functions.
 The scripts in the project folder load it and call the functions.

 CONTENTS
   1  How a script loads the modules          4  Shared state ($script:Pki)
   2  The modules (what each provides)        5  Rules for adding or changing a module
   3  Patterns for Phase B and Phase C        6  Where to change what


====================================================================================================

 READ THIS FIRST
----------------------------------------------------------------------------------------------------
 What it is   : Describes every module of the scripts folder.
 Who reads it : People who change or extend the scripts.
 You need     : None.
 Start with   : Use it as a reference.
 Words        : GLOSSARY.txt (technical terms), GLOSSARY-ENGLISH.txt (everyday English words)
----------------------------------------------------------------------------------------------------
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
                                                        the Windows stores (transport script, Phase
                                                        C)

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
 01c_Releases.ps1              RELEASES and the NoCR variant: Get-PkiContainer,       00
                               Get-PkiFolderName, Get-PkiFolderInfo,
                               Get-PkiInstalledPkis, Resolve-PkiRootChoice
                               (Use | Exact | Strict | Generate). Every PKI is in
                               pki\pki-<name>-<NN> or pki\pki-<name>-nocr-<NN>.
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
                               New-PkiServiceCertificate, Invoke-PkiSignServiceCsr,
                               Write-PkiRevocationInfo
 19_ExternalCaSigning.ps1    Sign the CSR of an external private CA (openssl ca, name constraints, chain folder)    00, 01, 02, 03, 04
 20_PersonLeaf.ps1             Person certificates: records (JSON, isGenerate), any ID, DNS from e-mail, DN, key usage, qcStatements   00, 01, 14
 17_Transport.ps1              Phase C: scans (Windows 11 24H2+, OpenSSL 4.0.1+), 00, 02, 07, 09, 16
                               password policy, package plan / pack / open /
                               export, Windows trust install, chain proof, kit,
                               Install-PkiOpenSsl (via Install-DevEnvironment.*)
 22_CsrSigning.ps1         Read and check a CSR against the PKI spec (colour report), sign it with a DV/OV/EV intermediate (SignCsr.ps1)   00, 01, 02, 03, 04, 19
 24_CodeSigning.ps1            Code signing certificates per platform (GenerateCodeSigningCertificate.ps1): issuer, spec, external CA, notes, index   00, 01, 02, 03, 04, 06, 14
 21_DevKit.ps1                 The DevKit (PkiTransport.ps1 -DevKit): devkit.env from the live configuration, the kit folder, the zip / 7z    00, 01, 03, 14, 16, 17, 20
                               (Write-PkiDevKitEnv, Copy-PkiDevKitTree, New-PkiDevKitArchive,
                               New-PkiDevKit). The kit's own files are in devkit\ of the project.


====================================================================================================
 3  PATTERNS FOR PHASE B AND PHASE C
====================================================================================================
 PHASE B - GenerateLeafCertificate.ps1 (DONE): issue a leaf from an existing intermediate. It is the
 model:

     param( ... its own parameters, no [CmdletBinding()] ... )
     $PkiModuleSet = 'Library'
     . (Join-Path $script:ScriptRoot 'scripts\PkiModules.ps1')

     Initialize-PkiConfiguration -ScriptRoot $script:ScriptRoot -Bound $PSBoundParameters     # cnf + defaults
     Test-PkiLeafNaming                                                                       # [ leaf_names ]
     Initialize-OpenSSL                                                                       # 4.x gate + advice
     [void](Assert-PkiLeafOpenSslReady -NeedFips $fips -NeedPqc $quantum)                     # FIPS + ML-DSA gate
     [void](Import-PkiExisting -SkipProviders)                                                # the PKI on disk
     $leafRoot = Get-PkiLeafRoot                                    # <script folder>\leafcerts
     $specs = New-PkiLeafSetSpecs -Base $base -Purposes $purposes   # one per purpose, validated
                                                                    before any write
     $res   = Invoke-PkiLeafSet -Specs $specs -LeafRoot $leafRoot   # folders, issue, validate,
                                                                    guidance; all or nothing
     # one certificate:  New-PkiLeafSpec / New-PkiUniqueFolder / New-PkiLeafCertificate / Test-PkiLeafResult

 PHASE C - transport / install script on another machine: only trust

     $PkiModuleSet = 'Trust'
     . (Join-Path $PSScriptRoot 'scripts\PkiModules.ps1')
     Initialize-PkiMinimalContext -PkiRoot $unpackedFolder -Password $pfxPassword
     $manifest = Get-Content (Join-Path $unpackedFolder 'pki-manifest.json') -Raw | ConvertFrom-Json
     Install-PkiTrust -Manifest $manifest          # roots -> Root, intermediates -> CA, leaves ->
                                                   My
     Remove-AllTrust                               # or  Remove-CurrentTrust

 NOTE: the manifest stores the ABSOLUTE paths of the machine that generated the PKI. The Phase C
       script
 rewrites them to the folder it unpacked into before it calls Install-PkiTrust.
 Both patterns need no change in pki_setup.ps1. The manifest (pki-manifest.json) is the contract
 between the generator and the later scripts: certificateAuthorities[] (id, kind, store, sha1,
 files), leaves[], quadrants, mode, enterpriseRoot.


====================================================================================================
 4  SHARED STATE  ($script:Pki)
====================================================================================================
 Initialize-PkiConfiguration creates $script:Pki (an ordered dictionary) in the SCRIPT scope.
 Because the loader is dot-sourced, the caller and all modules share it. Important keys:
     Bound, Ini, PkiRoot, PublishDir, LeafDir, Quadrants, ClassicPki
     Catalog   list of CA definitions (Id, Kind, Parent, Family, Bits, Curve, PqcAlg, Fips, Years,
               PathLen, Validation, Gen, Slug, Actual = the key that really exists)
     Built     id -> manifest entry of each built CA          Leaves   list of built leaf certificates
     Naming    effective names (01b_CaNaming.ps1)             ExternalRoot   public-CA information or $null
     Password, OpenSslExe, OpenSslVersion, PqcFallbacks, CustomPolicies, IanaPen, ...
 Other script-scope values: $script:PkiPolicyOid (EV / OV / DV OIDs), $script:PkiRootRsaBits,
 $script:PkiRootCurve, $script:PkiRootPqc (the enforced root key policy),
 $script:PkiGeneratorVersion. A script that only needs trust uses Initialize-PkiMinimalContext
 (PkiRoot, Password, Built, Leaves).


====================================================================================================
 5  RULES FOR ADDING OR CHANGING A MODULE
====================================================================================================
 * Only define functions and script-scope constants. No code that runs at load time (the loader runs
   it in the caller's scope). Start with  Set-StrictMode -Version Latest  and  $ErrorActionPreference='Stop'.
 * Write a header: purpose, "Provides", "Requires". Keep the dependency direction: a module may use
   lower-numbered modules; call upward only through functions that exist at call time.
 * Functions return objects, they do not exit the script. Errors are thrown with a message that says
   what to do. User-facing text goes through Write-PkiLog.
 * Return a collection that may hold ONE item with a leading comma  (return ,$list)  so PowerShell
   does not unroll it. Wrap callers in @( ) when they need an array. (A one-pair subject list became
   the string "CN".)
 * PowerShell variables are case-INSENSITIVE: a parameter $R and a local $r are the same variable.
   Never reuse a parameter's name, in any case, for a local.
 * EVERY MAIN SCRIPT has the STANDARD BOOTSTRAP (Invoke-PkiBootstrapUnlock, same text in
   pki_setup.ps1 and GenerateLeafCertificate.ps1) at its top, before any module is loaded, and an
   -Unblock switch that calls Invoke-PkiUnblockUnlock. Copy it into the Phase C script.
 * Do not use [CmdletBinding()] in an entry script that has -EV or -OV: they are aliases of
   -ErrorVariable and -OutVariable.
 * 'openssl' arguments go through Invoke-OpenSSL (it sets OPENSSL_CONF, hides passwords, throws with
   the OpenSSL message). File arguments of  openssl verify  come LAST, after the provider options.
 * Run  -Check  and a full build with a real OpenSSL 4 after a change; -Verify must stay green.
 * Every script starts with the marked PKI-VERSION-INFO block (tools\version-block.ps1 / .sh).
   Change the block there, then run tools\Update-VersionBlock.ps1 / tools\update_version_block.py.
   Never edit one copy by hand.
 * Document every new parameter in pki_setup.ps1 -Help, the manual and the design file.


====================================================================================================
 6  WHERE TO CHANGE WHAT
====================================================================================================
 CA names, prefix, generation labels, file-name stems   agantra_pki.cnf [ ca_names ]  or  01b_CaNaming.ps1
NoCR / release words, PQC short label                  agantra_pki.cnf [ ca_names ] NoCrLabel, ReleaseLabel, QuantumLabelShort
 Validity, intermediate algorithms, subject, URLs, SAN  agantra_pki.cnf
 The shape of the PKI (which CAs exist, their keys)     01_Configuration.ps1  (New-PkiCatalog)
 Root key policy (RSA 8192 / P-521 / ML-DSA-87)         01_Configuration.ps1  (constants at the top)
 Quadrant root key (Q1 RSA 4096, Q2 P-384, SHA-384)     agantra_pki.cnf [ pki_settings ] QuadrantRsaBits / QuadrantCurve
 Sign a colleague's CSR (leaf), CSR spec / error codes  SignCsr.ps1 + 22_CsrSigning.ps1 (twin: devkit/SignCsr.sh + lib/pki-csr.py)
 Sign a department CA's CSR (Classic Quadrant Root)     SignExternalCa.ps1 + 19_ExternalCaSigning.ps1
 Office / 365 document signing certificates           GenerateOffice365LeafCertificate.ps1 (shares 20_PersonLeaf.ps1), agantra_pki.cnf [ office365 ]
 Person (ID-card style) e-mail certificates             GeneratePersonLeafCertificate.ps1 + 20_PersonLeaf.ps1, agantra_pki.cnf [ person ]
 OpenSSL commands for CAs                               03_RuntimeConfig.ps1, 04_CertificateAuthority.ps1
 What counts as valid                                   06_Validation.ps1
 Windows store behaviour                                07_TrustStore.ps1
 Public-CA Enterprise Root, cross-signing               13_ExternalRoot.ps1
 Leaf certificates (any level, key, format)             14_LeafGenerator.ps1
 Leaf folder / file names / location                    agantra_pki.cnf [ leaf_names ]  or  01b_CaNaming.ps1
 Unblock / unlock                                       00_Common.ps1 (Unblock-PkiTree, Unlock-PkiTree)
 Conversion script and TLS guidance text                15_LeafGuidance.ps1
====================================================================================================

5.0.0 modules: 00a_Platform.ps1 (Get-PkiPlatformInfo, Assert-PkiPlatform: where the scripts run),
00b_Profiles.ps1 (profiles, Get-PkiToolSetting, pki_tools.cnf, Get-PkiFileStem,
Get-PkiTransportFolder). Both are in every module set. 01c_Releases.ps1: profile-aware folders,
Show-PkiList. 07_TrustStore.ps1: Remove-PkiProfileTrust, Remove-AllTrust (all companies).

5.2.2 scripts\22_CsrSigning.ps1: Get-PkiCsrAutoLevel (the level follows the request), the
development-SAN marker, PEN policies, serialNumber in OV; trustkit\ also holds New-PkiCsr.ps1 /
new-pki-csr.sh and Prepare-Computer.ps1 / prepare-computer.sh (standalone, copied into the trust-kit
zips, the DevKit and the transport kit).

5.1.0 trustkit\: Install-PkiCa.ps1 / install-pki-ca.sh (install every PKI of the .certpacked, write
the list of what was installed), Remove-PkiCa.ps1 / remove-pki-ca.sh (NEW: remove by company, all,
or organization), selfextract.sh template. New-PkiTrustKit.ps1 builds the single multi-PKI .certpacked
itself (no PkiTransport.ps1 -Pack call any more).

5.3.6 scripts\backup\: the SOURCE of Backup-Pki.ps1, Restore-Pki.ps1 and Test-PkiBackup.ps1 (*.src.ps1), PkiBackupCommon.ps1 (gate, password policy, hashes, requirement check, certificate / key inventory, Local Machine store) and Build-BackupScripts.ps1. The builder pastes PkiBackupCommon.ps1 and the zip engine of 16_CertPack.ps1 into each source and writes the three finished, STANDALONE scripts to the project root (they need no other .ps1). Edit the sources, run  pwsh -File .\scripts\backup\Build-BackupScripts.ps1 , never edit the three root scripts by hand. Not in the module catalog (PkiModules.ps1). See PkiBackup-MANUAL.txt

====================================================================================================
 NEW IN 7.5.2
====================================================================================================
 Module 24_CodeSigning.ps1 (sets All and Library, loaded before 17_Transport) is the code behind
 GenerateCodeSigningCertificate.ps1: the platform table (Windows, Java, Android, Apple, Apple
 installer), Get-PkiCodeSignSettings ([ codesign ] of the cnf), Resolve-PkiCodeSignIssuer (a CA of
 the catalog, or one from PEM files / PFX / the Windows store), New-PkiCodeSignSpec (on top of
 New-PkiLeafSpec), New-PkiCodeSignExternalCertificate, Write-PkiCodeSignNotes and the index
 (Add-PkiCodeSignIndex / Get-PkiCodeSignIndex: leafcerts\codesign\codesign-index.json and .tsv).
 14_LeafGenerator.ps1: $script:PkiLeafHashes (SHA-2 and SHA-3) and RSA 6144 / 7680 / 8192.
 06_Validation.ps1: Assert-PkiSignatureDigest accepts SHA-3. Sign-Code stays standalone.

====================================================================================================
 NEW IN 6.3.6
====================================================================================================
 Module 23_CaExport.ps1 is the code behind Export-PkiCa.ps1.
 Create-WebServerConfig and Sign-Code (.ps1 and .sh) are standalone tools: they use no module.
 Build-HtmlDocs.ps1 makes the html\ folder from the text documents.
