# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Generates the Agantra Inovatif Enterprise PKI: Classical and Quantum-safe
    tracks, FIPS and non-FIPS quadrants, DV / OV / EV intermediates, default
    EV leaf certificates, and the Windows trust installation.
.DESCRIPTION
    Requires PowerShell 7+ and OpenSSL 4.x (the script stops with an error on
    older OpenSSL). Only native OpenSSL providers are used; the ENGINE API and
    third-party providers (oqsprovider) are not.

    Run  .\pki_setup.ps1 -Help  for the complete parameter list.
.NOTES
    Phase A of the PKI redesign. GenerateLeafCertificate.ps1, pki_reuse.ps1 and
    the transport script are updated in later phases.
#>
[CmdletBinding()]
param(
    # ---- configuration ----
    [string]$ConfigFile,
    [string]$PkiRoot,
    [string]$OpenSslPath,
    [string]$FipsModuleConfig,

    # ---- hierarchy selection ----
    [ValidateSet(1, 2, 3, 4)][int[]]$Quadrant = @(1, 2, 3, 4),

    # ---- algorithms ----
    [ValidateSet(4096, 8192)][int]$IntermediateRsaBits = 4096,
    [ValidateSet('P-256', 'P-384', 'P-521')][string]$IntermediateCurve = 'P-384',
    [ValidatePattern('^(?i)ml-?dsa-?(44|65|87)$')][string]$PqcAlgorithm = 'mldsa87',
    [ValidatePattern('^(?i)ml-?dsa-?(44|65|87)$')][string]$PqcLeafAlgorithm = 'mldsa65',
    [switch]$PqcFallback,
    [ValidateSet(4096, 8192)][int]$FallbackRsaBits = 8192,
    [switch]$RsaPss,

    # ---- validity ----
    [ValidateRange(1, 1000)][int]$RootYears = 1000,
    [ValidateRange(1, 1000)][int]$TrackYears = 500,
    [ValidateRange(1, 1000)][int]$QuadrantYears = 400,
    [ValidateRange(1, 1000)][int]$IntYears = 250,
    [ValidateRange(1, 398)][int]$LeafDays = 397,
    [ValidateRange(1, 100)][int]$OvLeafYears = 3,
    [ValidateRange(1, 100)][int]$DvLeafYears = 5,

    # ---- policies ----
    [ValidatePattern('^[1-9]\d{0,9}$')][string]$IanaPen,
    [ValidatePattern('^[0-2](\.(0|[1-9]\d*))+$')][string]$EvPolicyOid,

    # ---- subject values: default comes from agantra_pki.cnf ----
    [string]$Domain,
    [string]$Organization,
    [string]$OrganizationalUnit,
    [string]$Country,
    [string]$State,
    [string]$Locality,
    [string]$Street,
    [string]$PostalCode,
    [string]$Serial,
    [string]$BusinessCategory,
    [string]$JurisdictionCountry,
    [string]$JurisdictionState,
    [string]$JurisdictionLocality,
    [string]$CpsUrl,
    [string]$ContactName,
    [string]$ContactEmail,
    [string]$ContactPhone,

    # ---- leaf / output ----
    [ValidateSet(2048, 3072, 4096, 8192)][int[]]$LeafSizes = @(2048),
    [string]$Password = 'Abc12345!',
    [switch]$LegacyPfx,
    [switch]$SkipLeaf,

    # ---- Windows trust (elevated PowerShell) ----
    [switch]$InstallTrust,
    [switch]$Clean,
    [switch]$RemoveTrust,
    [switch]$RemoveAllTrust,
    [switch]$Unblock,
    [switch]$Check,
    [switch]$Verify,
    [switch]$ShowNames,
    [switch]$ReinstallTrust,

    # ---- Classic PKI only ----
    [switch]$ClassicPKI,

    # ---- Enterprise Root signed by a public CA (see PUBLIC-CA-ENTERPRISE-ROOT.txt) ----
    [ValidateSet('DigiCert', 'GlobalSign', 'Sectigo', 'Other')][string]$ExternalCa,
    [switch]$EnterpriseRootCsr,
    [ValidateSet(4096, 8192)][int]$EnterpriseRootKeyBits = 8192,
    [string]$ImportEnterpriseRoot,
    [string]$ExternalChain,
    [switch]$CrossSignCsr,
    [string]$ImportCrossCert,

    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Show-PkiHelp {
    @'
============================================================
 pki_setup.ps1 - Agantra Inovatif Enterprise PKI generator
 Version 4.5.2-phaseA
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : pki_setup-MANUAL.txt   Design : PKI-Design-with-FIPS-and-PQC.txt
 Public CA : PUBLIC-CA-ENTERPRISE-ROOT.txt   Modules : scripts\README.txt

REQUIREMENTS
  PowerShell 7+ and OpenSSL 4.x ONLY. OpenSSL 3.x is refused. When several OpenSSL versions are installed
  the newest 4.x is used (PATH order does not matter: an older Git / package OpenSSL is skipped and
  reported). When no 4.x exists the output says how to install it: run your Install-DevEnvironment.ps1
  (FireDaemon OpenSSL with the FIPS module) and open a new PowerShell window. A machine-wide
  OPENSSL_CONF (for example a master configuration with oqsprovider) is ignored: every command of this
  script uses its own configuration. Before anything is generated the script proves that this OpenSSL can
  create ML-DSA keys (Quadrants 3 / 4) and load the FIPS provider (Quadrants 2 / 4); if not it stops.
  OpenSSL 4 has no ENGINE API; this PKI uses native providers only:
    non-FIPS : -provider default
    FIPS     : -provider fips -provider base     (needs fipsmodule.cnf, see -FipsModuleConfig)
  The script runs on Windows 10/11, Linux and macOS. Certificate-store installation
  (-InstallTrust and the Remove options) is Windows only; other systems: see the manual.

HIERARCHY CREATED  (.\pki)
  Enterprise Root CA                 RSA 8192  SHA-512   1000 years   pathlen 3
  |- Classic Track Root              RSA 8192  SHA-512    500 years   pathlen 2
  |   |- Q1 Root  Non-FIPS           RSA 8192  SHA-512    400 years   pathlen 1
  |   |    `- DV / OV / EV intermediates   RSA 4096 SHA-256    250 years   pathlen 0
  |   `- Q2 Root  FIPS               ECDSA P-521  SHA-512 400 years   pathlen 1
  |        `- DV / OV / EV intermediates   ECDSA P-384 SHA-384  250 years   pathlen 0
  `- Quantum Track Root              ML-DSA-87            500 years   pathlen 2
      |- Q3 Root  Non-FIPS           ML-DSA-87            400 years   pathlen 1
      |    `- DV / OV / EV intermediates   ML-DSA-87       250 years   pathlen 0
      `- Q4 Root  FIPS               ML-DSA-87            400 years   pathlen 1
           `- DV / OV / EV intermediates   ML-DSA-87       250 years   pathlen 0

  Quadrants:  Q1 Classic Non-FIPS | Q2 Classic FIPS | Q3 Quantum Non-FIPS | Q4 Quantum FIPS
  Default EV leaf: Q1 RSA 2048 | Q2 ECDSA P-256 | Q3, Q4 ML-DSA-65.
  Only the quadrants selected with -Quadrant are built; the Enterprise Root and the Track
  Roots they need are always built.

ROOT KEY POLICY  (enforced, not configurable)
  Every root-level CA (Enterprise Root, Track Roots, Quadrant Roots) is RSA 8192 with SHA-512.
  Where the algorithm is not RSA, the strongest key and the largest digest it offers are used:
      RSA      8192 bit           SHA-512   (8192 is also the largest size Chrome accepts)
      ECDSA    P-521              SHA-512   (largest NIST curve; Classic FIPS quadrant)
      ML-DSA   ML-DSA-87          none      (NIST level 5, the highest; a pure signature that hashes
                                             internally with SHAKE256; the whole Quantum track)
  The Enterprise Root is RSA because it anchors both tracks. The validator rejects a root-level CA
  that does not meet this, and checks that every certificate below an ML-DSA CA is ML-DSA signed.

QUANTUM TRACK  (post-quantum signatures, FIPS and non-FIPS)
  The Quantum track uses ML-DSA at EVERY level: Track Root, Q3 / Q4 roots, intermediates and leaves.
  If OpenSSL cannot create an ML-DSA key the script STOPS (a silent downgrade would defeat the
  purpose). -PqcFallback creates an RSA key instead (genrsa), with a warning per key, in the summary
  (marked *) and in pki-manifest.json; such a certificate is not quantum-safe.
  WHERE ML-DSA CERTIFICATES WORK (status of mid-2026; test on your builds):
    Certificate store, chain validation   Windows 11 24H2+ and Windows Server 2025 (updated), via
                                          CryptoAPI. -InstallTrust installs every Quantum root,
                                          intermediate and leaf there. NOT Windows 10 / Server 2022.
    TLS server certificate                OpenSSL 3.5+ servers and clients: nginx, Apache, Node.js,
                                          Python, curl, Kestrel on Linux. NOT Windows Schannel
                                          (Kestrel / IIS on Windows), NOT Java 25, NOT the browsers
                                          (Chrome, Edge, Brave, Firefox, UC, QQ) today.
  So: use the Quantum leaves for OpenSSL-based services and mutual TLS between your own systems.
  Sites that browsers or Windows servers must serve use the Classic leaves (Q1 / Q2); every browser
  and Windows 11 also negotiates the hybrid ML-KEM key exchange (X25519MLKEM768) with those.
  Windows 10 / Server 2022: quadrants 3, 4 are not built by default (-Quadrant 1,2,3,4 overrides).

VALIDITY  (from the moment of generation; each level shorter than the one above)
  Enterprise Root 1000 years > Track Roots 500 > Quadrant Roots 400 > Intermediates 250 > leaf
  Leaf (when no parameter is given):  EV 397 days | OV 3 years | DV 5 years
  Change with -RootYears -TrackYears -QuadrantYears -IntYears -LeafDays (EV) -OvLeafYears -DvLeafYears.
  pki_setup.ps1 issues EV leaves; the OV / DV defaults are used by the leaf generator (Phase B).
  The run prints every CA with its validity and expiry date when it finishes.

POLICIES  (EV policy is required)
  Every certificate carries the policy of its level so applications can tell what they hold:
  roots EV + OV + DV, an intermediate its own level, an EV leaf EV.
    EV  2.23.140.1.1   OV  2.23.140.1.2.2   DV  2.23.140.1.2.1   (CA/B Forum defaults)
  Change in agantra_pki.cnf [ policy_oids ] or with -EvPolicyOid. EV, OV and DV must differ.
  A blank value falls back to the default, so EV is always present.
  IANA Private Enterprise Number (PEN): blank until you have it. Set  IanaPen  in agantra_pki.cnf
  [ iana_pen ] or use -IanaPen <number>. Then these are added to the certificates:
    1.3.6.1.4.1.<PEN>.1      company policy (every certificate)
    1.3.6.1.4.1.<PEN>.1.1    company EV     (roots, EV intermediates, EV leaves)
    1.3.6.1.4.1.<PEN>.1.2    company OV     1.3.6.1.4.1.<PEN>.1.3   company DV
  More policies: agantra_pki.cnf [ custom_policies ].

COMMON NAMES
  Enterprise Root   Agantra Inovatif Enterprise Root CA G1
  Track Root        Agantra Inovatif Enterprise Classic Root CA G1
                    Agantra Inovatif Enterprise PQC-PostQuantum Root CA G2
  Quadrant Root     Agantra Inovatif Enterprise Classic Q1 Root CA G1        (Q2 likewise)
                    Agantra Inovatif Enterprise PQC-PostQuantum Q3 Root CA G2  (Q4 likewise)
  Intermediate      Agantra Inovatif <EV|OV|DV> <algorithm> <G1|G2> CA
                      e.g. Agantra Inovatif EV RSA-4096 G1 CA | ... OV ECDSA-P384 FIPS G1 CA |
                           ... DV ML-DSA-87 G2 CA | ... EV ML-DSA-87 FIPS G2 CA
  G1 = Classic track, G2 = everything in the Quantum track.
  Every CA certificate carries the CA/B Forum policy OIDs (EV 2.23.140.1.1, OV 2.23.140.1.2.2,
  DV 2.23.140.1.2.1; roots carry all three, an intermediate carries its own) plus every custom
  policy of agantra_pki.cnf.

USAGE
  .\pki_setup.ps1 -Check                      preflight: is this machine ready? (writes nothing)
  .\pki_setup.ps1 -ShowNames                  show the names of all CAs that would be created
  .\pki_setup.ps1 -ClassicPKI                 only Enterprise Root, Classic Track Root, Q1 Root, DV / OV / EV
  .\pki_setup.ps1                              all four quadrants
  .\pki_setup.ps1 -Quadrant 1,3                non-FIPS quadrants only (no FIPS module needed)
  .\pki_setup.ps1 -InstallTrust                generate, then install in Windows (admin)
  .\pki_setup.ps1 -ReinstallTrust             install the existing PKI in Windows again (admin, no rebuild)
  .\pki_setup.ps1 -Clean -InstallTrust         remove the old PKI first, then regenerate
  .\pki_setup.ps1 -FipsModuleConfig C:\openssl\ssl\fipsmodule.cnf
  .\pki_setup.ps1 -OpenSslPath 'C:\Program Files\OpenSSL\bin\openssl.exe'
  .\pki_setup.ps1 -Verify                     re-validate an existing PKI (and show Windows trust)
  .\pki_setup.ps1 -Unblock                     unblock all scripts and PKI files, list lock holders
  .\pki_setup.ps1 -RemoveTrust                 remove this PKI from Windows
  .\pki_setup.ps1 -RemoveAllTrust              remove every Agantra / NextMantra certificate
                                               AND delete the .\pki folder with all contents
  .\pki_setup.ps1 -Verbose                     show every OpenSSL command
  .\pki_setup.ps1 -Help

CLASSIC PKI  (-ClassicPKI)
  Builds only:  Enterprise Root -> Classic Track Root -> Q1 Root -> DV / OV / EV intermediates
  (RSA only, no FIPS module, no post-quantum) and the Q1 EV leaf. The widest compatibility and the
  smallest PKI; also the shape to use under a public CA. Cannot be combined with -Quadrant.

CA NAMES  (all roots and intermediates)
  The names are configurable. Defaults live in scripts\01b_CaNaming.ps1; override them in
  agantra_pki.cnf [ ca_names ] (templates, prefix, Quantum label, generation labels, file-name stem).
  Tokens: {Prefix} {QuantumLabel} {Gen} {N} {Level} {Algorithm} {Track} {Id}.
  A name may not exceed 64 characters and every CA needs a different one; the script stops with the
  reason. -ShowNames prints the templates and every resulting name without generating anything.

ENTERPRISE ROOT SIGNED BY A PUBLIC CA  (DigiCert, GlobalSign, Sectigo ...)  - full text:
PUBLIC-CA-ENTERPRISE-ROOT.txt
  Model A  The Enterprise Root becomes a subordinate CA of the public CA
    -EnterpriseRootCsr          create the Enterprise Root key and request (pki\root\root.csr), stop
    -ExternalCa <name>          DigiCert | GlobalSign | Sectigo | Other: names the CA in the request sheet
    -EnterpriseRootKeyBits <n>  4096 | 8192 (default 8192). 4096 only with these options: public CAs
                                rarely accept RSA 8192. Everything below keeps the normal key policy.
    -ImportEnterpriseRoot <f>   the signed certificate (PEM or DER); checked, then ALL CAs are built
                                under it. -ExternalChain <f>: the CA's chain (intermediates + root, PEM).
                                The choice -ClassicPKI made with the request is remembered.
  Model B  Cross-sign the existing self-signed Enterprise Root (nothing below it changes)
    -CrossSignCsr               request for the same key and subject (pki\root\cross-sign\)
    -ImportCrossCert <f>        the cross-certificate (+ -ExternalChain); writes <leaf>-fullchain-cross.crt
  Checks on import: CA:TRUE, pathlen >= 3, keyCertSign, the certificate is for YOUR key, not expired, EKU
  contains serverAuth + clientAuth when present, chain verifies; name constraints are reported.
  Every CA below is shortened to end before the public certificate; the Enterprise Root goes to
  LocalMachine\CA (it is no longer self-signed). Rehearse first with a stand-in CA (document, section 10).

CONFIGURATION FILE   (agantra_pki.cnf replaces ev_pki.cnf)
  -ConfigFile <path>   Default: agantra_pki.cnf next to this script.
                       Precedence: command line > file > built-in default.
                       Holds validity, intermediate algorithms, CA subject, CRL / OCSP /
                       CA Issuers URLs ({ca} = issuing CA), SAN set, leaf subject fields,
                       custom policies and the CA names ([ ca_names ]).
  -PkiRoot <path>      Output folder.                       Default: .\pki
  -OpenSslPath <path>  openssl.exe to use (must be 4.x).    Default: PATH, then common folders
  -FipsModuleConfig <path>
                       fipsmodule.cnf made by "openssl fipsinstall". Required when quadrant
                       2 or 4 is generated.                 Default: searched next to OpenSSL

SELECTION
  -ClassicPKI          Quadrant 1 only (see CLASSIC PKI).
  -Quadrant <1..4>     Quadrants to build.   Default: 1,2,3,4 (Windows 10: 1,2, see QUANTUM TRACK)

ALGORITHMS BELOW THE ROOTS
  -IntermediateRsaBits <n>  Q1 intermediate RSA size: 4096 | 8192.                Default: 4096
  -IntermediateCurve <c>    Q2 intermediate curve: P-256 | P-384 | P-521.         Default: P-384
  -PqcAlgorithm <a>         Q3 / Q4 intermediates: mldsa44 | mldsa65 | mldsa87.   Default: mldsa87
  -PqcLeafAlgorithm <a>     Q3 / Q4 leaves: mldsa44 | mldsa65 | mldsa87.           Default: mldsa65
  -PqcFallback              If an ML-DSA key cannot be created use RSA instead (genrsa) with a
                            warning, instead of stopping. NOT quantum-safe.
  -FallbackRsaBits <n>      RSA size used by -PqcFallback: 4096 | 8192.           Default: 8192
  -RsaPss                   Sign RSA CA certificates with RSASSA-PSS (MGF1 + the same digest).
                            Not every older chain engine accepts PSS: test first.
  Root-level keys are fixed (see ROOT KEY POLICY).

VALIDITY
  -RootYears <n>       Default 1000     -TrackYears <n>      Default 500
  -QuadrantYears <n>   Default 400      -IntYears <n>        Default 250
  -LeafDays <n>        EV leaf validity. Default 397 (maximum 398).
  -OvLeafYears <n>     OV leaf validity in years. Default 3.     -DvLeafYears <n>  DV. Default 5.

POLICY OPTIONS
  -IanaPen <number>    Your IANA Private Enterprise Number (optional, see POLICIES).
  -EvPolicyOid <oid>   EV policy OID.                        Default: 2.23.140.1.1

SUBJECT OPTIONS   (apply to the CA subjects and, where relevant, to the default leaves)
  -Domain <name>             Leaf CN and first DNS SAN (also adds www.<name>).
  -Organization <text>       O.                  Default: Agantra Inovatif OU
  -OrganizationalUnit <text> Leaf OU.
  -Country <cc>              C.                  Default: EE
  -State <text>              ST.                 Default: Tallinn
  -Locality <text>           L.                  Default: Tallinn
  -Street <text>             Street address.
  -PostalCode <text>         Postal code.        Default: 15199
  -Serial <text>             serialNumber.       CA default EEARIREG.17344131, leaf 17344131
  -BusinessCategory <text>   Private Organization | Government Entity | Business Entity |
                             Non-Commercial Entity
  -JurisdictionCountry <cc>  Default EE.   -JurisdictionState <text> Default Tallinn.
  -JurisdictionLocality <t>  Optional.
  -CpsUrl <url>              CPS URI in the first certificate policy.
  -ContactName / -ContactEmail / -ContactPhone   Contact fields.
                             Leaf defaults: BizDevSecOps Administrator, info@nextmantra.com,
                             (+372)53194019. CA defaults come from agantra_pki.cnf.

LEAF / OUTPUT OPTIONS
  One default EV leaf per quadrant: Q1 RSA 2048 | Q2 ECDSA P-256 | Q3, Q4 ML-DSA-65.
  -LeafSizes <int[]>   RSA sizes for the Q1 leaf: 2048 | 3072 | 4096 | 8192.     Default: 2048
                       RSA below 2048 is rejected.
  -Password <text>     PFX password (8+ characters).        Default: Abc12345!
  -LegacyPfx           Legacy PFX encryption (3DES / SHA-1) for very old software.
  -SkipLeaf            Build the CAs only.
  Leaf files in .\pki\leaf: <name>.crt .key -fullchain.crt .pfx (+ -fips.pfx for FIPS leaves:
                       FIPS-conformant container; Windows imports the normal .pfx)
  GenerateLeafCertificate.ps1 (Phase B) issues every other kind of leaf.

WINDOWS TRUST   (elevated PowerShell; other modes need no elevation)
  -InstallTrust        Every ROOT -> LocalMachine\Root  (Trusted Root Certification Authorities):
                         Enterprise Root, Classic / Quantum Track Roots, Q1..Q4 Quadrant Roots.
                       Every INTERMEDIATE -> LocalMachine\CA  (Intermediate Certification Authorities):
                         all DV / OV / EV CAs.
                       Default leaf PFX files -> LocalMachine\My (ONLY the leaf is imported; the chain
                       certificates inside the PFX are not, because Windows would file them under Intermediate).
                       Track and Quadrant Roots are issued by the Enterprise Root (not self-signed);
                       Windows treats a certificate in the Trusted Root store as a trust anchor either way.
                       A certificate an earlier version put in the wrong store is moved. Afterwards the
                       script READS THE STORES BACK and prints how many roots / intermediates are in place;
                       a certificate in the wrong store (or in both) is an ERROR and ends the run.
                       (An Enterprise Root signed by a public CA is an intermediate: it goes to CA.)
                       This includes every ML-DSA certificate on Windows 11 24H2+ and Windows
                       Server 2025. Each certificate is installed with .NET, then certutil.exe if
                       needed, and checked by thumbprint. A CA certificate that cannot be installed
                       stops the run with an error; a leaf PFX Windows cannot import is a warning.
  -ReinstallTrust      Install the PKI that ALREADY EXISTS in .\pki into the Windows stores again, without
                       regenerating anything and without OpenSSL: puts roots in Trusted Root, intermediates
                       in Intermediate, moves certificates found in the wrong store. Use it after an update
                       or when -Verify reports certificates in the wrong store.
  -Clean               Remove this PKI's trust and the .\pki folder first.
  -RemoveTrust         Remove only this PKI (by thumbprint) from Root, CA and My.
                       The files stay on disk.
  -RemoveAllTrust      Remove EVERY certificate whose subject or issuer contains
                       'Agantra Inovatif' or 'NextMantra' from Root, CA and My, then delete
                       the .\pki folder: all contents and the folder itself.
  Certificates that are already gone from the stores are ignored and the run continues.
  Linux, macOS, FreeBSD and the browsers' own stores: install pki\root\root.crt as described
  in pki_setup-MANUAL.txt.

UNBLOCK / UNLOCK
  -Unblock             Remove the Windows "downloaded from the Internet" mark from every file
                       below the script folder and the PKI folder, then list the processes
                       that hold files in .\pki open (Windows Restart Manager). Nothing is
                       killed: close the listed program (Explorer window, editor, shell).
  The script unblocks its own scripts at every start, and the PKI folder before and after
  generation. A script that is still blocked the very first time needs once:
      Get-ChildItem -Path . -Recurse -File | Unblock-File
  -Clean / -RemoveAllTrust leave the folder first when your shell is inside it, retry while
  antivirus or the indexer releases it, and name the holders if it stays locked.

CHECK / VERIFY  (read-only; nothing in the PKI folder or the stores is changed)
  -Check               Preflight. Tests PowerShell, OS, OpenSSL 4.x, the default provider, the FIPS
                       module (when quadrant 2 or 4 is selected), blocked files, rights, the output
                       folder, and runs a real mini CA with the exact OpenSSL options the generator
                       uses (RSA / ECDSA P-521 keys, SHA-512 root, ca, CRL, PFX, strict chain
                       verify). Ends with READY or NOT READY.
  -Verify              Re-validates the PKI in the output folder against pki-manifest.json (keys,
                       digests, pathlen, policies, chains, PFX). On Windows it also reports which CA
                       certificates are installed in the LocalMachine stores.

  -ShowNames           Print the CA naming templates and every resulting name, nothing is generated.

OTHER
  -Verbose             Show OpenSSL commands.        -Help   This help.

OUTPUT (.\pki)
  root\root.crt/.key/.pfx                         Enterprise Root CA (public CA: external-chain.pem,
                                                  external-request.txt, cross-sign\)
  classical\root\  quantum\root\                  Track Roots
  classical\q1\{root,dv,ov,ev}\ ... quantum\q4\{root,dv,ov,ev}\
        <id>.crt .key .pfx .cnf <id>-chain.crt, index.txt, serial, crlnumber, issued\
  leaf\                                           default EV leaf files
  publish\                                        root.crt, ca-bundle.crt, <slug>.crt/.crl/.pem,
                                                  README.txt
  provider-default.cnf, provider-fips.cnf         native provider configuration
  pki-manifest.json, telemetry.json               what was generated

LIMITATIONS  (details: PKI-Design-with-FIPS-and-PQC.txt, section 9)
  * Private PKI: install the Enterprise Root on every client. No browser shows the EV company
    line for a private root.
  * ML-DSA certificates are NOT accepted for HTTPS by Windows Schannel (Kestrel / IIS on Windows),
    Java 25 or the browsers today; they work in the Windows store and with OpenSSL 3.5+ stacks.
  * ML-DSA needs OpenSSL 3.5 or newer (4.x here); the FIPS quadrant also needs a FIPS module that
    contains ML-DSA.
  * ML-DSA signatures are large (about 3.3 KB for ML-DSA-65, 4.6 KB for ML-DSA-87): a full chain is
    tens of KB. Some proxies and servers limit header or handshake size.
  * Validity beyond 2038 can fail on 32-bit systems (old 32-bit Android, embedded devices).
  * RSA 8192 CA keys are slow to sign and verify; P-521 CA keys are validated by all listed
    platforms, but some TLS stacks restrict P-521 for TLS handshakes (leaves are P-256).
  * UC Browser and QQ Browser are not verified: they may use their own certificate store.
  * The CRL / OCSP / CA Issuers URLs help only when the files in .\pki\publish are served there.
  * Windows: -Verify asks the Windows chain engine itself whether it accepts every leaf chain. ML-DSA
    chains need Windows 11 24H2+ / Server 2025; the result on your machine is the proof.
  * OpenSSL 4.0 is a short-support release (about May 2027); the OpenSSL 3.5 LTS runs to 2030.
    Only this script needs 4.x; the servers that use the certificates can link 3.5 or newer.
  * A public CA signs only what it agrees to: it may refuse RSA 8192 / P-521, limit pathlen below 3, require
    an HSM, add name constraints and cap the validity (public TLS leaves: 398 days). Signing is not
    automated. Tested here with a stand-in CA, not with DigiCert, GlobalSign or Sectigo.
  * pki_reuse.ps1 and GenerateLeafCertificate.ps1 still target the old single-root layout until
    Phases B and C.
'@ | Write-Host
}

if ($Help) {
    Show-PkiHelp
    exit 0
}

Write-Host '============================================================'
Write-Host 'Author : Nicko Satria Utama'
Write-Host 'Company: Agantra Inovatif OÜ (NextMantra)'
Write-Host 'Email  : nicko@nextmantra.com'
Write-Host '============================================================'
Write-Host ''

try {
    if ($IsWindows) {
        Get-ChildItem -Path $script:ScriptRoot -Recurse -File -ErrorAction SilentlyContinue |
            Unblock-File -ErrorAction SilentlyContinue
    }
}
catch { Write-Host "[WARN] Automatic script unblocking failed: $($_.Exception.Message)" -ForegroundColor Yellow }

try {
    # All modules come from ONE loader (scripts\PkiModules.ps1); later scripts load them the same way.
    $PkiModuleSet = 'All'
    . (Join-Path $script:ScriptRoot 'scripts/PkiModules.ps1')

    Initialize-PkiConfiguration -ScriptRoot $script:ScriptRoot -Bound $PSBoundParameters -VerboseOutput:($VerbosePreference -eq 'Continue')
    Invoke-PkiMain
    exit 0
}
catch {
    $failure = $_
    if (Get-Command Write-PkiFatalError -ErrorAction SilentlyContinue) {
        try { Write-PkiFatalError -ErrorRecord $failure }
        catch { Write-Host "[FATAL] $($failure.Exception.Message)" -ForegroundColor Red }
    }
    else { Write-Host "[ERROR] $($failure.Exception.Message)" -ForegroundColor Red }
    exit 1
}
finally {
    if (Get-Command Clear-PkiSecretEnvironment -ErrorAction SilentlyContinue) { Clear-PkiSecretEnvironment }
}
