# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Issues leaf certificates (DV, OV or EV) from the Agantra Inovatif Enterprise PKI that pki_setup.ps1
    built: Classic or Quantum (ML-DSA), FIPS or non-FIPS. By default ONE RUN makes a certificate for EVERY
    purpose (ServerAuth, ClientAuth, CodeSigning, EmailProtection, TimeStamping, OcspSigning), each in EVERY
    format (PEM, DER, CER, CERT, P7B, RFC 7468, PFX).

.DESCRIPTION
    Uses the shared modules of the scripts folder (scripts\PkiModules.ps1, set 'Library'), the same leaf
    generator as pki_setup.ps1 and the same naming configuration (agantra_pki.cnf [ leaf_names ]).
    The leaf folders are written to  <script folder>\leafcerts  (NOT inside pki). If a folder exists a NEW
    folder with the date and time is created, nothing is overwritten.
    Before anything is made, the script checks that OpenSSL is 4.x WITH the FIPS module and ML-DSA; if
    not it says so and suggests running Install-DevEnvironment.ps1.
    At every start the script UNBLOCKS and UNLOCKS its folder, children and recursive.

    Full help:  .\GenerateLeafCertificate.ps1 -Help      Manual: GenerateLeafCertificate-MANUAL.txt

.EXAMPLE
    .\GenerateLeafCertificate.ps1 -DnsName www.example.com
        EV, Classic (Q1), RSA 2048: six certificates (one per purpose), every format, one go.
.EXAMPLE
    .\GenerateLeafCertificate.ps1 -OV -Quantum -FIPS -DnsName mtls.example.com -ExcludePurpose TimeStamping,OcspSigning
.EXAMPLE
    .\GenerateLeafCertificate.ps1 -DV -DnsName a.example.com -Purpose ServerAuth,ClientAuth -Format PFX
        ONE certificate with exactly these purposes, only the PFX.
#>
# No [CmdletBinding()]: it would reserve -EV and -OV (aliases of -ErrorVariable / -OutVariable), the names of the
# levels. -Verbose is declared below instead.
param(
    # ---- level and quadrant (default: -EV, -Classic, non-FIPS) ----
    [switch]$DV,
    [switch]$OV,
    [switch]$EV,
    [switch]$Classic,
    [switch]$Quantum,
    [switch]$FIPS,

    # ---- purposes: none given = ONE CERTIFICATE PER PURPOSE (the set) ----
    [switch]$AllPurposes,
    [ValidateSet('ServerAuth', 'ClientAuth', 'ServerClientAuth', 'CodeSigning', 'EmailProtection', 'TimeStamping', 'OcspSigning')][string[]]$Purpose,
    [ValidateSet('ServerAuth', 'ClientAuth', 'ServerClientAuth', 'CodeSigning', 'EmailProtection', 'TimeStamping', 'OcspSigning')][string[]]$ExcludePurpose,

    # ---- names ----
    [string[]]$DnsName,
    [string[]]$IpAddress,
    [string[]]$EmailAddress,
    [string]$CommonName,
    [switch]$AddDevelopmentSAN,
    [Alias('CodesignCompany')][string]$CodeSigningCompany,

    # ---- key and signature ----
    [ValidateSet('RSA', 'ECDSA', 'MLDSA')][string]$KeyType,
    [int]$KeyBits,
    [ValidateSet('P-256', 'P-384', 'P-521')][string]$Curve,
    [ValidatePattern('^(?i)ml-?dsa-?(44|65|87)$')][string]$PqcAlgorithm,
    [string]$Hash,

    # ---- validity and policies ----
    [ValidateRange(1, 36500)][int]$Days,
    # ---- time stamping: Classic non-FIPS (Quadrant 1) by default; the parameters prepare another one ----
    [ValidateSet(1, 2, 3, 4)][int]$TimestampQuadrant,
    [string]$TimestampPolicyOid,
    [ValidateRange(1, 36500)][int]$TimestampDays,
    [ValidateRange(1, 3650)][int]$OcspDays,
    [string[]]$Policy,
    [string]$CpsUrl,
    [string]$CpsUrlEv,

    # ---- subject values: default comes from agantra_pki.cnf ----
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
    [string]$Duns,
    [string]$ContactName,
    [string]$ContactEmail,
    [string]$ContactPhone,

    # ---- output ----
    [ValidateSet('PEM', 'DER', 'CER', 'CERT', 'P7B', 'RFC7468', 'PFX', 'ALL')][string[]]$Format = @('ALL'),
    [string]$OutputRoot,
    [string]$Password = 'Abc12345!',
    [switch]$LegacyPfx,
    [switch]$NoGuidance,
    [switch]$InstallPfx,

    # ---- information, unblock / unlock ----
    [switch]$List,
    [switch]$Check,
    [switch]$Unblock,
    [switch]$Help,
    [switch]$Verbose,

    # ---- environment ----
    [string]$ConfigFile,
    [string]$PkiRoot,
    [string]$OpenSslPath,
    [string]$FipsModuleConfig
)

$ErrorActionPreference = 'Stop'
$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Show-PkiLeafHelp {
    @'
============================================================
 GenerateLeafCertificate.ps1 - leaf certificates of the Agantra Inovatif Enterprise PKI
 Version 4.9.4-phaseC
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : GenerateLeafCertificate-MANUAL.txt   Design : PKI-Design-with-FIPS-and-PQC.txt (section 15)
 Needs  : PowerShell 7+, OpenSSL 4.x with the FIPS module and ML-DSA, and a PKI made by pki_setup.ps1.

WHAT IT DOES
  ONE RUN makes a certificate for EVERY purpose, each in EVERY format, validates all of them, and writes them to
      <script folder>\leafcerts\<name>\<purpose>\      (NOT inside the pki folder)
  The "set" is SEVEN certificates, because TLS comes in THREE variants:
      ServerAuth        TLS server only                 CodeSigning      code signing (Authenticode and others)
      ClientAuth        TLS client only (mutual TLS)    TimeStamping     RFC 3161 time stamping (critical, alone)
      ServerClientAuth  TLS server AND client in ONE    OcspSigning      OCSP responder (with the no-check extension)
      EmailProtection   S/MIME (EKU emailProtection + clientAuth, so the same certificate also logs in to mutual TLS / VPN / 802.1X)
  Every certificate has its own purpose, its own key and its own folder. The three TLS certificates carry the same
  names but are three separate certificates: one for servers (serverAuth), one for clients (clientAuth) and one that
  is both (serverAuth + clientAuth, for a service that is server and client, for example mutual TLS between services).
  Mixing other purposes in one certificate is possible (see -Purpose) but not the default: code signing and TLS
  should not share a certificate.
  If the set folder exists, a NEW folder <name>_<yyyyMMdd>-<HHmmss> is created. Nothing is overwritten.
  The same generator makes the default EV leaves of pki_setup.ps1.

BEFORE IT STARTS
  1. UNBLOCK + UNLOCK: the script folder (scripts, certificates, keys, leafcerts), children and recursive, loses the
     Windows "downloaded from the Internet" mark and the Read-only attribute. Every run. -Unblock does it on its own.
  2. OpenSSL: must be 4.x and have the FIPS provider (fipsmodule.cnf) and native ML-DSA. What THIS run needs and is
     missing stops the script; what it does not need is a warning. Both suggest the fix: run
     Install-DevEnvironment.ps1 (OpenSSL with FIPS and quantum support).   .\GenerateLeafCertificate.ps1 -Check

USAGE
  .\GenerateLeafCertificate.ps1 -DnsName www.example.com                      EV, Classic: the whole set, all formats
  .\GenerateLeafCertificate.ps1 -DV -DnsName a.example.com,b.example.com
  .\GenerateLeafCertificate.ps1 -OV -Classic -FIPS -DnsName api.example.com -KeyType ECDSA -Curve P-384
  .\GenerateLeafCertificate.ps1 -EV -Quantum -DnsName mtls.example.com        ML-DSA leaves (OpenSSL services, mTLS)
  .\GenerateLeafCertificate.ps1 -OV -DnsName shop.example.com -ExcludePurpose TimeStamping,OcspSigning
  .\GenerateLeafCertificate.ps1 -OV -DnsName shop.example.com -Purpose ServerAuth,ClientAuth -Format PFX   (3 certs)
  .\GenerateLeafCertificate.ps1 -OV -DnsName shop.example.com -Purpose ServerClientAuth   (1 cert)
  .\GenerateLeafCertificate.ps1 -EV -AddDevelopmentSAN         the set + development SAN
  .\GenerateLeafCertificate.ps1 -EV -DnsName api.nextmantra.com -AddDevelopmentSAN -Purpose ServerAuth,ClientAuth
  .\GenerateLeafCertificate.ps1 -OV -Purpose CodeSigning -CodeSigningCompany "Example Ltd"   CN = O = Example Ltd
  .\GenerateLeafCertificate.ps1 -List                                         leaf certificates made so far
  .\GenerateLeafCertificate.ps1 -Unblock                                      unblock + unlock the folders, then stop

LEVEL AND QUADRANT   (defaults: -EV, -Classic, no -FIPS)
  -DV | -OV | -EV      Domain / Organization / Extended validation. Chooses the intermediate q<N>-dv|ov|ev.
  -Classic | -Quantum  Classic: RSA or ECDSA leaf.  Quantum: ML-DSA leaf.
  -FIPS                FIPS quadrant (FIPS provider).  Quadrant NUMBERS (parameters, ids, folders): -Classic = 1,
                       -Classic -FIPS = 2, -Quantum = 3, -Quantum -FIPS = 4.  In NAMES the number is Q1 = non-FIPS,
                       Q2 = FIPS in BOTH tracks (Classic Q1 / Q2, Quantum Q1 / Q2), also in the file names of the
                       leaves; see .\pki_setup.ps1 -ShowNames.
  Browser-facing sites and Windows servers: Classic (quadrants 1 / 2). Quantum: OpenSSL-based services and mutual TLS.
  A quadrant the PKI does not have (built with -ClassicPKI or -Quadrant) is refused with the fix.

PURPOSES
  (none) | -AllPurposes   One certificate for EACH purpose (the set above). -AllPurposes only says it out loud.
  -ExcludePurpose <list>  Leave purposes out of the set: ServerAuth ClientAuth ServerClientAuth CodeSigning
                          EmailProtection TimeStamping OcspSigning. (-ExcludePurpose ServerClientAuth drops the
                          combined certificate and keeps the two separate ones.)
  -Purpose <list>         NOT a set (with two exceptions below): ONE certificate that carries exactly these
                          purposes, for example ServerAuth,EmailProtection. TimeStamping and OcspSigning must stand
                          alone. Cannot be combined with -AllPurposes / -ExcludePurpose.
                          ServerAuth,ClientAuth (nothing else)  -> THREE certificates: server only, client only and
                                                                   server + client (the TLS part of the set).
                          ServerClientAuth                      -> ONE certificate with serverAuth + clientAuth.
  Names per purpose in a set:
      ServerAuth, ClientAuth, ServerClientAuth   the DNS names / IPs you give (first = primary, wildcard *.example.com
                               allowed), or the [ leaf_san ] list of agantra_pki.cnf when none is given.
      EmailProtection          -EmailAddress, else the contact e-mail (ContactEmail). The CN is the e-mail address. EVERY e-mail
                               certificate carries the extended key usages emailProtection AND clientAuth.
      CodeSigning              no SAN; its own short subject (see CODE SIGNING SUBJECT).
      TimeStamping, OcspSigning   no SAN; CN = "<company or -CommonName> Time Stamping | OCSP Responder".

TIME STAMPING CERTIFICATE (RFC 3161)
  No special certificate type is needed: the TimeStamping leaf of this script IS the time stamp server certificate (EKU timeStamping,
  critical, the only purpose). Defaults: Quadrant 1 = Classic, non-FIPS (never quantum unless you ask), RSA, valid 1825 days,
  certificate policy OID <your PEN arc>.1.4 (1.3.6.1.4.1.67096.1.4) added next to the CA's DV/OV/EV policy.
  -TimestampQuadrant 1|2|3|4   1 Classic non-FIPS (default)  2 Classic FIPS  3 Quantum non-FIPS  4 Quantum FIPS (prepared for the future;
                               the PKI server kit signs RSA / ECDSA only)
  -TimestampPolicyOid <oid>    the TSA policy OID (also written to tsa.cnf default_policy by the server kit)
  -TimestampDays <n>           validity of the time stamp certificate     -OcspDays <n>   validity of OCSP responder certificates
  Config: [ timestamp ] Quadrant / PolicyOid / Days in agantra_pki.cnf.  Keys of the OCSP / TSA certificates can also be made on the
  server (pki-server.sh csr) and signed with PkiRevocation.ps1 -Action SignCsr.

NAMES
  -DnsName <a,b>   -IpAddress <a,b>   -EmailAddress <a,b>   -CommonName <text>
  Given on the command line = exactly these names. -CommonName replaces the CN of the TLS certificates and is the
  base of the CN of Time Stamping and OCSP signing (code signing: see CODE SIGNING SUBJECT).

DEVELOPMENT SAN   (-AddDevelopmentSAN)
  E-MAIL (S/MIME) with -AddDevelopmentSAN (4.9.4): the certificate gets the algorithm of GeneratePersonLeafCertificate.ps1 by default: ECDSA P-384, SHA-512
                       (Quadrants 1 and 2; -KeyType / -Curve / -Hash win), key usage digitalSignature + nonRepudiation + keyAgreement. The policies are the same as
                       those of every OV / EV certificate (level OID, company PEN OIDs, High Assurance for OV; CPS URL by level), see -CpsUrl.
  Adds the development list to the SAN. It is MERGED with the names you give (yours stay first, the CN is your first
  name; duplicates are removed). With no -DnsName the names of [ leaf_san ] come first. The list:
      DNS    nextmantra.com  www.nextmantra.com  *.nextmantra.com  localhost  local.dev
             nextmantra.internal  *.nextmantra.internal  nextmantra.developer  *.nextmantra.developer
             nextmantra.api  *.nextmantra.api  nextmantra.ldap  *.nextmantra.ldap
             agantra.internal  *.agantra.internal  agantra.developer  *.agantra.developer
             agantra.api  *.agantra.api  agantra.ldap  *.agantra.ldap                                 (21 names)
      IP     127.0.0.1  ::1  10.10.2.2  192.168.0.1 - 192.168.0.200  172.16.0.1 - 172.16.0.200  (403 in all,
             every address of both ranges is written)
      E-MAIL nicko@nextmantra.com  robby@nextmantra.com  info@nextmantra.com  airlangga@nextmantra.com
  Where it goes: ServerAuth, ClientAuth, ServerClientAuth (and any certificate with one of them): everything.
  EmailProtection: the e-mail addresses only. CodeSigning, TimeStamping, OcspSigning: nothing (they carry no SAN).
  EV: the SAN rules of EV certificates (no wildcard, no IP address, no internal name, no e-mail address) are
  deliberately NOT applied, so an EV leaf with -AddDevelopmentSAN is the way to make EV-looking certificates for
  development. The EV subject, the EV policy and the 398-day limit stay. A warning is printed and leaf-info.json says
  developmentSan / evSanOverride = true. FOR DEVELOPMENT ONLY: a public CA would not issue such a certificate.
  Change the list in [ development_san ] of agantra_pki.cnf (DNS.n, IP.n, IPRange.n = first-last, email.n); without
  that section the built-in list above is used. A range may have at most 1024 addresses.

CODE SIGNING SUBJECT   (-CodeSigningCompany)
  -CodeSigningCompany <name>   CN = O = <name>. Empty: CN = O = the organization (-Organization or the cnf; default
                               Agantra Inovatif OU). Alias: -CodesignCompany.
  The subject of every code signing certificate is short, at every level (DV, OV, EV):
      C = EE   ST = Tallinn   L = Tallinn   O = <company>   CN = <company>
  -Country / -State / -Locality change C, ST and L. Nothing else is written: no OU, street, postal code, contact
  fields and, at -EV, none of the EV-only fields (serialNumber, businessCategory, jurisdiction*). <company> may not be
  longer than 64 characters. -CommonName does not apply to code signing.

KEY AND SIGNATURE   (floors are enforced: weaker values are REJECTED)
  -KeyType RSA|ECDSA|MLDSA   Default: quadrant 1 RSA, 2 ECDSA, 3 / 4 MLDSA. Quantum quadrants take MLDSA only.
  -KeyBits <n>               RSA 2048 | 3072 | 4096 | 8192 (default 2048; below 2048 is rejected).
  -Curve P-256|P-384|P-521   ECDSA (default P-256; smaller curves are rejected).
  -PqcAlgorithm mldsa44|65|87  ML-DSA parameter set (default mldsa65, from the configuration).
  -Hash sha256|sha384|sha512 Digest of the signature (default: the issuer's). SHA-1, SHA-224, MD5 ... rejected.
  Code signing is FORCED up: RSA >= 4096, ECDSA >= P-384, ML-DSA >= 65, SHA-256 or stronger (a note says so).

VALIDITY AND POLICIES
  -Days <n>            Default: EV 397 days (maximum 398), OV 3 years, DV 5 years. Never longer than the issuer.
  -Policy <list>       Extra certificate policies: "OID" or "OID|CPS-URL". The level policy (EV 2.23.140.1.1,
                       OV 2.23.140.1.2.2, DV 2.23.140.1.2.1), [ policy_oids ] / [ iana_pen ] and these are written.
  -CpsUrl <url>        CPS pointer on every policy of a DV / OV certificate (default https://nextmantra.com/security/certs).
  -CpsUrlEv <url>      CPS pointer on every policy of an EV certificate (default https://nextmantra.com/security/certs/ev-cps.pdf).
  POLICIES of a leaf: the level policy (DV 2.23.140.1.2.1 | OV 2.23.140.1.2.2 | EV 2.23.140.1.1), the company policy 1.3.6.1.4.1.<PEN>.1 and its level policy
                       (.1.1 EV, .1.2 OV, .1.3 DV), and for EVERY OV certificate the HIGH ASSURANCE policy 1.3.6.1.4.1.<PEN>.1.5 ([ policy_oids ] HighAssurance).
                       Each policy carries the CPS pointer above.

SUBJECT   (DV: CN only.  OV: CN O OU L ST C street postalCode + contact.  EV: OV + serialNumber,
           businessCategory, jurisdiction*, and -Duns)
  -Organization -OrganizationalUnit -Country -State -Locality -Street -PostalCode
  -Serial -BusinessCategory -JurisdictionCountry -JurisdictionState -JurisdictionLocality
  -Duns <number>       EV: written as organizationIdentifier = DUNS+<number> (a private convention)
  -ContactName -ContactEmail -ContactPhone      Defaults come from [ subject_ov ] / [ subject_ev ].

OUTPUT   (ALL formats in ONE go by default)
  -Format <list>       PEM .pem | DER .der | CER .cer (DER) | CERT .cert (PEM) | P7B .p7b (leaf + chain) |
                       RFC7468 .rfc7468.pem (strict PEM) | PFX .pfx | ALL.   Default ALL.
                       ALWAYS written: <stem>.crt  .key (PKCS#8)  .pub  .pub.der (public key)  -fullchain.crt  -chain.crt  .cnf
                       A FIPS leaf also gets <stem>-fips.pfx (FIPS-conformant PKCS#12).
  -OutputRoot <path>   Folder that receives the leaf folders (default <script folder>\leafcerts).
  -Password <text>     PFX password (default Abc12345!, the lab password of the PKI).    -LegacyPfx  3DES / SHA-1 PFX.
  -NoGuidance          Do not write convert-formats.ps1 and tls-guidance.txt.
  -InstallPfx          Windows: also import the leaf PFX files into LocalMachine\My (elevated). Only the leaf.
  Written in every purpose folder (unless -NoGuidance):
      convert-formats.ps1   clean PowerShell with the exact OpenSSL syntax for every format of this leaf
      tls-guidance.txt      TLS 1.2 / 1.3, HTTP/2, HTTP/3 (ServerAuth and ClientAuth only)
      leaf-info.json        what was issued (also added to leafcerts\leaf-index.json)
  Written in the set folder:  leaf-set.json

NAMES OF THE FOLDERS AND FILES   (agantra_pki.cnf [ leaf_names ]; defaults in scripts\01b_CaNaming.ps1)
  OutputFolder = leafcerts   Folder = {Name}   Stem = {Name}-{Level}-{Tag}   UniqueSuffix = _{Date}-{Time}
  PurposeFolder = {PurposeName}   PurposeStem = {Name}-{Purpose}-{Level}-{Tag}
  Tokens: {Name} {Level} {Quadrant} {Tag} {Algorithm} {Track} {Fips} {Purpose} {PurposeName} {Date} {Time}
  Example: leafcerts\www.example.com\serverauth\www.example.com-server-ev-q1-rsa2048.crt

INFORMATION, UNBLOCK AND UNLOCK
  -List                Show the leaf certificates made so far.      -Check   OpenSSL readiness only.
  -Unblock             UNBLOCK (Internet mark) and UNLOCK (Read-only) the script folder, the pki folder and the leaf
                       folder, children and recursive, list the programs that hold files open, and stop.
                       (A script that is blocked the very first time needs once:
                        Get-ChildItem -Path . -Recurse -File | Unblock-File )
  -ConfigFile <path>   Configuration file (default agantra_pki.cnf next to the script).
  -PkiRoot <path>      The PKI folder (default .\pki).
  -OpenSslPath <path>  Use this openssl (4.x).        -FipsModuleConfig <path>   fipsmodule.cnf of the FIPS module.
  -Verbose             Show every OpenSSL command.    -Help   This text.

LIMITATIONS
  * ML-DSA leaves (-Quantum) work with OpenSSL 3.5+ services and mutual TLS. Windows Schannel (Kestrel / IIS on
    Windows), Java 25 and the browsers do not accept them for HTTPS today: use a Classic leaf there.
  * Private PKI: wildcard and internal names are allowed; a public CA would refuse some. Public TLS leaves are
    limited to 398 days.
  * -AddDevelopmentSAN makes certificates that are NOT EV-conformant in their SAN (by intent); development only.
    A SAN with 428 entries makes every TLS certificate about 6 KB larger than usual.
  * A set is all or nothing: if one certificate fails, the new set folder is removed.
  * Leaves of version 4.6 are in pki\leafcerts; they are not moved. Files are UTF-8 without BOM, LF endings,
    except convert-formats.ps1 (UTF-8 with BOM, CRLF).
'@
}

if ($Help) {
    Show-PkiLeafHelp
    exit 0
}

Write-Host '============================================================'
Write-Host 'Author : Nicko Satria Utama'
Write-Host 'Company: Agantra Inovatif OÜ (NextMantra)'
Write-Host 'Email  : nicko@nextmantra.com'
Write-Host '============================================================'
Write-Host ''

# ------------------------------------------------------------------------------------------------------------
# STANDARD BOOTSTRAP of every main script: UNBLOCK + UNLOCK the whole script folder, children and recursive,
# BEFORE any other script of the folder is loaded (a blocked script cannot be loaded). Same text in pki_setup.ps1.
#   unblock = remove the Windows "downloaded from the Internet" mark    unlock = remove the Read-only attribute
# ------------------------------------------------------------------------------------------------------------
function Invoke-PkiBootstrapUnlock {
    param([Parameter(Mandatory)][string]$Root)
    $ro = [System.IO.FileAttributes]::ReadOnly
    $unlocked = 0
    foreach ($i in (@(Get-Item -LiteralPath $Root -Force) + @(Get-ChildItem -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue))) {
        try { if (($i.Attributes -band $ro) -ne 0) { $i.Attributes = $i.Attributes -bxor $ro; $unlocked++ } } catch { }
        if ($IsWindows -and -not $i.PSIsContainer) { Unblock-File -LiteralPath $i.FullName -ErrorAction SilentlyContinue }
    }
    return $unlocked
}
$script:BootstrapUnlocked = 0
try { $script:BootstrapUnlocked = [int](Invoke-PkiBootstrapUnlock -Root $script:ScriptRoot) }
catch { Write-Host "[WARN] Automatic unblock / unlock failed: $($_.Exception.Message)" -ForegroundColor Yellow }

$script:LeafFolderCreated = $null
try {
    # The same shared modules as pki_setup.ps1 (the 'Library' set: everything except the pki_setup orchestration).
    $PkiModuleSet = 'Library'
    . (Join-Path $script:ScriptRoot 'scripts/PkiModules.ps1')

    # ---------------- selection ----------------
    if (@($DV, $OV, $EV | Where-Object { $_ }).Count -gt 1) { throw 'Use only one of -DV, -OV and -EV.' }
    if ($Classic -and $Quantum) { throw 'Use only one of -Classic and -Quantum.' }
    if ($Purpose -and ($AllPurposes -or $ExcludePurpose)) { throw '-Purpose makes ONE certificate with exactly those purposes; it cannot be combined with -AllPurposes or -ExcludePurpose (the set).' }
    $level = if ($DV) { 'DV' } elseif ($OV) { 'OV' } else { 'EV' }
    $track = if ($Quantum) { 'Quantum' } else { 'Classic' }
    $quadrant = if ($Quantum) { if ($FIPS) { 4 } else { 3 } } else { if ($FIPS) { 2 } else { 1 } }

    Initialize-PkiConfiguration -ScriptRoot $script:ScriptRoot -Bound $PSBoundParameters -VerboseOutput:([bool]$Verbose)
    $c = $script:Pki
    Test-PkiLeafNaming
    $leafRoot = Get-PkiLeafRoot

    # ---------------- -Unblock: UNBLOCK + UNLOCK, children and recursive ----------------
    if ($Unblock) {
        Write-PkiLog 'UNBLOCK + UNLOCK (children and recursive)'
        Write-PkiLog "Start-up bootstrap of this script: $($script:BootstrapUnlocked) read-only item(s) unlocked in $($script:ScriptRoot) (the Internet mark is removed on Windows)."
        [void](Invoke-PkiUnblockUnlock -Path @($script:ScriptRoot, $c.PkiRoot, $leafRoot))
        exit 0
    }
    if ($List) { Show-PkiLeafIndex -Root $leafRoot; exit 0 }

    if (-not ($DV -or $OV -or $EV)) { Write-PkiLog 'No -DV / -OV / -EV given: using -EV.' }
    if (-not ($Classic -or $Quantum)) { Write-PkiLog 'No -Classic / -Quantum given: using -Classic.' }
    if (-not $FIPS) { Write-PkiLog 'No -FIPS given: non-FIPS quadrant.' }
    # ServerAuth + ClientAuth asked together (and nothing else) = THREE certificates: server only, client only, server + client.
    $threeTls = $false
    if ($Purpose) {
        $pu = @($Purpose | Select-Object -Unique)
        if (($pu -contains 'ServerAuth') -and ($pu -contains 'ClientAuth') -and (@($pu | Where-Object { $_ -notin 'ServerAuth', 'ClientAuth', 'ServerClientAuth' }).Count -eq 0)) { $threeTls = $true }
    }
    $setMode = (-not [bool]$Purpose) -or $threeTls
    $purposes = @(if (-not [bool]$Purpose) { $script:PkiPurposeProfiles.Keys | Where-Object { @($ExcludePurpose) -notcontains $_ } } elseif ($threeTls) { @('ServerAuth', 'ClientAuth', 'ServerClientAuth') } else { $Purpose })
    if ($setMode -and $purposes.Count -eq 0) { throw '-ExcludePurpose removed every purpose: nothing to make.' }
    Write-PkiLog "Leaf: $level, $track$(if ($FIPS) { ' FIPS' }) = Quadrant $quadrant, issuer q$quadrant-$($level.ToLowerInvariant())"
    Write-PkiLog $(if ($setMode) { "Set: one certificate for each of $($purposes.Count) purposes ($($purposes -join ', ')), every format, in one go." } else { "One certificate with the purposes: $($Purpose -join ', ')." })
    if (($purposes -contains 'ServerAuth') -and ($purposes -contains 'ClientAuth') -and $setMode) { Write-PkiLog 'TLS: ServerAuth and ClientAuth are made as THREE certificates: server only, client only, and one with both (ServerClientAuth).' }
    Write-PkiLog "Output folder: $leafRoot"
    $oldLeaf = Join-Path $c.PkiRoot 'leafcerts'
    if ((Test-Path -LiteralPath (Join-Path $oldLeaf 'leaf-index.json')) -and ($oldLeaf -ne $leafRoot)) {
        Write-PkiLog "Leaf folders of version 4.6 are still in $oldLeaf (they are not moved)." 'INFO'
    }

    # ---------------- OpenSSL 4.x with FIPS and quantum: BEFORE anything is made ----------------
    Initialize-OpenSSL
    if ($Check) {
        $ready = $true
        try { [void](Assert-PkiLeafOpenSslReady -NeedFips $true -NeedPqc $true) }
        catch { $ready = $false; Write-Host ''; foreach ($l in ($_.Exception.Message -split "`r?`n")) { Write-Host $l -ForegroundColor Yellow } }
        Write-Host ''
        if ($ready) { Write-Host 'READY: OpenSSL 4.x with the FIPS provider and ML-DSA.' -ForegroundColor Green; exit 0 }
        Write-Host 'NOT READY: see above (run Install-DevEnvironment.ps1 as suggested).' -ForegroundColor Red
        exit 1
    }
    [void](Assert-PkiLeafOpenSslReady -NeedFips ([bool]$FIPS) -NeedPqc ([bool]$Quantum))

    # ---------------- the existing PKI ----------------
    $m = Import-PkiExisting -SkipProviders
    if ($c.Quadrants -notcontains $quadrant) {
        $have = ($c.Quadrants | ForEach-Object { "Q$_" }) -join ', '
        throw "This PKI has no Quadrant $quadrant ($track$(if ($FIPS) { ' FIPS' })); it contains: $have.`nUse another quadrant, or build the missing ones: .\pki_setup.ps1 -Clean -Quadrant 1,2,3,4 (a new PKI)."
    }
    $issuer = Get-PkiCa -Id "q$quadrant-$($level.ToLowerInvariant())"
    Write-PkiLog "Issuer: $($issuer.Id)  [$($c.Built[$issuer.Id].commonName)]"

    $base = @{
        Level = $level; Quadrant = $quadrant; DnsName = $DnsName; IpAddress = $IpAddress; EmailAddress = $EmailAddress
        CommonName = $CommonName; KeyType = $KeyType; KeyBits = $KeyBits; Curve = $Curve
        PqcAlgorithm = $PqcAlgorithm; Hash = $Hash; Days = $Days; Policy = $Policy; Format = $Format
        AddDevelopmentSan = [bool]$AddDevelopmentSAN; CodeSigningCompany = $CodeSigningCompany
    }
    if ($purposes -contains 'CodeSigning') {
        $csDn = Get-PkiCodeSigningDn -Company $CodeSigningCompany -Level $level
        Write-PkiLog ('Code signing subject: ' + (($csDn | ForEach-Object { '{0}={1}' -f $_[0], $_[1] }) -join ', '))
    }
    if ($AddDevelopmentSAN) {
        $devList = Get-PkiDevelopmentSan
        Write-PkiLog "-AddDevelopmentSAN: $($devList.Dns.Count) DNS names, $($devList.Ip.Count) IP addresses and $($devList.Email.Count) e-mail addresses ($($devList.Source)) are added to the SAN of the TLS certificates (S/MIME: the e-mail addresses only; code signing, time stamping and OCSP carry no SAN)." 'WARN'
        if ($level -eq 'EV') { Write-PkiLog 'EV: the SAN rules of EV certificates (no wildcard, no IP address, no internal name, no e-mail address) are deliberately NOT applied. The subject, the EV policy and the 398-day limit stay. For development only; no public CA would issue this.' 'WARN' }
    }
    if ($purposes -contains 'TimeStamping') {
        $ts = Get-PkiTimestampSettings
        Write-PkiLog ("Time stamping certificate: Quadrant {0} ({1}{2}), policy OID {3}, valid {4} days (Classic non-FIPS is the default; -TimestampQuadrant, -TimestampPolicyOid, -TimestampDays change it)." -f $ts.Quadrant, $(if ($ts.Quadrant -in 3, 4) { 'Quantum' } else { 'Classic' }), $(if ($ts.Quadrant -in 2, 4) { ' FIPS' } else { ' non-FIPS' }), $(if ($ts.PolicyOid) { $ts.PolicyOid + $(if ($ts.Derived) { ' (from your IANA PEN)' }) } else { '(none: set one)' }), $ts.Days)
        if ($ts.Quadrant -in 3, 4) { Write-PkiLog 'A quantum time stamping certificate cannot be used by the PKI server kit yet (openssl ts signs with RSA / ECDSA).' 'WARN' }
    }
    $items = [System.Collections.Generic.List[hashtable]]::new()
    $setFolder = $null
    $setName = ''

    if ($setMode) {
        # ---------------- the SET: decide everything first, then write ----------------
        $specs = New-PkiLeafSetSpecs -Base $base -Purposes $purposes
        $script:LeafFolderCreated = $null          # Invoke-PkiLeafSet removes its own folder when it fails
        $res = Invoke-PkiLeafSet -Specs $specs -LeafRoot $leafRoot -Guidance:(-not $NoGuidance)
        $setFolder = $res.Folder
        $setName = $setFolder.Name
        foreach ($it in $res.Items) { [void]$items.Add($it) }
    }
    else {
        # ---------------- ONE certificate with the given purposes ----------------
        $one = $base.Clone(); $one.Eku = @(Resolve-PkiPurposeEku -Purpose $Purpose)
        $spec = New-PkiLeafSpec -Options $one
        $folder = New-PkiUniqueFolder -Root $leafRoot -Name $spec.Folder -SuffixTemplate $spec.UniqueSuffix
        $script:LeafFolderCreated = $folder.Path
        $spec.OutDir = $folder.Path
        if ($folder.Renamed) { Write-PkiLog "The folder '$($spec.Folder)' exists already: a NEW folder was created: $($folder.Name)" 'WARN' }
        $r = New-PkiLeafCertificate -Spec $spec
        $validation = Test-PkiLeafResult -Spec $spec -R $r
        Write-PkiLog 'Validation passed: chain, key, purpose, policies and every file.' 'OK'
        foreach ($oid in $validation.UnsupportedPolicies) {
            Write-PkiLog "Policy $oid is in the leaf but the issuing CA does not carry it: a policy-processing client will not see it asserted by the chain." 'WARN'
        }
        if (-not $NoGuidance) { [void](Write-PkiLeafGuidance -Spec $spec -R $r) }
        $r.Files = @(@(Get-ChildItem -LiteralPath $r.Dir -File | Where-Object { $_.Name -notlike '*.tmp.*' } | ForEach-Object { $_.Name }) + @('leaf-info.json') | Sort-Object -Unique)
        $setFolder = $folder; $setName = ''
        [void]$items.Add(@{ Spec = $spec; Result = $r; Relative = $folder.Name })
        $script:LeafFolderCreated = $null
    }

    # ---------------- index, per-leaf info, set info ----------------
    foreach ($it in $items) {
        $entry = Add-PkiLeafIndex -Root $leafRoot -Spec $it.Spec -R $it.Result -FolderName $it.Relative -Set $setName
        Write-Utf8NoBom -Path (Join-Path $it.Result.Dir 'leaf-info.json') -Content ($entry | ConvertTo-Json -Depth 6)
    }
    if ($setMode) {
        $setInfo = [ordered]@{
            set = $setName; path = $setFolder.Path; level = $level; quadrant = $quadrant; track = $track; fips = [bool]$FIPS
            purposes = @($items | ForEach-Object { $_.Spec.Eku -join '+' }); developmentSan = [bool]$AddDevelopmentSAN; formats = @($items[0].Spec.Formats)
            createdUtc = [DateTime]::UtcNow.ToString('o'); generator = "GenerateLeafCertificate.ps1 $($script:PkiGeneratorVersion)"
            certificates = @($items | ForEach-Object { [ordered]@{ purpose = ($_.Spec.Eku -join '+'); folder = $_.Relative; stem = $_.Result.Stem; keyAlgorithm = $_.Result.Actual.Algorithm; notAfter = $_.Result.NotAfter; sha1 = $_.Result.Sha1 } })
        }
        Write-Utf8NoBom -Path (Join-Path $setFolder.Path 'leaf-set.json') -Content ($setInfo | ConvertTo-Json -Depth 6)
    }

    # ---------------- UNBLOCK + UNLOCK what was written ----------------
    [void](Unblock-PkiTree -Path @($setFolder.Path)); [void](Unlock-PkiTree -Path @($setFolder.Path))

    # ---------------- Windows: leaf PFX into My ----------------
    if ($InstallPfx) {
        if (-not $IsWindows) { Write-PkiLog '-InstallPfx is for Windows; skipped.' 'WARN' }
        else {
            Assert-Administrator
            foreach ($it in $items) {
                if (-not $it.Result.Pfx) { Write-PkiLog "-InstallPfx: no PFX for $($it.Result.Stem) (add PFX to -Format); skipped." 'WARN'; continue }
                $res2 = Install-PkiLeafPfx -Leaf ([ordered]@{ name = $it.Result.Stem; pfx = $it.Result.Pfx; sha1 = $it.Result.Sha1 })
                if ($res2.Status -eq 'failed') { Write-PkiLog "The PFX of $($it.Result.Stem) could not be imported: $($res2.Message)" 'WARN' }
            }
        }
    }

    # ---------------- summary ----------------
    Write-Host ''
    Write-Host $(if ($setMode) { 'LEAF CERTIFICATE SET' } else { 'LEAF CERTIFICATE' }) -ForegroundColor Cyan
    Write-Host ("  Folder     : {0}" -f $setFolder.Path)
    Write-Host ("  Level      : {0}   Quadrant {1} ({2}{3})   Issuer {4}" -f $level, $quadrant, $track, $(if ($FIPS) { ' FIPS' } else { '' }), $issuer.Id)
    Write-Host ("  Formats    : {0}" -f ($items[0].Spec.Formats -join ', '))
    if ($AddDevelopmentSAN) { Write-Host ("  Dev SAN    : {0} DNS, {1} IP, {2} e-mail in the TLS certificates{3}" -f $devList.Dns.Count, $devList.Ip.Count, $devList.Email.Count, $(if ($level -eq 'EV') { ' (EV SAN rules NOT applied)' } else { '' })) -ForegroundColor Yellow }
    Write-Host ''
    Write-Host ('  {0,-16} {1,-12} {2,-6} {3,-11} {4}' -f 'PURPOSE', 'KEY', 'DAYS', 'EXPIRES', 'SUBJECT CN / FOLDER') -ForegroundColor Cyan
    foreach ($it in $items) {
        $cn = (@($it.Spec.DnPairs | Where-Object { $_[0] -eq 'CN' }) | Select-Object -First 1)[1]
        Write-Host ('  {0,-16} {1,-12} {2,-6} {3,-11} {4}' -f ($it.Spec.Eku -join '+'), $it.Result.Actual.Algorithm, $it.Result.Days, $it.Result.NotAfter, $cn)
        Write-Host ('  {0,-16} {1}' -f '', $it.Relative) -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Host '  Files in every purpose folder:'
    Write-Host ('      ' + (($items[0].Result.Files | ForEach-Object { $_.Replace($items[0].Result.Stem, '<name>') }) -join '   '))
    Write-Host '      (<name> = the certificate name of that folder: the key <name>.key and the public key <name>.pub are in EVERY purpose folder)'
    Write-Host ''
    Write-PkiLog "$($items.Count) certificate(s) ready in $($setFolder.Path)" 'OK'
    if (-not $NoGuidance) { Write-PkiLog 'convert-formats.ps1 (every format) in each folder; tls-guidance.txt for ServerAuth / ClientAuth.' 'INFO' }
    exit 0
}
catch {
    $failure = $_
    # a folder this run created for a leaf that failed is removed (it is new and holds nothing else)
    if ($script:LeafFolderCreated -and (Test-Path -LiteralPath $script:LeafFolderCreated)) {
        if (Get-Command Unlock-PkiTree -ErrorAction SilentlyContinue) { [void](Unlock-PkiTree -Path @($script:LeafFolderCreated)) }
        Remove-Item -LiteralPath $script:LeafFolderCreated -Recurse -Force -ErrorAction SilentlyContinue
    }
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
