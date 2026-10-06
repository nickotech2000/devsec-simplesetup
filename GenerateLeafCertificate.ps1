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
    [ValidateSet('ServerAuth', 'ClientAuth', 'CodeSigning', 'EmailProtection', 'TimeStamping', 'OcspSigning')][string[]]$Purpose,
    [ValidateSet('ServerAuth', 'ClientAuth', 'CodeSigning', 'EmailProtection', 'TimeStamping', 'OcspSigning')][string[]]$ExcludePurpose,

    # ---- names ----
    [string[]]$DnsName,
    [string[]]$IpAddress,
    [string[]]$EmailAddress,
    [string]$CommonName,

    # ---- key and signature ----
    [ValidateSet('RSA', 'ECDSA', 'MLDSA')][string]$KeyType,
    [int]$KeyBits,
    [ValidateSet('P-256', 'P-384', 'P-521')][string]$Curve,
    [ValidatePattern('^(?i)ml-?dsa-?(44|65|87)$')][string]$PqcAlgorithm,
    [string]$Hash,

    # ---- validity and policies ----
    [ValidateRange(1, 36500)][int]$Days,
    [string[]]$Policy,
    [string]$CpsUrl,

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
 Version 4.7.0-phaseB
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : GenerateLeafCertificate-MANUAL.txt   Design : PKI-Design-with-FIPS-and-PQC.txt (section 15)
 Needs  : PowerShell 7+, OpenSSL 4.x with the FIPS module and ML-DSA, and a PKI made by pki_setup.ps1.

WHAT IT DOES
  ONE RUN makes a certificate for EVERY purpose, each in EVERY format, validates all of them, and writes them to
      <script folder>\leafcerts\<name>\<purpose>\      (NOT inside the pki folder)
  The six purposes (the "set"):
      ServerAuth       TLS server               CodeSigning      code signing (Authenticode and others)
      ClientAuth       TLS client / mutual TLS  TimeStamping     RFC 3161 time stamping (critical, alone)
      EmailProtection  S/MIME                   OcspSigning      OCSP responder (with the no-check extension)
  Every certificate has its own purpose, its own key and its own folder. Mixing purposes in one certificate is
  possible (see -Purpose) but not the default: code signing and TLS should not share a certificate.
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
  .\GenerateLeafCertificate.ps1 -OV -DnsName shop.example.com -Purpose ServerAuth,ClientAuth -Format PFX
  .\GenerateLeafCertificate.ps1 -List                                         leaf certificates made so far
  .\GenerateLeafCertificate.ps1 -Unblock                                      unblock + unlock the folders, then stop

LEVEL AND QUADRANT   (defaults: -EV, -Classic, no -FIPS)
  -DV | -OV | -EV      Domain / Organization / Extended validation. Chooses the intermediate q<N>-dv|ov|ev.
  -Classic | -Quantum  Classic: RSA or ECDSA leaf.  Quantum: ML-DSA leaf.
  -FIPS                FIPS quadrant (FIPS provider).  -Classic = Q1, -Classic -FIPS = Q2, -Quantum = Q3,
                       -Quantum -FIPS = Q4.
  Browser-facing sites and Windows servers: Classic (Q1 / Q2). Quantum: OpenSSL-based services and mutual TLS.
  A quadrant the PKI does not have (built with -ClassicPKI or -Quadrant) is refused with the fix.

PURPOSES
  (none) | -AllPurposes   One certificate for EACH purpose (the set above). -AllPurposes only says it out loud.
  -ExcludePurpose <list>  Leave purposes out of the set: ServerAuth ClientAuth CodeSigning EmailProtection
                          TimeStamping OcspSigning.
  -Purpose <list>         NOT a set: ONE certificate that carries exactly these purposes, for example
                          ServerAuth,ClientAuth (the old default). TimeStamping and OcspSigning must stand alone.
                          Cannot be combined with -AllPurposes / -ExcludePurpose.
  Names per purpose in a set:
      ServerAuth, ClientAuth   the DNS names / IPs you give (first = primary, wildcard *.example.com allowed), or the
                               [ leaf_san ] list of agantra_pki.cnf when none is given.
      EmailProtection          -EmailAddress, else the contact e-mail (ContactEmail). The CN is the e-mail address.
      CodeSigning, TimeStamping, OcspSigning   no SAN; CN = "<company or -CommonName> Code Signing | Time Stamping |
                               OCSP Responder".

NAMES
  -DnsName <a,b>   -IpAddress <a,b>   -EmailAddress <a,b>   -CommonName <text>
  Given on the command line = exactly these names. -CommonName replaces the CN of the TLS certificates and is the
  base of the CN of the other purposes.

KEY AND SIGNATURE   (floors are enforced: weaker values are REJECTED)
  -KeyType RSA|ECDSA|MLDSA   Default: Q1 RSA, Q2 ECDSA, Q3 / Q4 MLDSA. Quantum quadrants take MLDSA only.
  -KeyBits <n>               RSA 2048 | 3072 | 4096 | 8192 (default 2048; below 2048 is rejected).
  -Curve P-256|P-384|P-521   ECDSA (default P-256; smaller curves are rejected).
  -PqcAlgorithm mldsa44|65|87  ML-DSA parameter set (default mldsa65, from the configuration).
  -Hash sha256|sha384|sha512 Digest of the signature (default: the issuer's). SHA-1, SHA-224, MD5 ... rejected.
  Code signing is FORCED up: RSA >= 4096, ECDSA >= P-384, ML-DSA >= 65, SHA-256 or stronger (a note says so).

VALIDITY AND POLICIES
  -Days <n>            Default: EV 397 days (maximum 398), OV 3 years, DV 5 years. Never longer than the issuer.
  -Policy <list>       Extra certificate policies: "OID" or "OID|CPS-URL". The level policy (EV 2.23.140.1.1,
                       OV 2.23.140.1.2.2, DV 2.23.140.1.2.1), [ policy_oids ] / [ iana_pen ] and these are written.
  -CpsUrl <url>        CPS pointer of the level policy.

SUBJECT   (DV: CN only.  OV: CN O OU L ST C street postalCode + contact.  EV: OV + serialNumber,
           businessCategory, jurisdiction*, and -Duns)
  -Organization -OrganizationalUnit -Country -State -Locality -Street -PostalCode
  -Serial -BusinessCategory -JurisdictionCountry -JurisdictionState -JurisdictionLocality
  -Duns <number>       EV: written as organizationIdentifier = DUNS+<number> (a private convention)
  -ContactName -ContactEmail -ContactPhone      Defaults come from [ subject_ov ] / [ subject_ev ].

OUTPUT   (ALL formats in ONE go by default)
  -Format <list>       PEM .pem | DER .der | CER .cer (DER) | CERT .cert (PEM) | P7B .p7b (leaf + chain) |
                       RFC7468 .rfc7468.pem (strict PEM) | PFX .pfx | ALL.   Default ALL.
                       ALWAYS written: <stem>.crt  .key (PKCS#8)  -fullchain.crt  -chain.crt  .cnf
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
    $setMode = -not [bool]$Purpose
    $purposes = @(if ($setMode) { $script:PkiPurposeProfiles.Keys | Where-Object { @($ExcludePurpose) -notcontains $_ } } else { $Purpose })
    if ($setMode -and $purposes.Count -eq 0) { throw '-ExcludePurpose removed every purpose: nothing to make.' }
    Write-PkiLog "Leaf: $level, $track$(if ($FIPS) { ' FIPS' }) = Quadrant $quadrant, issuer q$quadrant-$($level.ToLowerInvariant())"
    Write-PkiLog $(if ($setMode) { "Set: one certificate for each of $($purposes.Count) purposes ($($purposes -join ', ')), every format, in one go." } else { "One certificate with the purposes: $($Purpose -join ', ')." })
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
        $one = $base.Clone(); $one.Eku = @($Purpose)
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
            purposes = @($items | ForEach-Object { $_.Spec.Eku[0] }); formats = @($items[0].Spec.Formats)
            createdUtc = [DateTime]::UtcNow.ToString('o'); generator = "GenerateLeafCertificate.ps1 $($script:PkiGeneratorVersion)"
            certificates = @($items | ForEach-Object { [ordered]@{ purpose = $_.Spec.Eku[0]; folder = $_.Relative; stem = $_.Result.Stem; keyAlgorithm = $_.Result.Actual.Algorithm; notAfter = $_.Result.NotAfter; sha1 = $_.Result.Sha1 } })
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
    Write-Host ''
    Write-Host ('  {0,-16} {1,-12} {2,-6} {3,-11} {4}' -f 'PURPOSE', 'KEY', 'DAYS', 'EXPIRES', 'SUBJECT CN / FOLDER') -ForegroundColor Cyan
    foreach ($it in $items) {
        $cn = (@($it.Spec.DnPairs | Where-Object { $_[0] -eq 'CN' }) | Select-Object -First 1)[1]
        Write-Host ('  {0,-16} {1,-12} {2,-6} {3,-11} {4}' -f ($it.Spec.Eku -join '+'), $it.Result.Actual.Algorithm, $it.Result.Days, $it.Result.NotAfter, $cn)
        Write-Host ('  {0,-16} {1}' -f '', $it.Relative) -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Host '  Files in every purpose folder:'
    Write-Host ('      ' + (($items[0].Result.Files | Where-Object { $_ -notlike '*-chain.crt' -and $_ -notlike '*-fullchain.crt' -and $_ -notlike '*.cnf' }) -join '   '))
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
