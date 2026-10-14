# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Signs the CSR (certificate signing request) of another department or person with one of our INTERMEDIATE CAs, after checking the request
    against the specification of this PKI, and writes the certificate and our chain into a NEW folder to send back.
    Default: DV, Classic non-FIPS, TLS server. Full help: .\SignCsr.ps1 -Help     Manual: docs\SignCsr-MANUAL.txt
.EXAMPLE
    .\SignCsr.ps1 -Csr D:\requests\web01.csr
.EXAMPLE
    .\SignCsr.ps1 -Csr .\web01.csr -OV -Purpose ServerClientAuth
.EXAMPLE
    .\SignCsr.ps1 -Csr .\web01.csr -EV -FIPS -Check
#>
# No [CmdletBinding()]: it would reserve -EV and -OV (aliases of -ErrorVariable / -OutVariable), the names of the levels.
param(
    # which company's PKI (default: agantra; names = the *_pki.cnf files next to the scripts; list: .\pki_setup.ps1 -ListPki)
    [Alias('Pki')][ArgumentCompleter({ param($c, $p, $w) $s = (Get-Command $c -ErrorAction SilentlyContinue).Source; $d = if ($s) { Split-Path -Parent $s } else { $PWD.Path }; Get-ChildItem -LiteralPath $d -Filter '*_pki.cnf' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name -replace '_pki\.cnf$', '' } | Where-Object { $_ -like "$w*" } })][string]$PkiProfile,
    [string]$Csr,
    [ValidateSet('Auto', 'Leaf', 'IntermediateCA')][string]$CsrType = 'Auto',
    # ---- level and quadrant (default: -DV, -Classic, non-FIPS) ----
    [switch]$DV,
    [switch]$OV,
    [switch]$EV,
    [switch]$Classic,
    [switch]$Quantum,
    [switch]$FIPS,
    [switch]$AddDevelopmentSAN,
    # ---- what the certificate is for (one purpose per request: one key = one purpose) ----
    [ValidateSet('ServerAuth', 'ClientAuth', 'ServerClientAuth', 'CodeSigning', 'EmailProtection', 'TimeStamping', 'OcspSigning')][string]$Purpose = 'ServerAuth',
    [ValidateRange(1, 36500)][int]$Days,
    [string]$Name,
    [string]$OutFolder,
    [string[]]$Policy,
    [switch]$NoCrl,
    [switch]$NoOcsp,
    [switch]$NoRevocationInfo,
    # ---- behaviour ----
    [switch]$Check,
    [switch]$Strict,
    [switch]$NoColor,
    [switch]$List,
    [switch]$WriteShellEnv,
    [switch]$Unblock,
    [switch]$Help,
    [switch]$Verbose,
    [string]$ConfigFile,
    [string]$PkiRoot,
    [ValidateRange(1, 99)][int]$Release,
    [switch]$NoCaRevocationInfo,
    [string]$OpenSslPath,
    [string]$FipsModuleConfig
)

$ErrorActionPreference = 'Stop'
$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Show-SignCsrHelp {
    @'
============================================================
 SignCsr.ps1 - sign the certificate request (CSR) of another department with our PKI
 Version 5.3.5
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : docs\SignCsr-MANUAL.txt     Design : docs\PKI-Design-with-FIPS-and-PQC.txt (10.72, section 20)
 Ubuntu : SignCsr.sh (same options, written --like-this): in the DevKit, or devkit\SignCsr.sh of the project.
 Needs  : PowerShell 7+, OpenSSL 4.x, a PKI made by pki_setup.ps1 (or the DevKit unpacked with Install-PkiTrust).

WHAT IT DOES
  A department has made its OWN private key and a CSR (the request) and sent you only the CSR. This script
    1. READS the request and CHECKS it against the specification of this PKI (key, signature, subject, names, validity),
       printing every finding in colour with the reason and the fix:   red ERROR   yellow WARN   green OK   cyan INFO
    2. refuses it when there is an ERROR (exit code 2, nothing is signed), or signs it with the right INTERMEDIATE CA,
    3. writes the result into a NEW folder (never overwritten):
           csr-signed\<name>_<yyyyMMdd-HHmmss>\
               <name>.crt <name>.cer       his certificate (PEM and DER)
               <name>-fullchain.crt        his certificate + our CA chain: the file for his server
               <name>-chain.crt            our CA chain       <name>.p7b  certificate + chain for Windows
               root.crt                    our Enterprise Root (clients must trust it)    our-ca-bundle.crt  chain + root
               <name>.csr  sign-info.json  README.txt        (README.txt tells HIM what to do with the files)
       and one line in csr-signed\signed-csr.tsv. Send him the folder (never any private key: we have none of his, he has none of ours).
  The certificate is recorded in the index.txt of the issuing CA: it can be revoked (PkiRevocation.ps1 -Action Revoke) and then shows in the CRL.

WHO SIGNS
  The INTERMEDIATE CA of the level and quadrant:   q<N>-dv | q<N>-ov | q<N>-ev
  -DV | -OV | -EV                  the level. DV = domain only, OV = organization, EV = extended validation.
                                   WITHOUT one of them the level follows the request (5.2.2): the EV information complete (businessCategory, serialNumber,
                                   jurisdictionC) = EV; a company (C and O) = OV; a common name only = DV. A request made by New-PkiCsr.ps1 / new-pki-csr.sh
                                   therefore gets the right level by itself. -Classic and Quadrant 1 (non-FIPS) stay the default; -Quantum / -FIPS decide otherwise.
  -Classic (default) | -Quantum    the track.   -FIPS   the FIPS quadrant (Classic: Q2, Quantum: Q4). Without -FIPS: Q1 / Q3, non-FIPS.
  Roots never sign a request here: a request for a CA certificate is signed by the owner of the Quadrant Roots with SignExternalCa.ps1.

THE SPEC A REQUEST MUST FOLLOW (each deviation is an ERROR or WARN in the report)
  Signature  valid (proves he owns the key), SHA-256 or stronger.
  Key        Classic: RSA 2048 / 3072 / 4096 / 8192 or ECDSA P-256 / P-384 / P-521.     Quantum: ML-DSA-44 / 65 / 87.
             -Purpose CodeSigning needs RSA 4096+ / ECDSA P-384+ / ML-DSA-65+.   Never: RSA < 2048, other curves, Ed25519, DSA.
             A Classic request cannot get a Quantum issuer and the reverse.
  Subject    DV: CN only (other fields are dropped, with a warning).
             OV: C (2 letters), O and CN required; ST, L recommended; OU, street, postalCode, name, emailAddress, telephoneNumber allowed.
             EV: OV + ST, L, serialNumber, businessCategory (Private Organization | Government Entity | Business Entity | Non-Commercial Entity)
                 and jurisdictionC required; jurisdictionST, postalCode recommended.
             CodeSigning: C, O, CN (CN = the company name = O).    Anything else in the subject is an ERROR for that level.
  Names      TLS (ServerAuth, ClientAuth, ServerClientAuth): DNS names and IP addresses. A request without a SAN gets the CN as DNS name (WARN).
             EV: no wildcard, no IP address, no internal name (.internal .local .lan ...), no e-mail address.
             EmailProtection: e-mail addresses (SAN email:) only.  CodeSigning, TimeStamping, OcspSigning: no names (dropped with a WARN).
  Validity   DV 5 years, OV 3 years, EV 397 days (the maximum; a longer -Days is an ERROR), TimeStamping 5 years, OcspSigning 1 year.
             Never longer than the issuing CA.
  Ignored    keyUsage, extendedKeyUsage, CRL / OCSP URLs asked for in the request: THIS PKI sets them (from -Purpose and -Level). The CRL and OCSP
             addresses are those of the issuing CA that signs (q<N>-<level>), whatever the request says.
             A policy OID of the request is added ONLY when it is in the IANA private enterprise arc 1.3.6.1.4.1.<PEN> (the company policy, 5.2.2).
             OV may carry serialNumber (the company ID).
             A request for CA:TRUE is refused.   Policies: the level policy, the PEN policies and the High Assurance policy (OV), as for any leaf.

OPTIONS
  -Csr <file>              His request (PEM).
  -CsrType Auto|Leaf|IntermediateCA   the kind of request (5.2.6, default Auto). Auto recognises it: CA:TRUE = a CA request, names without CA:TRUE = a leaf request.
                           This script signs LEAF requests; a CA request is refused with the command to use (SignExternalCa.ps1). New-PkiCsr.ps1 -CertificateType decides what it makes.
  -DV | -OV | -EV          Level (default: from the request, see WHO SIGNS).          -Classic | -Quantum   Track (default Classic).          -FIPS   FIPS quadrant.
  -Purpose <p>             ServerAuth (default) | ClientAuth | ServerClientAuth | CodeSigning | EmailProtection | TimeStamping | OcspSigning
  -Days <n>                Validity in days (default by level; EV at most 397; cut to what the issuer still has).
  -Name <text>             Name of the output folder and files (default: his CN).
  -OutFolder <path>        Where the per-request folders go (default: .\csr-signed next to the pki folder).
  -AddDevelopmentSAN       merge the development SAN list (DNS, IP, e-mail of [ development_san ]) into the names, like GenerateLeafCertificate.ps1. A request
                           made by New-PkiCsr.ps1 can ask for it itself (a marker name in its SAN); the marker is never put in the certificate. (5.2.2)
  -Policy <oid|cps ...>    Extra policy "OID|CPS-URL" for this certificate.
  -NoCrl -NoOcsp -NoRevocationInfo   leave the CRL distribution point and / or the OCSP URL out of the certificate.
                                     NoCR: with this switch the leaf is signed by the NoCR PKI (latest NoCR release, or -Release N): its CA certificates carry no CRL / OCSP URL either. Without a NoCR PKI the script stops: pki_setup.ps1 -NoCaRevocationInfo -InstallTrust.
  -Check                   Only check the request and print the report; sign nothing.
  -Strict                  Warnings count as errors.
  -NoColor                 Plain text (also when the environment variable NO_COLOR is set).
  -List                    List the earlier requests (csr-signed\signed-csr.tsv) and stop.
  -WriteShellEnv           Write devkit.env next to this script, so that devkit\SignCsr.sh can sign on this PKI too (Linux / WSL), and stop.
  -Unblock                 UNBLOCK and UNLOCK the script folder and the pki folder, then stop.
  -ConfigFile <path> -PkiRoot <path> -OpenSslPath <path> -FipsModuleConfig <path> -Verbose   as in pki_setup.ps1.   -Help   this text.
  -Release <n>         Release of the PKI to use (R1, R2 ...). Default: the LATEST release in .\pki\. A release that no longer exists
                       (deleted) is not an error: the latest release is used and a warning says so.
  -NoCaRevocationInfo  Use the NoCR family (pki\pki-<name>-nocr-<NN>, CA certificates without CRL / OCSP). Default: the normal family (the NoCR one
                       when it is the only one).   -PkiRoot <folder> names one PKI folder and overrides both.

HIS SIDE (he makes the key and the request himself and keeps the key)
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out web01.key
  openssl req -new -key web01.key -sha256 -subj "/CN=web01.dept.example" -addext "subjectAltName=DNS:web01.dept.example" -out web01.csr
  (OV adds /C=EE/ST=Harju/L=Tallinn/O=Dept Ltd ;  EV adds /serialNumber=.../businessCategory=Private Organization/jurisdictionC=EE.)
  Windows without OpenSSL:  certreq -new request.inf web01.csr   (the .inf holds the subject and the SAN)

EXAMPLES
  .\SignCsr.ps1 -Csr .\web01.csr                                    DV, Classic non-FIPS (q1-dv), TLS server
  .\SignCsr.ps1 -Csr .\web01.csr -OV -Purpose ServerClientAuth      OV (q1-ov), server and client authentication
  .\SignCsr.ps1 -Csr .\web01.csr -EV -FIPS -Check                   would q2-ev sign it? print the report only
  .\SignCsr.ps1 -Csr .\sign.csr -OV -Purpose CodeSigning -NoRevocationInfo
  .\SignCsr.ps1 -Csr .\pq.csr -Quantum -OV                          ML-DSA request, quantum quadrant 3 (q3-ov)
  .\SignCsr.ps1 -List
EXIT CODES   0 ok (signed, or -Check passed)   1 error (the message says why)   2 the request does not follow the spec (the report says where)
============================================================

WHICH PKI  (-Pki, 5.0.0)
  -Pki <name>   the company whose PKI is used: the file <name>_pki.cnf next to the scripts. Default: agantra (or DefaultPki of pki_tools.cnf).
                The names: .\pki_setup.ps1 -ListPki  (press Tab after -Pki to see them). Make a new company: .\New-PkiConfig.ps1.
                The PKI folders are .\pki\pki-default-NN (agantra) and .\pki\pki-<name>-NN (NoCR: pki-<name>-nocr-NN).

WHERE IT RUNS  (5.0.0)
  Windows 11 24H2 or newer (Home, Pro, Pro for Workstations, Education, Pro Education, Enterprise), Windows Server 2025 and Windows Server 2022
  (Essentials, Standard, Datacenter; RTM or newer). On Windows Server 2022 only the CLASSIC track is generated or issued (no Quantum / ML-DSA);
  FIPS and non-FIPS, DV / OV / EV are available. REFUSED with an error (exit 5, nothing is done): Windows 10 and earlier, Windows 11 before 24H2,
  Windows Server before 2022, and the Chinese, Government, IoT / IoT Enterprise, SE and Embedded editions. Linux (pwsh): the distributions of the
  .sh scripts. Settings shared by all scripts (optional): pki_tools.cnf.
'@
}

if ($Help) { Show-SignCsrHelp; exit 0 }

# Where may this script run? Windows 11 24H2+ / Server 2025 / Server 2022 (classic only), supported Linux. Error and exit 5 otherwise.
$__pf = Join-Path $PSScriptRoot 'scripts/00a_Platform.ps1'
if (-not (Test-Path -LiteralPath $__pf)) { [Console]::Error.WriteLine('[ERROR] scripts/00a_Platform.ps1 is missing: the operating system cannot be checked. Nothing was done.'); exit 5 }
. $__pf; Assert-PkiPlatform

Write-Host '============================================================'
Write-Host 'Author : Nicko Satria Utama'
Write-Host 'Company: Agantra Inovatif OÜ (NextMantra)'
Write-Host 'Email  : nicko@nextmantra.com'
Write-Host '============================================================'
Write-Host ''

try {
    $PkiModuleSet = 'Library'
    . (Join-Path $script:ScriptRoot 'scripts/PkiModules.ps1')
    if (@($DV, $OV, $EV | Where-Object { $_ }).Count -gt 1) { throw 'Use only one of -DV, -OV and -EV.' }
    if ($Classic -and $Quantum) { throw 'Use only one of -Classic and -Quantum.' }
    $levelGiven = ($EV -or $OV -or $DV)
    $level = if ($EV) { 'EV' } elseif ($OV) { 'OV' } else { 'DV' }
    $quadrant = if ($Quantum) { if ($FIPS) { 4 } else { 3 } } else { if ($FIPS) { 2 } else { 1 } }
    Initialize-PkiConfiguration -ScriptRoot $script:ScriptRoot -Bound $PSBoundParameters -VerboseOutput:([bool]$Verbose)
    if ([bool]$script:Pki.ClassicOnly -and $Quantum) { throw 'This computer is Windows Server 2022: only the CLASSIC track can be issued (Quadrant 1 and 2; FIPS and non-FIPS; DV / OV / EV). The Quantum track (-Quantum, ML-DSA) needs Windows 11 24H2 or newer / Windows Server 2025.' }
    $c = $script:Pki
    if ($Unblock) { [void](Invoke-PkiUnblockUnlock -Path @($script:ScriptRoot, $c.PkiRoot)); exit 0 }
    $outRoot = if ($OutFolder) { $OutFolder } else { Join-Path $c.ScriptRoot 'csr-signed' }
    if ($List) {
        $tsv = Join-Path $outRoot 'signed-csr.tsv'
        if (Test-Path -LiteralPath $tsv) { Get-Content -LiteralPath $tsv | ForEach-Object { Write-Host $_ } } else { Write-PkiLog "No request was signed yet ($outRoot)." 'INFO' }
        exit 0
    }
    if ($WriteShellEnv) {
        Initialize-OpenSSL; [void](Import-PkiExisting)
        $envFile = Join-Path $script:ScriptRoot 'devkit.env'
        Write-PkiDevKitEnv -Path $envFile; [void](ConvertTo-PkiLf -Path $envFile)
        Write-PkiLog "devkit.env written: $envFile  (Linux / WSL:  bash devkit/SignCsr.sh --csr <file> ...)" 'OK'
        exit 0
    }
    if (-not $Csr) { throw '-Csr <file.csr> is required (see -Help).' }
    Initialize-OpenSSL
    [void](Import-PkiExisting)
    if ($c.Quadrants -notcontains $quadrant) { throw "This PKI has no Quadrant $quadrant ($(if ($Quantum) { 'Quantum' } else { 'Classic' })$(if ($FIPS) { ' FIPS' })); it contains: $((($c.Quadrants | ForEach-Object { "Q$_" }) -join ', '))." }
    # no -DV / -OV / -EV: the level follows the request (5.2.2): EV information complete = EV, a company (C + O) = OV, else DV
    $levelReason = ''
    if (-not $levelGiven) {
        $auto = Get-PkiCsrAutoLevel -Csr (Read-PkiCsr -Path $Csr)
        $level = $auto.Level; $levelReason = $auto.Reason
        Write-PkiLog "Level $level, chosen from the request: $levelReason. (-DV, -OV or -EV decide it yourself.)" 'INFO'
    }
    $r = Invoke-PkiSignCsr -Csr $Csr -Level $level -Quadrant $quadrant -Purpose $Purpose -Days $Days -Name $Name -OutRoot $outRoot -CsrType $CsrType `
            -NoCrl:([bool]($NoCrl -or $NoRevocationInfo)) -NoOcsp:([bool]($NoOcsp -or $NoRevocationInfo)) -Strict:$Strict -CheckOnly:$Check -NoColor:$NoColor -Policy $Policy -AddDevelopmentSan:$AddDevelopmentSAN -LevelReason $levelReason
    if ($r.Errors -gt 0 -or ($Strict -and $r.Warnings -gt 0)) { exit 2 }
    if ($r.Signed) {
        Write-PkiLog "Give him the content of $($r.Dir)  (README.txt explains the files)." 'INFO'
        Write-PkiLog 'The issuing CA index.txt changed: New-PkiServerPackage.ps1 + "pki-server.sh update" make OCSP know the new certificate.' 'INFO'
    }
    exit 0
}
catch {
    $failure = $_
    if (-not $Verbose -and $failure.Exception -is [System.Management.Automation.RuntimeException] -and $failure.Exception.GetType().Name -eq 'RuntimeException') {
        Write-Host "[ERROR] $($failure.Exception.Message)" -ForegroundColor Red; exit 1
    }
    if (Get-Command Write-PkiFatalError -ErrorAction SilentlyContinue) {
        try { Write-PkiFatalError -ErrorRecord $failure } catch { Write-Host "[FATAL] $($failure.Exception.Message)" -ForegroundColor Red }
    }
    else { Write-Host "[ERROR] $($failure.Exception.Message)" -ForegroundColor Red }
    exit 1
}
finally { if (Get-Command Clear-PkiSecretEnvironment -ErrorAction SilentlyContinue) { Clear-PkiSecretEnvironment } }
