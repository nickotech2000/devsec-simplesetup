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
    [string]$Csr,
    # ---- level and quadrant (default: -DV, -Classic, non-FIPS) ----
    [switch]$DV,
    [switch]$OV,
    [switch]$EV,
    [switch]$Classic,
    [switch]$Quantum,
    [switch]$FIPS,
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
 Version 4.9.5-phaseC
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
  -DV (default) | -OV | -EV        the level. DV = domain only, OV = organization, EV = extended validation
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
  Ignored    keyUsage, extendedKeyUsage, policies, CRL / OCSP URLs asked for in the request: THIS PKI sets them (from -Purpose and -Level).
             A request for CA:TRUE is refused.   Policies: the level policy, the PEN policies and the High Assurance policy (OV), as for any leaf.

OPTIONS
  -Csr <file>              His request (PEM).
  -DV | -OV | -EV          Level (default DV).          -Classic | -Quantum   Track (default Classic).          -FIPS   FIPS quadrant.
  -Purpose <p>             ServerAuth (default) | ClientAuth | ServerClientAuth | CodeSigning | EmailProtection | TimeStamping | OcspSigning
  -Days <n>                Validity in days (default by level; EV at most 397; cut to what the issuer still has).
  -Name <text>             Name of the output folder and files (default: his CN).
  -OutFolder <path>        Where the per-request folders go (default: .\csr-signed next to the pki folder).
  -Policy <oid|cps ...>    Extra policy "OID|CPS-URL" for this certificate.
  -NoCrl -NoOcsp -NoRevocationInfo   leave the CRL distribution point and / or the OCSP URL out of the certificate.
  -Check                   Only check the request and print the report; sign nothing.
  -Strict                  Warnings count as errors.
  -NoColor                 Plain text (also when the environment variable NO_COLOR is set).
  -List                    List the earlier requests (csr-signed\signed-csr.tsv) and stop.
  -WriteShellEnv           Write devkit.env next to this script, so that devkit\SignCsr.sh can sign on this PKI too (Linux / WSL), and stop.
  -Unblock                 UNBLOCK and UNLOCK the script folder and the pki folder, then stop.
  -ConfigFile <path> -PkiRoot <path> -OpenSslPath <path> -FipsModuleConfig <path> -Verbose   as in pki_setup.ps1.   -Help   this text.
  -Release <n>         Release of the PKI to use (R1, R2 ...). Default: the LATEST release in .\pki\. A release that no longer exists
                       (deleted) is not an error: the latest release is used and a warning says so.
  -NoCaRevocationInfo  Use the NoCR family (pki\NoCR-R<n>, CA certificates without CRL / OCSP). Default: the normal family (the NoCR one
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
'@
}

if ($Help) { Show-SignCsrHelp; exit 0 }

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
    $level = if ($EV) { 'EV' } elseif ($OV) { 'OV' } else { 'DV' }
    $quadrant = if ($Quantum) { if ($FIPS) { 4 } else { 3 } } else { if ($FIPS) { 2 } else { 1 } }
    Initialize-PkiConfiguration -ScriptRoot $script:ScriptRoot -Bound $PSBoundParameters -VerboseOutput:([bool]$Verbose)
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
    $r = Invoke-PkiSignCsr -Csr $Csr -Level $level -Quadrant $quadrant -Purpose $Purpose -Days $Days -Name $Name -OutRoot $outRoot `
            -NoCrl:([bool]($NoCrl -or $NoRevocationInfo)) -NoOcsp:([bool]($NoOcsp -or $NoRevocationInfo)) -Strict:$Strict -CheckOnly:$Check -NoColor:$NoColor -Policy $Policy
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
