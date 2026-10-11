# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Signs the CSR of a CA of ANOTHER department (or organization) with our Classic Quadrant Root (q1-root, or q2-root with -Fips), after checking
    the request against the spec of this PKI, and writes his CSR, his signed CA certificate and our chain into a NEW folder. Full help: .\SignExternalCa.ps1 -Help     Manual: docs\SignExternalCa-MANUAL.txt
.EXAMPLE
    .\SignExternalCa.ps1 -Csr D:\partner\partner-ca.csr
.EXAMPLE
    .\SignExternalCa.ps1 -Csr .\sub-ca.csr -Level OV -Days 1825 -PermitDns partner.example
#>
param(
    [string]$Csr,
    [string]$Name,
    [ValidateSet(1, 2)][int]$Quadrant = 1,
    [switch]$Fips,
    [ValidateSet('DV', 'OV', 'EV')][string]$Level = 'OV',
    [ValidateRange(1, 36500)][int]$Days,
    [ValidateRange(0, 3)][int]$PathLen = 0,
    [string[]]$PermitDns,
    [string[]]$PermitEmail,
    [string]$OutFolder,
    [switch]$Check,
    [switch]$Strict,
    [switch]$NoColor,
    [switch]$Force,
    [switch]$List,
    [switch]$Unblock,
    [switch]$Help,
    [switch]$Verbose,
    [string]$ConfigFile,
    [string]$PkiRoot,
    [string]$OpenSslPath,
    [string]$FipsModuleConfig
)

$ErrorActionPreference = 'Stop'
$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Show-SignExternalCaHelp {
    @'
============================================================
 SignExternalCa.ps1 - sign the CA certificate of a department (or another organization) with our Quadrant Root
 Version 4.9.5-phaseC
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : docs\SignExternalCa-MANUAL.txt     Design : docs\PKI-Design-with-FIPS-and-PQC.txt (10.58, 10.73)
 Needs  : PowerShell 7+, OpenSSL 4.x, the ORIGINAL PKI made by pki_setup.ps1 (a DevKit has no Quadrant Root key and can not do this).
 A leaf (server, person ...) request is a different job: SignCsr.ps1.

WHAT IT DOES
  A department has made its own CA key and a CSR and sends you only the CSR. This script
    1. CHECKS the request against the specification of this PKI (colour report: red ERROR, yellow WARN, green OK, cyan INFO; every finding says
       why and how to fix it); an ERROR means nothing is signed (exit code 2),
    2. signs it with our Classic QUADRANT ROOT, so that everything his CA issues chains to OUR Enterprise Root,
    3. writes a NEW folder (never overwritten):
          external-ca\<name>_<yyyyMMdd-HHmmss>\
              <name>.csr            his request, unchanged (LF)
              <name>.crt            HIS CA CERTIFICATE, signed by us
              <name>-fullchain.crt  his certificate + our chain (up to, not including, the Enterprise Root): the chain for HIS certificates
              <name>-chain.crt      our chain only          root.crt   our Enterprise Root (the trust anchor)   our-ca-bundle.crt   chain + root
              ca-info.json  README.txt   the facts: signer, subject, key, dates, serial, fingerprint, constraints, verification result
  The certificate is recorded in the index.txt of the signing root: revoke it with PkiRevocation.ps1 -Action Revoke and it is in the CRL.
  Nothing but the CSR comes in; no private key of ours goes out.

WHO SIGNS - ONLY A CLASSIC QUADRANT ROOT
  (default)  q1-root   Classic, non-FIPS (Quadrant 1)
  -Fips      q2-root   Classic, FIPS (Quadrant 2).     -Quadrant 1|2 does the same by number.
  Never an intermediate, never a Quantum Quadrant Root, never the Track or Enterprise Root: they sign our own CAs only. The DevKit holds
  issuing keys only: a request for a CA certificate can ONLY be signed here, on the original PKI. (pathLenConstraint: a Quadrant Root has 1,
  so his CA is a sibling of our intermediates and may issue end-entity certificates only - pathLen 0 - unless you raise -PathLen.)

THE LEVEL OF HIS CA (-Level, default OV) AND WHAT HIS REQUEST MUST CONTAIN
  OV (default)  subject C (2 letters), O, OU and CN are REQUIRED, otherwise the request is rejected. ST and L are recommended.
                Allowed: street, postalCode, name, emailAddress, telephoneNumber.   Policies: OV + High Assurance + PEN.
  EV            everything of OV, plus ST, L, serialNumber, businessCategory (Private Organization | Government Entity | Business Entity |
                Non-Commercial Entity) and jurisdictionC. Recommended: jurisdictionST, postalCode. Validity 397 days at most.
  DV            CN required; any other field is dropped from the certificate (WARN).
  Key           RSA 4096 or 8192, or ECDSA P-384 / P-521 (equal strength; P-256, RSA 2048/3072, Ed25519, ML-DSA are rejected - this is a
                Classic CA). The signature of the request must be valid and SHA-256 or stronger. A request that uses the CN of one of OUR CAs is refused.

OPTIONS
  -Csr <file>            His PKCS#10 request (PEM).
  -Level DV|OV|EV        Level written into his certificate (default OV).          -Fips   sign with q2-root (Classic FIPS).
  -Name <text>           Name of the output folder and files (default: his CN).
  -Days <n>              Validity (default 1825 = 5 years; EV 397, EV may not be longer), cut to what the signer still has.
  -PathLen 0..3          pathLenConstraint of HIS certificate (default 0). Limited to the signer's pathLen - 1.
  -PermitDns <a,b>       Name constraint (critical): he may issue only for these DNS names and their sub-domains (example.internal).
  -PermitEmail <a,b>     Name constraint: only these e-mail addresses / domains (@example.internal).
  -OutFolder <path>      Where the per-request folders go (default: .\external-ca next to the pki folder).
  -Check                 Check the request and print the report; sign nothing.         -Strict   warnings count as errors.
  -NoColor               Plain text (also when the environment variable NO_COLOR is set).
  -Force                 Issue even when the signer has pathLenConstraint 0 (lab only).
  -List                  List the earlier requests (folders, signer, serial, dates) and stop.
  -Unblock               UNBLOCK and UNLOCK the script folder and the pki folder, then stop.
  -ConfigFile <path> -PkiRoot <path> -OpenSslPath <path> -FipsModuleConfig <path> -Verbose   as in pki_setup.ps1.   -Help   this text.

THE OTHER SIDE (he makes the key and the CSR himself, for example)
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out dept-ca.key
  openssl req -new -key dept-ca.key -sha384 -subj "/C=EE/ST=Harju/L=Tallinn/O=Dept Ltd/OU=IT Department/CN=Dept Issuing CA G1" -out dept-ca.csr
  (EV adds  /serialNumber=12345678/businessCategory=Private Organization/jurisdictionC=EE )
  He keeps dept-ca.key. He sends only dept-ca.csr and gets back the folder content.

EXAMPLES
  .\SignExternalCa.ps1 -Csr .\dept-ca.csr                         OV, signed by q1-root (Classic, non-FIPS)
  .\SignExternalCa.ps1 -Csr .\dept-ca.csr -Fips -PermitDns dept.internal -Days 3650
  .\SignExternalCa.ps1 -Csr .\dept-ca.csr -Level EV -Check        would an EV CA be accepted? report only
  .\SignExternalCa.ps1 -List
EXIT CODES   0 ok (signed, or -Check passed)   1 error (the message says why)   2 the request does not follow the spec (the report says where)
============================================================
'@
}

if ($Help) { Show-SignExternalCaHelp; exit 0 }

Write-Host '============================================================'
Write-Host 'Author : Nicko Satria Utama'
Write-Host 'Company: Agantra Inovatif OÜ (NextMantra)'
Write-Host 'Email  : nicko@nextmantra.com'
Write-Host '============================================================'
Write-Host ''

try {
    $PkiModuleSet = 'Library'
    . (Join-Path $script:ScriptRoot 'scripts/PkiModules.ps1')
    Initialize-PkiConfiguration -ScriptRoot $script:ScriptRoot -Bound $PSBoundParameters -VerboseOutput:([bool]$Verbose)
    $c = $script:Pki
    if ($Unblock) { [void](Invoke-PkiUnblockUnlock -Path @($script:ScriptRoot, $c.PkiRoot)); exit 0 }
    $outRoot = if ($OutFolder) { $OutFolder } else { Join-Path (Split-Path -Parent $c.PkiRoot) 'external-ca' }
    if ($List) {
        $rows = foreach ($f in @(Get-ChildItem -LiteralPath $outRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name)) {
            $j = Join-Path $f.FullName 'ca-info.json'
            if (Test-Path -LiteralPath $j) { $i = Get-Content -LiteralPath $j -Raw | ConvertFrom-Json; [pscustomobject]@{ Folder = $f.Name; Signer = $i.signer; Key = $i.keyAlgorithm; Until = $i.notAfter; Serial = $i.serial } }
        }
        if ($rows) { Write-Host ('{0,-44} {1,-9} {2,-11} {3,-26} {4}' -f 'FOLDER', 'SIGNER', 'KEY', 'VALID UNTIL', 'SERIAL'); foreach ($r in $rows) { Write-Host ('{0,-44} {1,-9} {2,-11} {3,-26} {4}' -f $r.Folder, $r.Signer, $r.Key, $r.Until, $r.Serial) } } else { Write-PkiLog "No external CA was signed yet ($outRoot)." 'INFO' }
        exit 0
    }
    if (-not $Csr) { throw '-Csr <file.csr> is required (see -Help).' }
    Initialize-OpenSSL
    [void](Import-PkiExisting)
    if ($Fips) { $Quadrant = 2 }
    $signer = Get-PkiExternalCaSigner -Quadrant $Quadrant
    Write-PkiLog "Signer: $($signer.Id) ($($signer.Kind))   OpenSSL: $($c.OpenSslVersion.Split([char]40)[0].Trim())" 'INFO'
    $daysEff = if ($Days) { $Days } elseif ($Level -eq 'EV') { 397 } else { 1825 }
    $r = Invoke-PkiSignExternalCa -Csr $Csr -Signer $signer -Name $Name -Level $Level -Days $daysEff -DaysAsked $Days -PathLen $PathLen -PermitDns $PermitDns -PermitEmail $PermitEmail -OutRoot $outRoot `
            -Force:$Force -Strict:$Strict -CheckOnly:$Check -NoColor:$NoColor
    if ($r.Errors -gt 0 -or ($Strict -and $r.Warnings -gt 0)) { exit 2 }
    if ($r.Signed) {
        Write-PkiLog "Give him the content of $($r.Dir)  (the .crt, -fullchain.crt and root.crt; the README.txt explains them)." 'INFO'
        Write-PkiLog 'The signer index.txt changed: New-PkiServerPackage.ps1 + "pki-server.sh update" make OCSP know the new certificate.' 'INFO'
    }
    exit 0
}
catch {
    $failure = $_
    if (-not $Verbose -and $failure.Exception -is [System.Management.Automation.RuntimeException] -and $failure.Exception.GetType().Name -eq 'RuntimeException') {
        Write-Host "[ERROR] $($failure.Exception.Message)" -ForegroundColor Red; exit 1      # a message written for the person (path length, bad CSR ...)
    }
    if (Get-Command Write-PkiFatalError -ErrorAction SilentlyContinue) {
        try { Write-PkiFatalError -ErrorRecord $failure } catch { Write-Host "[FATAL] $($failure.Exception.Message)" -ForegroundColor Red }
    }
    else { Write-Host "[ERROR] $($failure.Exception.Message)" -ForegroundColor Red }
    exit 1
}
finally { if (Get-Command Clear-PkiSecretEnvironment -ErrorAction SilentlyContinue) { Clear-PkiSecretEnvironment } }
