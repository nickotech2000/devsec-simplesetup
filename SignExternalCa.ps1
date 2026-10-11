# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Signs the CSR of ANOTHER private CA with our intermediate (default) or our Quadrant Root, and writes his CSR, his signed certificate
    and our full chain into a NEW folder for this request. Full help: .\SignExternalCa.ps1 -Help     Manual: SignExternalCa-MANUAL.txt
.EXAMPLE
    .\SignExternalCa.ps1 -Csr D:\partner\partner-ca.csr
.EXAMPLE
    .\SignExternalCa.ps1 -Csr .\sub-ca.csr -Days 1825 -PermitDns partner.example
#>
param(
    [string]$Csr,
    [string]$Name,
    [ValidateSet('Intermediate', 'QuadrantRoot')][string]$SignWith = 'QuadrantRoot',
    [ValidateSet(1, 2, 3, 4)][int]$Quadrant = 1,
    [ValidateSet('DV', 'OV', 'EV')][string]$Level = 'OV',
    [string]$Ca,
    [ValidateRange(1, 36500)][int]$Days = 1825,
    [ValidateRange(0, 3)][int]$PathLen = 0,
    [string[]]$PermitDns,
    [string[]]$PermitEmail,
    [string]$OutFolder,
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
 SignExternalCa.ps1 - sign the CA certificate of ANOTHER private CA with our PKI
 Version 4.9.4-phaseC
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : SignExternalCa-MANUAL.txt     Design : PKI-Design-with-FIPS-and-PQC.txt (10.58)
 Needs  : PowerShell 7+, OpenSSL 4.x, a PKI made by pki_setup.ps1.

WHAT IT DOES
  Another organization (or another private CA of yours) has made its own CA key and a CSR. This script signs that CSR with our CA, so that
  everything that CA issues chains to OUR Enterprise Root. Nothing but the CSR comes in; no private key of ours goes out.
  Every request gets a NEW folder (never overwritten):
      external-ca\<name>_<yyyyMMdd-HHmmss>\
          <name>.csr            his request, unchanged (LF)
          <name>.crt            HIS CA CERTIFICATE, signed by us
          <name>-fullchain.crt  his certificate + our chain (up to, not including, the Enterprise Root): the chain for HIS usage
          <name>-chain.crt      our chain only          root.crt   our Enterprise Root (the trust anchor)   our-ca-bundle.crt   chain + root
          ca-info.json  README.txt   the facts: signer, subject, key, dates, serial, fingerprint, constraints, verification result
  The certificate is recorded in the index.txt of the signing CA: revoke it with PkiRevocation.ps1 -Action Revoke and it is in the CRL.

WHO SIGNS
  -SignWith QuadrantRoot   (default) our Quadrant Root of -Quadrant (default 1 = Classic, non-FIPS)                = q1-root
  -SignWith Intermediate   our DV / OV / EV intermediate of -Quadrant and -Level (default OV)                      = q1-ov
  -Quadrant 1|2|3|4        1 Classic non-FIPS (default), 2 Classic FIPS, 3 Quantum non-FIPS, 4 Quantum FIPS
  -Ca <id>                 a CA by id (q2-ev, q1-root ...); replaces the three options above
  The Enterprise Root and the Track Roots are never used: they stay offline.

  IMPORTANT - PATH LENGTH.  Our intermediates are built with pathLenConstraint 0: they may issue end-entity certificates only. A CA below
  them is rejected by OpenSSL, Windows and browsers ("path length constraint exceeded"). The Quadrant Roots have pathLenConstraint 1: a CA
  signed by one is a sibling of our intermediates and VALID - that is why the default signer is the Classic non-FIPS Quadrant Root (q1-root).
  With -SignWith Intermediate the script STOPS and tells you what to do:
     * leave -SignWith at its default (QuadrantRoot)
     * build the PKI with  pki_setup.ps1 -IntermediatePathLen 1  (or [ pki_setup ] IntermediatePathLen = 1) to let the intermediates sign CAs
     * -Force   issue it anyway (lab, or the other CA is only a trust anchor): README.txt says "NO" under "Valid below a pathLen-0 signer"

OPTIONS
  -Csr <file>            His PKCS#10 request (PEM). The signature is verified (SHA-256 or stronger; SHA-1 / MD5 refused). MINIMUM KEY, equal strength:
                         RSA 4096 | ECDSA P-384 or P-521 | ML-DSA-65 or -87. Anything weaker is refused. A request that uses the name of one of
                         OUR CAs is refused. Our signature on his certificate: SHA-384 (Quadrant Root) or SHA-256+ (intermediate).
  -Name <text>           Name of the output folder and files (default: his CN).
  -Level DV|OV|EV        Policy level written into his certificate (our CA/B Forum + PEN policies of that level). Default OV.
  -Days <n>              Validity (default 1825 = 5 years), cut to what the signer still has.
  -PathLen 0..3          pathLenConstraint of HIS certificate (default 0: he issues end-entity certificates only). Limited to signer's pathLen - 1.
  -PermitDns <a,b>       Name constraint (critical): he may issue only for these DNS names and their sub-domains (example.internal).
  -PermitEmail <a,b>     Name constraint: only these e-mail addresses / domains (@example.internal).
  -OutFolder <path>      Where the per-request folders go (default: .\external-ca next to the pki folder).
  -Force                 See PATH LENGTH.
  -List                  List the earlier requests (folders, signer, serial, dates) and stop.
  -Unblock               UNBLOCK and UNLOCK the script folder and the pki folder, then stop.
  -ConfigFile <path> -PkiRoot <path> -OpenSslPath <path> -FipsModuleConfig <path> -Verbose   as in pki_setup.ps1.   -Help   this text.

THE OTHER SIDE (he makes the key and the CSR himself, for example)
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out partner-ca.key
  openssl req -new -key partner-ca.key -sha384 -subj "/C=EE/O=Partner OU/CN=Partner Issuing CA G1" -out partner-ca.csr
  He keeps partner-ca.key. He sends only partner-ca.csr and gets back the folder content.

EXAMPLES
  .\SignExternalCa.ps1 -Csr .\partner-ca.csr                       (signed by q1-root: Classic, non-FIPS)
  .\SignExternalCa.ps1 -Csr .\partner-ca.csr -SignWith Intermediate -Level OV
  .\SignExternalCa.ps1 -Csr .\partner-ca.csr -Ca q2-root -Level OV -PermitDns partner.internal -Days 3650
  .\SignExternalCa.ps1 -List
EXIT CODES   0 ok   1 error (the message says why)
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
        if ($rows) { $rows | Format-Table -AutoSize | Out-String | Write-Host } else { Write-PkiLog "No external CA was signed yet ($outRoot)." 'INFO' }
        exit 0
    }
    if (-not $Csr) { throw '-Csr <file.csr> is required (see -Help).' }
    Initialize-OpenSSL
    [void](Import-PkiExisting)
    $signer = Get-PkiExternalCaSigner -CaId $Ca -SignWith $SignWith -Quadrant $Quadrant -Level $Level
    Write-PkiLog "Signer: $($signer.Id) ($($signer.Kind))   OpenSSL: $($c.OpenSslVersion.Split([char]40)[0].Trim())" 'INFO'
    $r = Invoke-PkiSignExternalCa -Csr $Csr -Signer $signer -Name $Name -Level $Level -Days $Days -PathLen $PathLen -PermitDns $PermitDns -PermitEmail $PermitEmail -OutRoot $outRoot -Force:$Force
    Write-PkiLog "Give him the content of $($r.Dir)  (the .crt, -fullchain.crt and root.crt; the README.txt explains them)." 'INFO'
    Write-PkiLog 'The signer index.txt changed: New-PkiServerPackage.ps1 + "pki-server.sh update" make OCSP know the new certificate.' 'INFO'
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
