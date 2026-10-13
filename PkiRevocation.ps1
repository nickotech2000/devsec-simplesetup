# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    CRLs, revocation, OCSP responder certificates and the time stamping certificate of the Agantra Inovatif Enterprise PKI:
    show them, make them, edit (renew) them. Full help: .\PkiRevocation.ps1 -Help     Manual: docs\PkiRevocation-MANUAL.txt
.EXAMPLE
    .\PkiRevocation.ps1 -Action Status
.EXAMPLE
    .\PkiRevocation.ps1 -Action NewOcsp -Ca q1-ev -Replace -OcspDays 180 -OcspKeyBits 3072
#>
param(
    # which company's PKI (default: agantra; names = the *_pki.cnf files next to the scripts; list: .\pki_setup.ps1 -ListPki)
    [Alias('Pki')][ArgumentCompleter({ param($c, $p, $w) $s = (Get-Command $c -ErrorAction SilentlyContinue).Source; $d = if ($s) { Split-Path -Parent $s } else { $PWD.Path }; Get-ChildItem -LiteralPath $d -Filter '*_pki.cnf' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name -replace '_pki\.cnf$', '' } | Where-Object { $_ -like "$w*" } })][string]$PkiProfile,
    [ValidateSet('Status', 'Info', 'NewCrl', 'Revoke', 'NewOcsp', 'NewTsa', 'SignCsr')][string]$Action = 'Status',
    [string[]]$Ca,
    # ---- CRL / revocation ----
    [ValidateRange(1, 3650)][int]$CrlDays,
    [string]$Certificate,
    [string]$Serial,
    [ValidateSet('unspecified', 'keyCompromise', 'CACompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation', 'certificateHold')][string]$Reason = 'unspecified',
    [switch]$NoCrl,
    # ---- OCSP responder / time stamping certificates (edit = change a value and add -Replace) ----
    [ValidateRange(1, 3650)][int]$OcspDays,
    [ValidateSet(2048, 3072, 4096)][int]$OcspKeyBits,
    [ValidateSet('RSA', 'ECDSA')][string]$KeyType,
    [string]$CommonName,
    [switch]$Replace,
    [switch]$RevokeOld,
    [ValidateSet('DV', 'OV', 'EV')][string]$Level = 'EV',
    [ValidateSet(1, 2, 3, 4)][int]$TimestampQuadrant,
    [string]$TimestampPolicyOid,
    [ValidateRange(1, 36500)][int]$TimestampDays,
    # ---- CSR made on the server ----
    [string]$Csr,
    [ValidateSet('Ocsp', 'Tsa')][string]$For,
    [int]$Days,
    [string]$OutFolder,
    # ---- common ----
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

function Show-PkiRevocationHelp {
    @'
============================================================
 PkiRevocation.ps1 - CRL, OCSP and time stamping certificates of the Agantra Inovatif Enterprise PKI
 Version 5.2.6
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : docs\PkiRevocation-MANUAL.txt     Server: docs\PKI-SERVER-MANUAL.txt     Design: docs\PKI-Server-Design.txt
 Needs  : PowerShell 7+, OpenSSL 4.x (see Install-DevEnvironment.ps1) and a PKI made by pki_setup.ps1.

WHAT IT DOES
  pki_setup.ps1 already makes, with the PKI:   one OCSP responder certificate per Classic intermediate CA  (pki\ocsp\<ca>\),
  one time stamping certificate (pki\pki-<name>-<NN>\tsa\<ca>\), the CRLs (pki\pki-<name>-<NN>\publish\) and pki\pki-<name>-<NN>\revocation-info.json / REVOCATION-INFO.txt.
  This script SHOWS them and lets you EDIT them. A certificate cannot be edited: "edit" = change a value and issue it again
  (-Replace archives the old one to old-<date>\), and for a CRL = make a new CRL (new number, new validity).

ACTIONS   (-Action <name>)
  Status      Table: per CA the CRL number, next update, days left, revoked/issued, and the OCSP responder. (default)
  Info        Status + writes pki\pki-<name>-<NN>\revocation-info.json and REVOCATION-INFO.txt (URLs, dates, how to renew) and the server\ folder
              (server-info.json, ca-list.tsv, server.env, expected-urls.tsv, DNS-RECORDS.txt) that pki-server.sh reads. Every action refreshes them.
  NewCrl      New CRL of the CA(s) (-Ca q1-ev,q1-ov ; default every CA) and publish it. -CrlDays N = its validity (default 365,
              agantra_pki.cnf [ revocation ] CrlDays).    Do it BEFORE the old CRL ends (Status shows the days left).
  Revoke      Revoke an issued certificate:  -Certificate <file.crt>   or  -Serial <hex> -Ca <issuing CA>.
              -Reason unspecified|keyCompromise|CACompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold
              The new CRL of that CA is made at once (-NoCrl: not). The OCSP server follows the index.txt of the CA.
  NewOcsp     OCSP responder certificate for the CA(s) (-Ca; default every Classic intermediate). Exists already: skipped.
              EDIT: -Replace (+ -OcspDays N, -OcspKeyBits 2048|3072|4096, -KeyType RSA|ECDSA, -CommonName "...") issues a new one;
              -RevokeOld also revokes the old one (superseded). Files: pki\ocsp\<ca>\<ca>-ocsp.crt .key .pub -fullchain.crt ocsp-info.json
  NewTsa      The time stamping certificate (RFC 3161), in pki\tsa\<ca>\. -Level EV|OV|DV (default EV). EDIT: -Replace with
              -TimestampDays, -TimestampPolicyOid, -TimestampQuadrant, -CommonName, -KeyType, -OcspKeyBits(key size).
  SignCsr     Sign the CSR of an OCSP responder / time stamp server made ON THE SERVER (the key never leaves it):
              -Csr <file.csr> -For Ocsp|Tsa -Ca <issuing CA> [-Days N] [-OutFolder <folder>]    -> <name>.crt + -fullchain.crt

TIME STAMPING CERTIFICATE (no special certificate is needed)
  It is the normal leaf with the purpose TimeStamping: extended key usage timeStamping, CRITICAL and alone (RFC 3161). Defaults:
  Classic non-FIPS (Quadrant 1), RSA 2048, valid 1825 days (a time stamp must stay verifiable for years), policy OID
  1.3.6.1.4.1.<PEN>.<arc>.4 (your IANA PEN) unless -TimestampPolicyOid / [ timestamp ] PolicyOid say otherwise.
  -TimestampQuadrant 2|3|4 prepares FIPS / quantum time stamping; the PKI server kit signs with RSA / ECDSA only.

OPTIONS
  -Ca <ids>             CA id(s): q1-ev, q1-ov, q1-dv, q2-ev ... (intermediates) or any CA for -Action NewCrl.
  -OcspDays N           Validity of an OCSP responder certificate (default 365, [ revocation ] OcspDays).
  -Unblock              UNBLOCK and UNLOCK the script folder and the pki folder, children and recursive, then stop.
  -ConfigFile <path>    agantra_pki.cnf (default next to the script).    -PkiRoot <path>   The PKI folder (default: the latest release in .\pki\).
  -Release <n>         Release of the PKI to use (R1, R2 ...). Default: the LATEST release in .\pki\. A release that no longer exists
                       (deleted) is not an error: the latest release is used and a warning says so.
  -NoCaRevocationInfo  Use the NoCR family (pki\pki-<name>-nocr-<NN>, CA certificates without CRL / OCSP). Default: the normal family (the NoCR one
                       when it is the only one).   -PkiRoot <folder> names one PKI folder and overrides both.
  -OpenSslPath <path>   openssl 4.x.   -FipsModuleConfig <path>   fipsmodule.cnf.   -Verbose   Every OpenSSL command.   -Help   This text.

AFTER A CHANGE
  The server only knows what you copied to it: run  .\New-PkiServerPackage.ps1  and  sudo ./pki-server.sh update  (new CRL, new
  index.txt, new responder certificates). Certificates carry the CRL / OCSP URLs of agantra_pki.cnf at the time they were issued.

EXAMPLES
  .\PkiRevocation.ps1                                        status of every CRL and responder
  .\PkiRevocation.ps1 -Action NewCrl -CrlDays 90             new 90-day CRL for every CA
  .\PkiRevocation.ps1 -Action Revoke -Certificate leafcerts\site\serverauth\site-server-ev-q1-rsa2048.crt -Reason keyCompromise
  .\PkiRevocation.ps1 -Action NewOcsp -Ca q1-ev -Replace -OcspKeyBits 3072 -OcspDays 180 -RevokeOld
  .\PkiRevocation.ps1 -Action NewTsa -Replace -TimestampDays 3650 -TimestampPolicyOid 1.3.6.1.4.1.67096.1.4
  .\PkiRevocation.ps1 -Action SignCsr -Csr .\ocsp-q1-ev.csr -For Ocsp -Ca q1-ev

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

if ($Help) { Show-PkiRevocationHelp; exit 0 }

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

try {
    $PkiModuleSet = 'Library'
    . (Join-Path $script:ScriptRoot 'scripts/PkiModules.ps1')
    Initialize-PkiConfiguration -ScriptRoot $script:ScriptRoot -Bound $PSBoundParameters -VerboseOutput:([bool]$Verbose)
    $c = $script:Pki
    if ($Unblock) {
        Write-PkiLog "UNBLOCK + UNLOCK (children and recursive); the start-up bootstrap unlocked $($script:BootstrapUnlocked) item(s)."
        [void](Invoke-PkiUnblockUnlock -Path @($script:ScriptRoot, $c.PkiRoot)); exit 0
    }
    Initialize-OpenSSL
    [void](Import-PkiExisting)
    Write-PkiLog "PKI: $($c.PkiRoot)   OpenSSL: $($c.OpenSslVersion.Split([char]40)[0].Trim())"

    switch ($Action) {
        'Status' { Show-PkiRevocationStatus -Status (Get-PkiRevocationStatus) }
        'Info' { $st = Write-PkiRevocationInfo; Show-PkiRevocationStatus -Status $st }
        'NewCrl' {
            foreach ($a in (Get-PkiRevocationCas -Id $Ca)) { Update-PkiCrl -Ca $a -Days $CrlDays }
            [void](Write-PkiRevocationInfo)
            Write-PkiLog 'Copy the pki folder to the server again (New-PkiServerPackage.ps1) and run "sudo ./pki-server.sh update".' 'INFO'
        }
        'Revoke' {
            $a = Revoke-PkiCertificate -CertificateFile $Certificate -Serial $Serial -CaId ($Ca | Select-Object -First 1) -Reason $Reason -NoCrl:$NoCrl -CrlDays $CrlDays
            [void](Write-PkiRevocationInfo)
            Write-PkiLog "Revoked. Copy the pki folder to the server again (New-PkiServerPackage.ps1) and run 'sudo ./pki-server.sh update': the OCSP answer follows the index.txt." 'INFO'
        }
        'NewOcsp' {
            $targets = @(Get-PkiRevocationCas -Id $Ca -IssuingOnly -ClassicOnly)
            if ($targets.Count -eq 0) { throw 'No Classic intermediate CA selected (-Ca q1-ev ...).' }
            $madeCount = 0
            foreach ($target in $targets) {
                $res = New-PkiServiceCertificate -Kind Ocsp -Ca $target -Days $OcspDays -KeyBits $OcspKeyBits -KeyType $KeyType -CommonName $CommonName -Replace:$Replace -RevokeOld:$RevokeOld
                if ($res.Status -eq 'created') { $madeCount++ }
            }
            [void](Write-PkiRevocationInfo)
            Write-PkiLog "$madeCount OCSP responder certificate(s) made. Then: New-PkiServerPackage.ps1 and 'sudo ./pki-server.sh update'." 'OK'
        }
        'NewTsa' {
            $r = New-PkiServiceCertificate -Kind Tsa -Level $Level -Days $TimestampDays -KeyBits $OcspKeyBits -KeyType $KeyType -CommonName $CommonName -Replace:$Replace -RevokeOld:$RevokeOld
            [void](Write-PkiRevocationInfo)
            Write-PkiLog "Time stamping certificate: $($r.Dir)  ($($r.Status))" 'OK'
        }
        'SignCsr' {
            if (-not $Csr -or -not $For -or -not $Ca) { throw '-Action SignCsr needs -Csr <file>, -For Ocsp|Tsa and -Ca <issuing CA>.' }
            $a = @(Get-PkiRevocationCas -Id @($Ca | Select-Object -First 1))[0]
            $out = Invoke-PkiSignServiceCsr -Csr $Csr -Kind $For -Ca $a -Days $Days -OutFolder $OutFolder
            Write-PkiLog "Copy $out and its -fullchain.crt back to the server:  sudo ./pki-server.sh import-cert <file>" 'INFO'
        }
    }
    exit 0
}
catch {
    $failure = $_
    if (Get-Command Write-PkiFatalError -ErrorAction SilentlyContinue) {
        try { Write-PkiFatalError -ErrorRecord $failure } catch { Write-Host "[FATAL] $($failure.Exception.Message)" -ForegroundColor Red }
    }
    else { Write-Host "[ERROR] $($failure.Exception.Message)" -ForegroundColor Red }
    exit 1
}
finally { if (Get-Command Clear-PkiSecretEnvironment -ErrorAction SilentlyContinue) { Clear-PkiSecretEnvironment } }
