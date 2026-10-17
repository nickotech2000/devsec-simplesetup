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
====================================================================================================
 PkiRevocation.ps1  -  revoke certificates, make CRLs, OCSP and time stamp certificates
 Version 6.4.7
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
====================================================================================================
 On a terminal: SPACE = next page, ENTER = next line, Q = quit.
 Manual : docs\PkiRevocation-MANUAL.txt    Server: docs\PKI-SERVER-MANUAL.txt
 Needs  : PowerShell 7+, OpenSSL 4.x, and a PKI made by pki_setup.ps1.

WHAT IT IS
  A certificate can become bad before its end date: a key is stolen, a person leaves. Clients must
  learn this. Your PKI tells them in two ways:
    CRL   a signed list of the revoked certificates of one CA. Clients download it.
    OCSP  a small server that answers "is this certificate still good?". It has its own
          certificate, the OCSP responder certificate.
  This script shows these things, makes them again, and revokes a certificate.
  pki_setup.ps1 already makes them when it builds the PKI, so you only come here later.

QUICK START
  See the state of everything:          .\PkiRevocation.ps1
  Revoke a certificate:                 .\PkiRevocation.ps1 -Action Revoke -Certificate x.crt
  Make a new CRL before the old ends:   .\PkiRevocation.ps1 -Action NewCrl
  After any change copy the PKI to the server again (see AFTER A CHANGE).

ACTIONS   (-Action <name>)
  Status    Default. A table: per CA the CRL number, the next update, the days left, revoked /
            issued, and the OCSP responder. Look at "days left" often.
  Info      Status, and it rewrites pki\pki-<name>-<NN>\revocation-info.json and
            REVOCATION-INFO.txt (URLs, dates, how to renew) and the server\ folder that
            pki-server.sh reads. Every other action does this too.
  NewCrl    Make a new CRL for the CA(s) and publish it. -Ca q1-ev,q1-ov (default: every CA).
            -CrlDays N is its validity (default 365). Do it BEFORE the old CRL ends.
  Revoke    Revoke one issued certificate. Name it with -Certificate <file.crt>, or with
            -Serial <hex> -Ca <issuing CA>. Add -Reason (below). A new CRL of that CA is made at
            once (-NoCrl: not now). The OCSP server follows the index.txt of the CA.
  NewOcsp   Make the OCSP responder certificate for the CA(s) (-Ca; default every Classic
            intermediate). One that exists is skipped. To change one, add -Replace.
  NewTsa    Make the time stamp certificate (RFC 3161) in pki\tsa\<ca>\. -Level EV|OV|DV
            (default EV). To change it, add -Replace.
  SignCsr   Sign the CSR of an OCSP responder or time stamp server whose key was made ON THE
            SERVER. The key never leaves the server:
            -Csr <file.csr> -For Ocsp|Tsa -Ca <issuing CA> [-Days N] [-OutFolder <folder>]

REVOKE REASONS   (-Reason)
  unspecified (default)   keyCompromise   CACompromise   affiliationChanged   superseded
  cessationOfOperation    certificateHold
  If the private key is stolen, use keyCompromise. A revoked certificate stays revoked.

CHANGE A CERTIFICATE  (a certificate cannot be edited; you issue it again)
  -Replace      Issue a new one. The old files move to old-<date>\.
  -RevokeOld    Also revoke the old certificate (reason superseded) and make a new CRL.
  OCSP:  -Action NewOcsp -Ca q1-ev -Replace -OcspDays 180 -OcspKeyBits 3072 -KeyType RSA|ECDSA
         -CommonName "..." [-RevokeOld]
  TSA:   -Action NewTsa -Replace -TimestampDays 3650 -TimestampPolicyOid 1.3.6.1.4.1.<PEN>.1.4
         -TimestampQuadrant 1
  CRL:   -Action NewCrl -CrlDays N   (new CRL number, new validity; the old CRL is replaced)

THE TIME STAMP CERTIFICATE  (no special certificate is needed)
  It is a normal leaf certificate. Its ONLY extended key usage is timeStamping, marked critical
  (RFC 3161). Defaults: Classic non-FIPS (Quadrant 1), RSA 2048, valid 1825 days (a time stamp must
  stay checkable for years), policy OID 1.3.6.1.4.1.<PEN>.<arc>.4. -TimestampQuadrant 2|3|4 only
  prepares FIPS or quantum time stamping. The PKI server kit signs with RSA / ECDSA only.

OPTIONS
  -Action <name>          Status (default), Info, NewCrl, Revoke, NewOcsp, NewTsa, SignCsr.
  -Ca <ids>               CA ids: q1-ev, q1-ov, q1-dv, q2-ev ... NewCrl accepts any CA.
  -CrlDays N              CRL validity in days (default 365).
  -Certificate <file>     Revoke: the certificate file.
  -Serial <hex>           Revoke: the serial number (needs -Ca).
  -Reason <r>             Revoke: the reason.                -NoCrl   Revoke: no new CRL now.
  -OcspDays N             OCSP responder validity (default 365).
  -OcspKeyBits 2048|3072|4096     -KeyType RSA|ECDSA     -CommonName "..."
  -Replace  -RevokeOld    Issue again; revoke the old one.
  -Level EV|OV|DV         Time stamp level (default EV).
  -TimestampDays N  -TimestampPolicyOid <oid>  -TimestampQuadrant 1|2|3|4
  -Csr <file>  -For Ocsp|Tsa  -Days N  -OutFolder <folder>     SignCsr only.
  -Pki <name>             Which company PKI (default agantra). List: .\pki_setup.ps1 -ListPki
  -Release <n>            Which release (R1, R2 ...). Default: the latest.
  -NoCaRevocationInfo     Use the NoCR family (CA certificates without CRL / OCSP addresses).
  -PkiRoot <folder>       One PKI folder. Overrides -Pki, -Release and -NoCaRevocationInfo.
  -ConfigFile <path>  -OpenSslPath <path>  -FipsModuleConfig <path>  -Verbose
  -Unblock                Unblock and unlock the script and pki folders, then stop.
  -Help                   This text.

AFTER A CHANGE
  The server knows only what you copied to it. After NewCrl, Revoke, NewOcsp or NewTsa:
     .\New-PkiServerPackage.ps1                     (make the server package)
     sudo ./linux/pki-server/pki-server.sh update --source ./pki      (on the server)
  New certificates carry the CRL / OCSP addresses of agantra_pki.cnf as they were on the day of
  issue.

EXAMPLES
  .\PkiRevocation.ps1                                        status of every CRL and responder
  .\PkiRevocation.ps1 -Action NewCrl -CrlDays 90             new 90-day CRL for every CA
  .\PkiRevocation.ps1 -Action Revoke `
        -Certificate leafcerts\site\serverauth\site-server-ev-q1-rsa2048.crt `
        -Reason keyCompromise
  .\PkiRevocation.ps1 -Action NewOcsp -Ca q1-ev -Replace -OcspKeyBits 3072 -OcspDays 180 -RevokeOld
  .\PkiRevocation.ps1 -Action NewTsa -Replace -TimestampDays 3650
  .\PkiRevocation.ps1 -Action SignCsr -Csr .\ocsp-q1-ev.csr -For Ocsp -Ca q1-ev

EXIT CODES   0 ok    1 error (the message says why)    5 this system is refused

WHERE IT RUNS
  Windows 11 24H2 or newer, Windows Server 2025 and 2022 (Server 2022: Classic only). Linux with
  PowerShell: Ubuntu 24+, CentOS Stream / RHEL / Rocky / Oracle 10+, SLES / openSUSE 15+.
  Refused (exit 5, nothing done): Windows 10, Windows 11 before 24H2, Server before 2022, macOS,
  and the Chinese, Government, IoT, SE and Embedded editions.
====================================================================================================
'@
}

function Out-PagedHelp {
    # Shows help one screen at a time on a terminal (Space = next page, Enter = next line, q = quit).
    # When the output is redirected (a file, a pipe, a pipeline) it prints everything.
    param([Parameter(ValueFromPipeline = $true)][AllowEmptyString()][AllowNull()][string[]]$InputObject)
    begin { $all = [System.Collections.Generic.List[string]]::new() }
    process { foreach ($x in $InputObject) { foreach ($l in ([string]$x -split "\r?\n")) { [void]$all.Add($l) } } }
    end {
        $page = 0; $width = 120
        try { if (-not ([Console]::IsOutputRedirected -or [Console]::IsInputRedirected)) { $page = [Console]::WindowHeight - 2; $width = [Console]::WindowWidth } } catch { $page = 0 }
        if ($page -lt 8) { foreach ($l in $all) { Write-Host $l }; return }
        $rows = 0
        foreach ($l in $all) {
            Write-Host $l
            $rows += [Math]::Max(1, [Math]::Ceiling($l.Length / [Math]::Max(20, $width)))
            if ($rows -ge $page) {
                Write-Host ' -- more --  Space = next page   Enter = next line   q = quit ' -NoNewline -ForegroundColor Yellow
                $k = [Console]::ReadKey($true)
                Write-Host ("`r" + (' ' * 64) + "`r") -NoNewline
                if ($k.KeyChar -eq 'q' -or $k.KeyChar -eq 'Q' -or $k.Key -eq 'Escape') { return }
                $rows = if ($k.Key -eq 'Enter') { $page - 1 } else { 0 }
            }
        }
    }
}
function Invoke-PagedHelp {
    param([scriptblock]$Block)
    & $Block 6>&1 | ForEach-Object { if ($_ -is [System.Management.Automation.InformationRecord]) { [string]$_.MessageData } else { [string]$_ } } | Out-PagedHelp
}

if ($Help) { Invoke-PagedHelp { Show-PkiRevocationHelp }; exit 0 }

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
