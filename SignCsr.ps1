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
====================================================================================================
 SignCsr.ps1  -  sign the certificate request (CSR) of a colleague with your PKI
 Version 6.4.7
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
====================================================================================================
 On a terminal: SPACE = next page, ENTER = next line, Q = quit.
 Manual : docs\SignCsr-MANUAL.txt     Design: docs\PKI-Design-with-FIPS-and-PQC.txt (10.72, 20)
 Twin   : SignCsr.sh (same rules, options written --like-this) in the DevKit and in devkit\.
 Needs  : PowerShell 7+, OpenSSL 4.x, and a PKI made by pki_setup.ps1.

WHAT IT IS
  A colleague made his own private key and a certificate request (a CSR file). He sent you ONLY the
  CSR. This script checks the CSR against the rules of your PKI. If the CSR is good, the script
  signs it and gives you a certificate. If the CSR breaks a rule, the script signs nothing.
  You never see his private key. He never sees yours.

QUICK START
  1. Put his file next to the script, for example web01.csr.
  2. Check it first. Nothing is signed:     .\SignCsr.ps1 -Csr .\web01.csr -Check
  3. Read the report. Fix every red ERROR (ask him to make a new CSR).
  4. Sign it:                                .\SignCsr.ps1 -Csr .\web01.csr
  5. Send him the new folder from csr-signed\ (it holds no private key).

HOW TO READ THE REPORT
  red ERROR   the CSR breaks a rule. Nothing is signed (exit code 2).
  yellow WARN the CSR is allowed, but something was changed or dropped. Read the line.
  green OK    the check passed.
  cyan INFO   a fact, for example which CA signs.
  Every line says what is wrong and how to fix it. -Strict makes every WARN an ERROR.

WHAT YOU GET
  A NEW folder, never overwritten:   csr-signed\<name>_<yyyyMMdd-HHmmss>\
     <name>.crt  <name>.cer     the certificate (PEM and DER)
     <name>-fullchain.crt       certificate + CA chain: the file for his server
     <name>-chain.crt           the CA chain only
     <name>.p7b                 certificate + chain, for Windows
     root.crt                   your Enterprise Root: his clients must trust it
     our-ca-bundle.crt          chain + root
     <name>.csr  sign-info.json  README.txt   (README.txt tells HIM what to do)
  One line is added to csr-signed\signed-csr.tsv. The certificate is also written in the index.txt
  of the issuing CA, so you can revoke it later (PkiRevocation.ps1 -Action Revoke).

WHICH CA SIGNS
  Only an INTERMEDIATE CA signs here: q<N>-dv, q<N>-ov or q<N>-ev. A root never signs a CSR.
  -DV | -OV | -EV   the level. Without one, the level follows the CSR:
                      complete EV data (businessCategory, serialNumber, jurisdictionC)  = EV
                      company name and country (O and C)                                 = OV
                      common name only                                                   = DV
  -Classic | -Quantum   the track. Default: Classic.
  -FIPS                 the FIPS quadrant (Classic = Q2, Quantum = Q4). Without it: Q1 or Q3.
  A CSR for a CA certificate (CA:TRUE) is refused here. Use SignExternalCa.ps1 for it.

RULES A CSR MUST FOLLOW
  Signature  valid, SHA-256 or stronger.
  Key        Classic: RSA 2048, 3072, 4096, 8192 or ECDSA P-256, P-384, P-521.
             Quantum: ML-DSA-44, 65, 87.
             Code signing: RSA 4096+, ECDSA P-384+, ML-DSA-65+.
             Never: RSA below 2048, other curves, Ed25519, DSA.
  Subject    DV: CN only (the rest is dropped, WARN).
             OV: C (2 letters), O and CN. ST and L are recommended.
             EV: OV + ST, L, serialNumber, businessCategory and jurisdictionC.
                 businessCategory is one of: Private Organization, Government Entity,
                 Business Entity, Non-Commercial Entity.
             Code signing: C, O, CN.
  Names      TLS: DNS names and IP addresses. No SAN: the CN becomes the DNS name (WARN).
             EV: no wildcard, no IP address, no internal name (.local .lan .internal), no e-mail.
             E-mail certificate: e-mail addresses only.
             Code signing, time stamping, OCSP: no names (dropped, WARN).
  Validity   DV 5 years, OV 3 years, EV 397 days at most, time stamping 5 years, OCSP 1 year.
             Never longer than the CA that signs.
  Ignored    keyUsage, extendedKeyUsage, CRL and OCSP addresses in the CSR. Your PKI sets them.
             A policy OID in the CSR is kept only inside the company arc 1.3.6.1.4.1.<PEN>.

OPTIONS
  -Csr <file>          His CSR (PEM). Required.
  -CsrType Auto|Leaf|IntermediateCA   Default Auto: the script sees CA:TRUE by itself.
  -DV | -OV | -EV      Level. Default: from the CSR.
  -Classic | -Quantum  Track. Default Classic.             -FIPS   FIPS quadrant.
  -Purpose <p>         ServerAuth (default), ClientAuth, ServerClientAuth, CodeSigning,
                       EmailProtection, TimeStamping, OcspSigning.
  -Days <n>            Validity in days. Default by level. EV: 397 at most.
  -Name <text>         Name of the folder and the files. Default: his CN.
  -OutFolder <path>    Where the folders go. Default: csr-signed\ next to the pki folder.
  -AddDevelopmentSAN   Add the development names (DNS, IP, e-mail of [ development_san ]).
                       A CSR from New-PkiCsr.ps1 can ask for this by itself.
  -Policy <oid|cps>    One extra policy for this certificate, "OID|CPS-URL".
  -NoCrl -NoOcsp -NoRevocationInfo   Leave the CRL address and/or the OCSP address out. The leaf is
                       then signed by the NoCR PKI. Without a NoCR PKI the script stops: first run
                       pki_setup.ps1 -NoCaRevocationInfo -InstallTrust.
  -Check               Only check and print the report. Sign nothing.
  -Strict              A WARN counts as an ERROR.
  -NoColor             Plain text (also when NO_COLOR is set).
  -List                Show the earlier requests (csr-signed\signed-csr.tsv) and stop.
  -WriteShellEnv       Write devkit.env so devkit\SignCsr.sh can sign on this PKI (Linux, WSL).
  -Unblock             Unblock and unlock the script folder and the pki folder, then stop.
  -Pki <name>          Which company PKI. Default agantra (or DefaultPki of pki_tools.cnf).
                       List: .\pki_setup.ps1 -ListPki
  -Release <n>         Which release (R1, R2 ...). Default: the latest. A deleted release is not an
                       error: the latest is used and a WARN says so.
  -NoCaRevocationInfo  Use the NoCR family (CA certificates without CRL and OCSP addresses).
  -PkiRoot <folder>    One PKI folder. Overrides -Pki, -Release and -NoCaRevocationInfo.
  -ConfigFile <path>  -OpenSslPath <path>  -FipsModuleConfig <path>  -Verbose
  -Help                This text.

HOW HE MAKES A CSR  (he keeps the key, you never see it)
  Easiest: New-PkiCsr.ps1 or new-pki-csr.sh from the trust kit. It asks questions.
  By hand with OpenSSL:
     openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out web01.key
     openssl req -new -key web01.key -sha256 -subj "/CN=web01.dept.example" `
         -addext "subjectAltName=DNS:web01.dept.example" -out web01.csr
  OV adds /C=EE/ST=Harju/L=Tallinn/O=Dept Ltd. EV also adds /serialNumber=... ,
  /businessCategory=Private Organization and /jurisdictionC=EE.
  Windows without OpenSSL: certreq -new request.inf web01.csr (the .inf holds subject and SAN).

EXAMPLES
  .\SignCsr.ps1 -Csr .\web01.csr                              level from the CSR, Q1, TLS server
  .\SignCsr.ps1 -Csr .\web01.csr -OV -Purpose ServerClientAuth
  .\SignCsr.ps1 -Csr .\web01.csr -EV -FIPS -Check             would q2-ev sign it? Report only
  .\SignCsr.ps1 -Csr .\sign.csr -OV -Purpose CodeSigning -NoRevocationInfo
  .\SignCsr.ps1 -Csr .\pq.csr -Quantum -OV                    ML-DSA request, q3-ov
  .\SignCsr.ps1 -List

EXIT CODES
  0 ok (signed, or -Check passed)    1 error (the message says why)
  2 the CSR breaks a rule (the report says where)    5 this system is refused

WHERE IT RUNS
  Windows 11 24H2 or newer, Windows Server 2025 (everything), Windows Server 2022 (Classic only).
  Linux with PowerShell: Ubuntu 24+, CentOS Stream / RHEL / Rocky / Oracle 10+, SLES / openSUSE 15+.
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

if ($Help) { Invoke-PagedHelp { Show-SignCsrHelp }; exit 0 }

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
