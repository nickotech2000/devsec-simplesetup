# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Packs the Linux scripts (pki-server kit, pki-transport.sh, Install-DevEnvironment.sh) and the PKI WITHOUT private keys into one
    zip (and optionally .tar.gz) for Ubuntu 24.04 / 26.04: all text is LF, .sh and .py carry the Unix execute bit.
    Full help: .\New-PkiServerPackage.ps1 -Help      Manual: docs\PKI-SERVER-MANUAL.txt, docs\PKI-Server-Design.txt
.EXAMPLE
    .\New-PkiServerPackage.ps1
.EXAMPLE
    .\New-PkiServerPackage.ps1 -PkiRoot D:\pki -Output D:\out\agantra-pki-server.zip -Tar
#>
param(
    # which company's PKI (default: agantra; names = the *_pki.cnf files next to the scripts; list: .\pki_setup.ps1 -ListPki)
    [Alias('Pki')][ArgumentCompleter({ param($c, $p, $w) $s = (Get-Command $c -ErrorAction SilentlyContinue).Source; $d = if ($s) { Split-Path -Parent $s } else { $PWD.Path }; Get-ChildItem -LiteralPath $d -Filter '*_pki.cnf' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name -replace '_pki\.cnf$', '' } | Where-Object { $_ -like "$w*" } })][string]$PkiProfile,
    [string]$PkiRoot,
    [ValidateRange(1, 99)][int]$Release,
    [switch]$NoCaRevocationInfo,
    [string]$Output,
    [string]$RootName,
    [switch]$IncludeServiceKeys,
    [switch]$NoPki,
    [switch]$CrlOnly,
    [switch]$NoTsa,
    [switch]$TsaOnly,
    [switch]$Tar,
    [switch]$Force,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$script:Version = '5.3.5'
$root = $PSScriptRoot

function Show-PackageHelp {
    @'
============================================================
 New-PkiServerPackage.ps1 - the PKI + the Linux scripts as ONE zip for Ubuntu 24.04 / 26.04
 Version 5.3.5
 Author : Nicko Satria Utama     Company: Agantra Inovatif OU (NextMantra)     Email: nicko@nextmantra.com
============================================================
WHAT IT DOES
  Builds <name>.zip (and with -Tar also <name>.tar.gz) that you copy to the Ubuntu VM / WSL. It holds:
    linux\                 pki-server\ (the server kit: nginx CRL/CA host, OCSP, RFC 3161 time stamping), pki-transport.sh,
                           Install-DevEnvironment.sh, fix-permissions.sh
    pki\                   the PKI WITHOUT any private key: publish\ (CA certificates, CRLs), every CA's certificate, chain,
                           configuration, index.txt, serial and crlnumber (the OCSP responders read index.txt), the public parts of
                           ocsp\ and tsa\ (certificates, chains, .pub, info json)
    pki\server\            made by pki_setup.ps1: the host names, the CA list and every URL of THIS PKI. pki-server.sh reads it (no key inside)
    agantra_pki.cnf        only a fallback for the host names when the PKI has no server\ folder (a PKI of an older version)
    docs\PKI-Server-Design.txt, docs\PKI-SERVER-MANUAL.txt, docs\PkiRevocation-MANUAL.txt   the documents
    README-SERVER-PACKAGE.txt, SHA256SUMS, PACKAGE-MANIFEST.txt
  Every text file is written with LF and no BOM (OpenSSL 3.5+ and nginx on Linux reject CRLF keys / PEM). The .sh and .py files get
  mode 755 inside the zip (and inside the .tar.gz), everything else 644.

NEVER IN THE PACKAGE
  *.key, *.pfx, *.p12, private\ folders, issued\ (copies of every issued certificate), leafcerts\, .csr, *.old, backups, any file
  that contains "PRIVATE KEY". After the package is built it is opened again and scanned: one hit = the package is deleted, exit 5.
  The OCSP and time stamp keys: the safe way is to make them ON the server (pki-server.sh csr -> PkiRevocation.ps1 -Action SignCsr ->
  pki-server.sh import-cert), so no key ever travels. -IncludeServiceKeys is for a lab only: it adds the .key of the OCSP / time
  stamp certificates found in pki\ocsp and pki\tsa (never a CA key).

USAGE
  .\New-PkiServerPackage.ps1 [-PkiRoot <folder>] [-Release <n>] [-NoCaRevocationInfo] [-Output <file.zip>] [-RootName <name>] [-IncludeServiceKeys] [-NoPki] [-CrlOnly] [-NoTsa] [-TsaOnly] [-Tar] [-Force]

ALSO AS PkiTransport.ps1 -Server (same package, same checks, lands in .\transport\).

PARAMETERS
  -PkiRoot <folder>      one PKI folder made by pki_setup.ps1 (default: the latest release in .\pki\ next to this script)
  -Release <n>           the release to pack (R1, R2 ...). Default: the LATEST. A release that no longer exists = the latest, with a warning.
  -NoCaRevocationInfo    pack the NoCR family (pki\pki-<name>-nocr-<NN>). Default: the normal family (the NoCR one when it is the only one).
                         ONE PKI per package (inside the zip it is always pki\). The CRL and CA files of several releases can all be installed
                         on one server (the file stems differ: ...-r2, ...-nocr); the OCSP responders and the time stamp server serve the
                         release of the package that was installed LAST.
  -Output <file.zip>     default: .\agantra-pki-server-<yyyyMMdd-HHmmss>.zip next to this script
  -RootName <name>       the folder inside the zip (default agantra-pki-server)
  -IncludeServiceKeys    lab only: include the OCSP / TSA private keys (see above)
  -CrlOnly               the SMALL package of a CRL / CA-certificate server (no OCSP, no time stamping): pki-server.sh only, pki\publish + pki\server
                         of the PKI, README-CRL-SERVER.txt. On Ubuntu:  sudo ./linux/pki-server/pki-server.sh install --crl-only --source ./pki
                         (also as PkiTransport.ps1 -CrlServer). Default file name agantra-pki-crl-server-<date>.zip
  -NoTsa                 the package of a CRL + OCSP server (no time stamping): no pki-tsa.py, no pki\tsa, README-CRL-OCSP-SERVER.txt; on Ubuntu
                         install with --no-tsa. Default file name agantra-pki-crl-ocsp-server-<date>.zip (also PkiTransport.ps1 -CrlOcspServer)
  -TsaOnly               the package of a TIME STAMP server only (RFC 3161): no OCSP dispatcher, no pki\ocsp, README-TIMESTAMP-SERVER.txt; on Ubuntu
                         install with --tsa-only. Default file name agantra-pki-timestamp-server-<date>.zip (also PkiTransport.ps1 -TimestampServer)
  -NoPki                 only the Linux scripts and documents (the kit scripts for a repository check-out, no certificates)
  -Tar                   also write a .tar.gz with the same content (tar keeps the mode bits on every tool)
  -Force                 overwrite an existing output file
  -Help                  this text

ON UBUNTU / WSL
  cd ~ && unzip /mnt/c/Users/<you>/agantra-pki-server-*.zip && cd agantra-pki-server
  bash linux/fix-permissions.sh                 (only needed when the zip tool dropped the execute bits; harmless otherwise)
  sudo ./linux/pki-server/pki-server.sh csr --source ./pki --out ./csr           keys stay on the server
  (Windows)  .\PkiRevocation.ps1 -Action SignCsr -Csr ocsp-q1-ev.csr -For Ocsp -Ca q1-ev      and -For Tsa for tsa-*.csr
  sudo ./linux/pki-server/pki-server.sh import-cert --cert ./signed/ocsp-q1-ev.crt --cert ./signed/tsa-q1-ev.crt
  sudo ./linux/pki-server/pki-server.sh install --source ./pki
  ./linux/pki-server/pki-server.sh dns          the names for the Windows hosts file
  WSL test: add the dns lines to C:\Windows\System32\drivers\etc\hosts (Notepad as administrator), WSL IP: hostname -I.
  Windows 11 23H2+ with mirrored networking: use 127.0.0.1 in the hosts file. Without systemd in WSL use:  pki-server.sh run

EXIT CODES   0 ok   1 error   4 PKI folder not found   5 a private key was found in the package (deleted)
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
if ($Help) { Show-PackageHelp; exit 0 }

# Where may this script run? Windows 11 24H2+ / Server 2025 / Server 2022 (classic only), supported Linux. Error and exit 5 otherwise.
$__pf = Join-Path $PSScriptRoot 'scripts/00a_Platform.ps1'
if (-not (Test-Path -LiteralPath $__pf)) { [Console]::Error.WriteLine('[ERROR] scripts/00a_Platform.ps1 is missing: the operating system cannot be checked. Nothing was done.'); exit 5 }
. $__pf; Assert-PkiPlatform
. (Join-Path $PSScriptRoot 'scripts/00b_Profiles.ps1')

function Write-Msg { param([string]$Text, [string]$Level = 'INFO') $c = switch ($Level) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'ERROR' { 'Red' } default { 'Cyan' } }; Write-Host "[$Level] $Text" -ForegroundColor $c }

# ---------------------------------------------------------------- rules
$binaryExt = @('.crl', '.der', '.p12', '.pfx', '.zip', '.certpacked', '.tsr', '.tsq', '.gz', '.7z', '.png', '.jpg')
$unixExec = @('.sh', '.py')
$skipDirs = @('issued', 'leafcerts', 'external-ca', 'private', 'backup', 'backups', 'transport', 'logs', 'tmp', '.git')
$skipExt = @('.key', '.pfx', '.p12', '.csr', '.old', '.tmp', '.bak', '.certpacked', '.zip', '.7z', '.log')
$utf8 = [System.Text.UTF8Encoding]::new($false)
$items = [System.Collections.Generic.List[object]]::new()
$names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$skipped = [System.Collections.Generic.List[string]]::new()
$pkMarker = [System.Text.Encoding]::ASCII.GetBytes('PRIVATE KEY')

function Test-Bytes { param([byte[]]$Hay, [byte[]]$Needle)
    if ($Hay.Length -lt $Needle.Length) { return $false }
    $first = $Needle[0]
    for ($i = 0; $i -le $Hay.Length - $Needle.Length; $i++) {
        if ($Hay[$i] -ne $first) { continue }
        $m = $true; for ($j = 1; $j -lt $Needle.Length; $j++) { if ($Hay[$i + $j] -ne $Needle[$j]) { $m = $false; break } }
        if ($m) { return $true }
    }
    return $false
}

# a real PEM private key = the BEGIN line followed by base64; the words "PRIVATE KEY" in a manual or a script are not a key
$pkRegex = [regex]::new('-----BEGIN [A-Z ]*PRIVATE KEY-----\s*(Proc-Type[^\n]*\n|DEK-Info[^\n]*\n|\s)*[A-Za-z0-9+/=]{40,}', 'Singleline')
function Test-PrivateKey { param([byte[]]$Bytes)
    if (-not (Test-Bytes $Bytes $pkMarker)) { return $false }
    return $pkRegex.IsMatch([System.Text.Encoding]::Latin1.GetString($Bytes))
}

# Author / Company / Email block at the top of every text file this script generates ('#' style for SHA256SUMS, banner style otherwise).
function Get-AuthorBlock {
    param([switch]$Comment)
    $l = @('Author : Nicko Satria Utama', 'Company: Agantra Inovatif OU (NextMantra)', 'Email  : nicko@nextmantra.com')
    if ($Comment) { return (($l | ForEach-Object { "# $_" }) -join "`n") + "`n" }
    return ('=' * 60) + "`n " + ($l -join "`n ") + "`n" + ('=' * 60) + "`n`n"
}
function Add-Item {
    param([string]$Name, [byte[]]$Bytes, [string]$Ext, [bool]$AllowKey = $false)
    $Name = $Name -replace '\\', '/'
    if (-not $names.Add($Name)) { return }
    $isBin = ($binaryExt -contains $Ext) -or ($Bytes -contains 0)
    if (-not $isBin) {
        $b = $Bytes
        if ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { $b = $b[3..($b.Length - 1)] }
        $t = $utf8.GetString([byte[]]$b)
        $t = $t -replace "`r`n", "`n"
        $Bytes = $utf8.GetBytes($t)
    }
    if (-not $AllowKey -and (Test-PrivateKey $Bytes)) { $script:skipped.Add("$Name (contains PRIVATE KEY)"); [void]$names.Remove($Name); return }
    $mode = if ($unixExec -contains $Ext) { 0x1ED } else { 0x1A4 }   # 0755 / 0644
    $items.Add([pscustomobject]@{ Name = $Name; Bytes = [byte[]]$Bytes; Mode = $mode })
}

function Add-File { param([string]$Path, [string]$Name, [bool]$AllowKey = $false)
    Add-Item -Name $Name -Bytes ([System.IO.File]::ReadAllBytes($Path)) -Ext ([System.IO.Path]::GetExtension($Path).ToLowerInvariant()) -AllowKey $AllowKey
}

# ---------------------------------------------------------------- inputs
try { $profile = Resolve-PkiProfile -ScriptRoot $root -Name $PkiProfile } catch { Write-Msg $_.Exception.Message 'ERROR'; exit 1 }
$profName = $profile.Name
$stem = Get-PkiFileStem -Name $profName                       # agantra-pki | raksaka-pki ...
$pkiDir = $PkiRoot
if (-not $pkiDir) {
    $rel01c = Join-Path $root 'scripts\01c_Releases.ps1'
    if (Test-Path -LiteralPath $rel01c) {
        if (-not (Get-Command Write-PkiLog -ErrorAction SilentlyContinue)) { function Write-PkiLog { param([string]$Message, [string]$Level = 'INFO') Write-Msg $Message $Level } }
        . $rel01c
        $choice = Resolve-PkiRootChoice -ScriptRoot $root -NoCr ([bool]$NoCaRevocationInfo) -NoCrExplicit ([bool]$NoCaRevocationInfo) -Release $(if ($Release) { $Release } else { 0 }) -Mode Use -Profile $profName
        $pkiDir = $choice.Path
        if ($choice.Exists) { Write-Msg "PKI: release R$($choice.Release)$(if ($choice.NoCr) { ' (NoCR)' })  $pkiDir" 'INFO' }
    }
    else { $pkiDir = Join-Path $root 'pki' }
}
if (-not $NoPki -and -not (Test-Path -LiteralPath (Join-Path $pkiDir 'publish') -PathType Container)) {
    Write-Msg "PKI folder not found or no publish\ inside: $pkiDir  (-PkiRoot <folder>, or -NoPki)" 'ERROR'; exit 4
}
if ($CrlOnly -and $NoTsa) { Write-Msg '-CrlOnly and -NoTsa cannot be combined (-CrlOnly has no OCSP either).' 'ERROR'; exit 1 }
if ($TsaOnly -and ($CrlOnly -or $NoTsa)) { Write-Msg '-TsaOnly cannot be combined with -CrlOnly or -NoTsa.' 'ERROR'; exit 1 }
if (-not $RootName) { $RootName = "$stem-server" }
if ($TsaOnly -and $RootName -eq "$stem-server") { $RootName = "$stem-timestamp-server" }
if ($NoTsa -and $RootName -eq "$stem-server") { $RootName = "$stem-crl-ocsp-server" }
if ($CrlOnly) { if ($NoPki) { Write-Msg '-CrlOnly needs the PKI (publish\ and server\): do not combine it with -NoPki.' 'ERROR'; exit 1 }; if ($IncludeServiceKeys) { Write-Msg '-CrlOnly carries no keys at all: -IncludeServiceKeys is not allowed with it.' 'ERROR'; exit 1 }; if ($RootName -eq 'agantra-pki-server') { $RootName = 'agantra-pki-crl-server' } }
if (-not $Output) { $Output = Join-Path $root ("{0}-{1}.zip" -f $(if ($CrlOnly) { "$stem-crl-server" } elseif ($NoTsa) { "$stem-crl-ocsp-server" } elseif ($TsaOnly) { "$stem-timestamp-server" } else { "$stem-server" }), (Get-Date -Format 'yyyyMMdd-HHmmss')) }
$Output = [System.IO.Path]::GetFullPath($Output)
$tarOut = [System.IO.Path]::ChangeExtension($Output, '.tar.gz')
foreach ($o in @($Output) + @($(if ($Tar) { $tarOut }))) { if (Test-Path -LiteralPath $o) { if ($Force) { Remove-Item -LiteralPath $o -Force } else { Write-Msg "Exists: $o  (use -Force)" 'ERROR'; exit 1 } } }
[void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $Output))

# ---------------------------------------------------------------- linux scripts and documents
$linuxDir = Join-Path $root 'linux'
if (-not (Test-Path -LiteralPath $linuxDir -PathType Container)) { Write-Msg "linux folder not found next to this script: $linuxDir" 'ERROR'; exit 1 }
Get-ChildItem -LiteralPath $linuxDir -Recurse -File -Force | ForEach-Object {
    $rel = $_.FullName.Substring($linuxDir.Length).TrimStart('\', '/')
    if ($rel -match '(^|[\\/])(\.git|__pycache__)([\\/]|$)') { return }
    if ($NoTsa -and $rel -match 'pki-tsa\.py$') { return }
    if ($TsaOnly -and $rel -match 'pki-ocsp-dispatch\.py$') { return }
    if ($CrlOnly -and ($rel -replace '\\', '/') -ne 'pki-server/pki-server.sh') { return }
    Add-File -Path $_.FullName -Name "$RootName/linux/$rel"
}
$cn = $profile.ConfigPath
if ($CrlOnly) { }
elseif (Test-Path -LiteralPath $cn) { Add-File -Path $cn -Name "$RootName/$(Split-Path -Leaf $cn)" } else { Write-Msg "not found, not packed: $cn" 'WARN' }
foreach ($d in $(if ($CrlOnly) { @('PKI-SERVER-MANUAL.txt') } else { @('PKI-Server-Design.txt', 'PKI-SERVER-MANUAL.txt', 'PkiRevocation-MANUAL.txt', 'PkiTransport-MANUAL.txt', 'Install-DevEnvironment-MANUAL.txt', 'linux-README.txt') })) {
    $p = Join-Path (Join-Path $root 'docs') $d
    if (Test-Path -LiteralPath $p) { Add-File -Path $p -Name "$RootName/docs/$d" } else { Write-Msg "not found, not packed: docs\$d" 'WARN' }
}

# ---------------------------------------------------------------- the PKI, public parts only
$nPki = 0; $nKeyFiles = 0
if (-not $NoPki) {
    $pkiFull = (Resolve-Path -LiteralPath $pkiDir).Path
    Get-ChildItem -LiteralPath $pkiFull -Recurse -File -Force | ForEach-Object {
        $rel = $_.FullName.Substring($pkiFull.Length).TrimStart('\', '/') -replace '\\', '/'
        $parts = $rel.Split('/'); $ext = $_.Extension.ToLowerInvariant(); $fn = $_.Name
        $inSvc = ($parts[0] -in @('ocsp', 'tsa'))
        if ($NoTsa -and $parts[0] -eq 'tsa') { return }
        if ($TsaOnly -and $parts[0] -eq 'ocsp') { return }
        if ($CrlOnly -and $parts[0] -notin @('publish', 'server')) { return }
        $dirParts = if ($parts.Length -gt 1) { $parts[0..($parts.Length - 2)] } else { @() }
        if ($dirParts | Where-Object { $skipDirs -contains $_.ToLowerInvariant() }) { $skipped.Add($rel); return }
        if ($fn -in @('telemetry.json')) { return }
        if ($inSvc -and $IncludeServiceKeys -and ($ext -in @('.key', '.pem'))) {
            Add-File -Path $_.FullName -Name "$RootName/pki/$rel" -AllowKey $true; $nKeyFiles++; $nPki++; return
        }
        if ($ext -eq '.key' -or $ext -in $skipExt) { $skipped.Add($rel); return }
        if ($fn -match '\.(old|tmp|bak)$' -or $fn -match '\.old\.|\.attr\.old$') { $skipped.Add($rel); return }
        if ($ext -eq '.pem' -and $inSvc) { $skipped.Add("$rel (combined key file)"); return }
        Add-File -Path $_.FullName -Name "$RootName/pki/$rel"; $nPki++
    }
}

# ---------------------------------------------------------------- generated documents
$readme = @"
Agantra Inovatif PKI - server package (built $((Get-Date).ToString('yyyy-MM-dd HH:mm')) with New-PkiServerPackage.ps1 $script:Version)
==========================================================================================================
For Ubuntu 24.04 / 26.04 (or WSL with Ubuntu 24.04 / 26.04). All text files are LF. $(if ($IncludeServiceKeys) { 'THIS PACKAGE CONTAINS OCSP / TSA PRIVATE KEYS (-IncludeServiceKeys): lab use only.' } else { 'There is NO private key in this package.' })

1  unzip, then (only if the execute bits are missing):   bash linux/fix-permissions.sh
2  the keys of the OCSP responders and the time stamp server are made HERE, on the server:
     sudo ./linux/pki-server/pki-server.sh csr --source ./pki --out ./csr
   copy ./csr/*.csr to the machine that holds the CA keys and sign them:
     .\PkiRevocation.ps1 -Action SignCsr -Csr ocsp-q1-ev.csr -For Ocsp -Ca q1-ev      (-For Tsa -Ca q1-ev for tsa-q1-ev.csr)
   copy the signed .crt files back:
     sudo ./linux/pki-server/pki-server.sh import-cert --cert ./signed/ocsp-q1-ev.crt --cert ./signed/tsa-q1-ev.crt
3  sudo ./linux/pki-server/pki-server.sh install --source ./pki
4  ./linux/pki-server/pki-server.sh dns         -> the lines for the hosts file (WSL test) or for your DNS server
5  ./linux/pki-server/pki-server.sh test        -> CRL download, OCSP query, time stamp

Documents: docs\PKI-SERVER-MANUAL.txt, docs\PKI-Server-Design.txt, docs\PkiRevocation-MANUAL.txt.   Check the files: sha256sum -c SHA256SUMS
"@
if ($CrlOnly) {
    $readme = @"
Agantra Inovatif PKI - CRL server package (built $((Get-Date).ToString('yyyy-MM-dd HH:mm')) with New-PkiServerPackage.ps1 $script:Version)
==========================================================================================================
A small web server for the CRLs and CA certificates of the PKI, on Ubuntu 24.04 / 26.04 (or WSL with Ubuntu 24.04 / 26.04). No OCSP, no time stamping,
NO private key in this package, no OpenSSL 4 needed. All text files are LF.

1  unzip, then (only if the execute bit is missing):   chmod +x linux/pki-server/pki-server.sh
2  sudo ./linux/pki-server/pki-server.sh install --crl-only --source ./pki
      installs nginx (your PPA ppa:nickotech2000/nicko-su-prod; --no-ppa uses the Ubuntu nginx), publishes pki/publish, writes the nginx site,
      runs a self-test. Without systemd (WSL):  add  --no-systemd  (nginx is started by you:  sudo nginx )
3  ./linux/pki-server/pki-server.sh dns
      prints the lines for the Windows hosts file and the records for the Wi-Fi router (crl / crt host names -> this server's IP)
4  on a client:  curl -I http://crl.nextmantra.internal/<ca>.crl        certutil -verify -urlfetch <leaf>-fullchain.crt

NEW CRL (they expire; CRL_DAYS in pki/server/server.env):  on the CA machine  .\PkiRevocation.ps1 -Action NewCrl , then build this package again
(.\PkiTransport.ps1 -CrlServer), copy it, unzip, and  sudo ./linux/pki-server/pki-server.sh update --crl-only --source ./pki
Check the expiry any time:  ./linux/pki-server/pki-server.sh crl-check      (a daily systemd timer does it too)
OCSP and time stamping later: use the full package  .\PkiTransport.ps1 -Server  and  install  without --crl-only.

Documents: docs\PKI-SERVER-MANUAL.txt.   Check the files: sha256sum -c SHA256SUMS
"@
}
if ($TsaOnly) {
    $readme = @"
Agantra Inovatif PKI - TIME STAMP server package (built $((Get-Date).ToString('yyyy-MM-dd HH:mm')) with New-PkiServerPackage.ps1 $script:Version)
==========================================================================================================
An RFC 3161 time stamp server on Ubuntu 24.04 / 26.04 (or WSL with Ubuntu 24.04 / 26.04): http://tsa.nextmantra.internal and http://timestamp.nextmantra.internal.
No CRL host, no OCSP, NO CA key. All text files are LF.

1  unzip, then (only if the execute bits are missing):   bash linux/fix-permissions.sh
2  the time stamp key is made HERE, on the server (no key travels):
     sudo ./linux/pki-server/pki-server.sh csr --tsa-only --source ./pki --out ./csr           (--tsa-ca <id> chooses the CA, default the first -ev CA)
   copy ./csr/tsa-*.csr to the CA machine and sign it:
     .\PkiRevocation.ps1 -Action SignCsr -Csr tsa-q1-ev.csr -For Tsa -Ca q1-ev
   copy the signed .crt back:
     sudo ./linux/pki-server/pki-server.sh import-cert --cert ./signed/tsa-q1-ev.crt
3  sudo ./linux/pki-server/pki-server.sh install --tsa-only --source ./pki
      (nginx and OpenSSL 4 from the PPA, python3; WSL without systemd: add --no-systemd, then  sudo /opt/agantra-pki-server/pki-server.sh run)
4  ./linux/pki-server/pki-server.sh dns         -> hosts-file lines / router records for tsa. and timestamp.nextmantra.internal
5  ./linux/pki-server/pki-server.sh test        -> one time stamp request: created and verified against the chain

A time stamp is checked by the client against the CA chain and (for revocation) the CRL / OCSP of the PKI: run the CRL server (.\PkiTransport.ps1 -CrlServer) or the
full server (-Server) too, on this or another machine.
Documents: docs\PKI-SERVER-MANUAL.txt.   Check the files: sha256sum -c SHA256SUMS
"@
}
if ($NoTsa) {
    $readme = @"
Agantra Inovatif PKI - CRL + OCSP server package (built $((Get-Date).ToString('yyyy-MM-dd HH:mm')) with New-PkiServerPackage.ps1 $script:Version)
==========================================================================================================
CRL, CA certificates and OCSP on Ubuntu 24.04 / 26.04 (or WSL with Ubuntu 24.04 / 26.04). NO time stamping, NO CA key. All text files are LF.

1  unzip, then (only if the execute bits are missing):   bash linux/fix-permissions.sh
2  the OCSP responder keys are made HERE, on the server (no key travels):
     sudo ./linux/pki-server/pki-server.sh csr --no-tsa --source ./pki --out ./csr
   copy ./csr/*.csr to the machine that holds the CA keys and sign them:
     .\PkiRevocation.ps1 -Action SignCsr -Csr ocsp-q1-ev.csr -For Ocsp -Ca q1-ev          (one per issuing CA)
   copy the signed .crt files back:
     sudo ./linux/pki-server/pki-server.sh import-cert --cert ./signed/ocsp-q1-ev.crt [--cert ...]
3  sudo ./linux/pki-server/pki-server.sh install --no-tsa --source ./pki
      (nginx from the PPA, OpenSSL 4 from the PPA, python3 for the OCSP dispatcher; WSL without systemd: add --no-systemd, then  sudo /opt/agantra-pki-server/pki-server.sh run)
4  ./linux/pki-server/pki-server.sh dns         -> hosts-file lines / router records for crl., crt. and ocsp.nextmantra.internal
5  ./linux/pki-server/pki-server.sh test        -> CRL and CA-issuer downloads, one OCSP query per responder

NEW CRL / NEW CERTIFICATES: build this package again on the CA machine (.\PkiTransport.ps1 -CrlOcspServer), copy, unzip, and
  sudo ./linux/pki-server/pki-server.sh update --no-tsa --source ./pki
Only the CRL is needed (no OCSP)?  .\PkiTransport.ps1 -CrlServer.   Time stamping too?  .\PkiTransport.ps1 -Server.
Documents: docs\PKI-SERVER-MANUAL.txt.   Check the files: sha256sum -c SHA256SUMS
"@
}
Add-Item -Name "$RootName/README-$(if ($CrlOnly) { 'CRL-SERVER' } elseif ($NoTsa) { 'CRL-OCSP-SERVER' } elseif ($TsaOnly) { 'TIMESTAMP-SERVER' } else { 'SERVER-PACKAGE' }).txt" -Bytes $utf8.GetBytes((Get-AuthorBlock) + $readme) -Ext '.txt'

$sumLines = foreach ($it in ($items | Sort-Object Name)) {
    $h = [System.Security.Cryptography.SHA256]::HashData([byte[]]$it.Bytes)
    "{0}  {1}" -f ([BitConverter]::ToString($h).Replace('-', '').ToLowerInvariant()), $it.Name.Substring($RootName.Length + 1)
}
Add-Item -Name "$RootName/SHA256SUMS" -Bytes $utf8.GetBytes((Get-AuthorBlock -Comment) + (($sumLines -join "`n") + "`n")) -Ext '.txt'
$man = @("Package : $RootName   built $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) UTC   by New-PkiServerPackage.ps1 $script:Version",
    "Files   : $($items.Count + 1)   PKI files: $nPki   service key files: $nKeyFiles   (IncludeServiceKeys=$([bool]$IncludeServiceKeys))",
    "Skipped : $($skipped.Count)") + @($skipped | ForEach-Object { "  - $_" })
Add-Item -Name "$RootName/PACKAGE-MANIFEST.txt" -Bytes $utf8.GetBytes((Get-AuthorBlock) + (($man -join "`n") + "`n")) -Ext '.txt'

# ---------------------------------------------------------------- write the zip (unix host + mode bits)
$zfs = [System.IO.File]::Create($Output)
$zip = [System.IO.Compression.ZipArchive]::new($zfs, [System.IO.Compression.ZipArchiveMode]::Create, $false, $utf8)
foreach ($it in ($items | Sort-Object Name)) {
    $e = $zip.CreateEntry($it.Name, [System.IO.Compression.CompressionLevel]::Optimal)
    $e.LastWriteTime = [DateTimeOffset]::Now
    $attr = [uint32](0x8000 -bor $it.Mode) -shl 16
    $e.ExternalAttributes = [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$attr), 0)
    $es = $e.Open(); $es.Write($it.Bytes, 0, $it.Bytes.Length); $es.Dispose()
}
$zip.Dispose(); $zfs.Dispose()
# "version made by" = Unix (3), so unzip honours the mode bits
$zb = [System.IO.File]::ReadAllBytes($Output)
$eocd = -1; for ($i = $zb.Length - 22; $i -ge 0; $i--) { if ($zb[$i] -eq 0x50 -and $zb[$i + 1] -eq 0x4B -and $zb[$i + 2] -eq 5 -and $zb[$i + 3] -eq 6) { $eocd = $i; break } }
if ($eocd -lt 0) { throw 'zip: end of central directory not found' }
$cnt = [BitConverter]::ToUInt16($zb, $eocd + 10); $p = [int][BitConverter]::ToUInt32($zb, $eocd + 16)
for ($k = 0; $k -lt $cnt; $k++) {
    if ([BitConverter]::ToUInt32($zb, $p) -ne 0x02014B50) { throw 'zip: bad central directory' }
    $zb[$p + 5] = 3
    $p += 46 + [BitConverter]::ToUInt16($zb, $p + 28) + [BitConverter]::ToUInt16($zb, $p + 30) + [BitConverter]::ToUInt16($zb, $p + 32)
}
[System.IO.File]::WriteAllBytes($Output, $zb)

if ($Tar) {
    $tfs = [System.IO.File]::Create($tarOut)
    $gz = [System.IO.Compression.GZipStream]::new($tfs, [System.IO.Compression.CompressionLevel]::Optimal)
    $tw = [System.Formats.Tar.TarWriter]::new($gz, [System.Formats.Tar.TarEntryFormat]::Pax, $false)
    foreach ($it in ($items | Sort-Object Name)) {
        $te = [System.Formats.Tar.PaxTarEntry]::new([System.Formats.Tar.TarEntryType]::RegularFile, $it.Name)
        $te.DataStream = [System.IO.MemoryStream]::new([byte[]]$it.Bytes)
        $te.Mode = [System.IO.UnixFileMode][int]$it.Mode
        $tw.WriteEntry($te)
    }
    $tw.Dispose(); $gz.Dispose(); $tfs.Dispose()
}

# ---------------------------------------------------------------- verify what was written
function Test-Package {
    $bad = 0
    $z = [System.IO.Compression.ZipFile]::OpenRead($Output)
    try {
        foreach ($e in $z.Entries) {
            $ms = [System.IO.MemoryStream]::new(); $s = $e.Open(); $s.CopyTo($ms); $s.Dispose(); $b = $ms.ToArray()
            $ext = [System.IO.Path]::GetExtension($e.FullName).ToLowerInvariant()
            $isKeyOk = $IncludeServiceKeys -and ($e.FullName -match '/pki/(ocsp|tsa)/')
            if (-not $isKeyOk -and (Test-PrivateKey $b)) { Write-Msg "PRIVATE KEY text inside: $($e.FullName)" 'ERROR'; $bad++ }
            if (-not $IncludeServiceKeys -and $e.FullName -match '\.(key|pfx|p12)$') { Write-Msg "key file inside: $($e.FullName)" 'ERROR'; $bad++ }
            if (($binaryExt -notcontains $ext) -and -not ($b -contains 0) -and ($b -contains 13)) { Write-Msg "CR found in text file: $($e.FullName)" 'ERROR'; $bad++ }
            if ($unixExec -contains $ext -and (($e.ExternalAttributes -shr 16) -band 0x49) -ne 0x49) { Write-Msg "execute bit missing: $($e.FullName)" 'ERROR'; $bad++ }
        }
    } finally { $z.Dispose() }
    return $bad
}
$bad = Test-Package
if ($bad -gt 0) {
    Remove-Item -LiteralPath $Output, $tarOut -Force -ErrorAction SilentlyContinue
    Write-Msg "$bad problem(s): the package was deleted." 'ERROR'; exit 5
}
Write-Msg ("Package: {0}  ({1:N0} KB, {2} files, PKI files {3}, skipped {4})" -f $Output, ((Get-Item -LiteralPath $Output).Length / 1KB), ($items.Count), $nPki, $skipped.Count) 'OK'
if ($Tar) { Write-Msg "Package: $tarOut" 'OK' }
Write-Msg $(if ($IncludeServiceKeys) { 'Checked: no CA key; OCSP / TSA keys included on request; all text LF; .sh / .py executable.' } else { 'Checked: no private key, no CR in any text file, .sh / .py executable.' }) 'OK'
$rd = if ($CrlOnly) { 'README-CRL-SERVER.txt' } elseif ($NoTsa) { 'README-CRL-OCSP-SERVER.txt' } elseif ($TsaOnly) { 'README-TIMESTAMP-SERVER.txt' } else { 'README-SERVER-PACKAGE.txt' }
Write-Msg "Copy it to Ubuntu / WSL:  unzip <zip>; cd $RootName; see $rd" 'INFO'
exit 0
