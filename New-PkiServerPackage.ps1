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
    [string]$PkiRoot,
    [string]$Output,
    [string]$RootName = 'agantra-pki-server',
    [switch]$IncludeServiceKeys,
    [switch]$NoPki,
    [switch]$Tar,
    [switch]$Force,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$script:Version = '4.9.5-phaseC'
$root = $PSScriptRoot

function Show-PackageHelp {
    @'
============================================================
 New-PkiServerPackage.ps1 - the PKI + the Linux scripts as ONE zip for Ubuntu 24.04 / 26.04
 Version 4.9.5-phaseC
 Author : Nicko Satria Utama     Company: Agantra Inovatif OU (NextMantra)     Email: nicko@nextmantra.com
============================================================
WHAT IT DOES
  Builds <name>.zip (and with -Tar also <name>.tar.gz) that you copy to the Ubuntu VM / WSL. It holds:
    linux\                 pki-server\ (the server kit: nginx CRL/CA host, OCSP, RFC 3161 time stamping), pki-transport.sh,
                           Install-DevEnvironment.sh, fix-permissions.sh
    pki\                   the PKI WITHOUT any private key: publish\ (CA certificates, CRLs), every CA's certificate, chain,
                           configuration, index.txt, serial and crlnumber (the OCSP responders read index.txt), the public parts of
                           ocsp\ and tsa\ (certificates, chains, .pub, info json)
    agantra_pki.cnf        the host names (CRL / OCSP / CA issuer URLs) the kit puts into nginx
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
  .\New-PkiServerPackage.ps1 [-PkiRoot <folder>] [-Output <file.zip>] [-RootName <name>] [-IncludeServiceKeys] [-NoPki] [-Tar] [-Force]

PARAMETERS
  -PkiRoot <folder>      the PKI made by pki_setup.ps1 (default: .\pki next to this script)
  -Output <file.zip>     default: .\agantra-pki-server-<yyyyMMdd-HHmmss>.zip next to this script
  -RootName <name>       the folder inside the zip (default agantra-pki-server)
  -IncludeServiceKeys    lab only: include the OCSP / TSA private keys (see above)
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
'@
}
if ($Help) { Show-PackageHelp; exit 0 }

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
$pkiDir = if ($PkiRoot) { $PkiRoot } else { Join-Path $root 'pki' }
if (-not $NoPki -and -not (Test-Path -LiteralPath (Join-Path $pkiDir 'publish') -PathType Container)) {
    Write-Msg "PKI folder not found or no publish\ inside: $pkiDir  (-PkiRoot <folder>, or -NoPki)" 'ERROR'; exit 4
}
if (-not $Output) { $Output = Join-Path $root ("agantra-pki-server-{0}.zip" -f (Get-Date -Format 'yyyyMMdd-HHmmss')) }
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
    Add-File -Path $_.FullName -Name "$RootName/linux/$rel"
}
$cn = Join-Path $root 'agantra_pki.cnf'
if (Test-Path -LiteralPath $cn) { Add-File -Path $cn -Name "$RootName/agantra_pki.cnf" } else { Write-Msg 'not found, not packed: agantra_pki.cnf' 'WARN' }
foreach ($d in @('PKI-Server-Design.txt', 'PKI-SERVER-MANUAL.txt', 'PkiRevocation-MANUAL.txt', 'PkiTransport-MANUAL.txt', 'Install-DevEnvironment-MANUAL.txt', 'linux-README.txt')) {
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
Add-Item -Name "$RootName/README-SERVER-PACKAGE.txt" -Bytes $utf8.GetBytes($readme) -Ext '.txt'

$sumLines = foreach ($it in ($items | Sort-Object Name)) {
    $h = [System.Security.Cryptography.SHA256]::HashData([byte[]]$it.Bytes)
    "{0}  {1}" -f ([BitConverter]::ToString($h).Replace('-', '').ToLowerInvariant()), $it.Name.Substring($RootName.Length + 1)
}
Add-Item -Name "$RootName/SHA256SUMS" -Bytes $utf8.GetBytes((($sumLines -join "`n") + "`n")) -Ext '.txt'
$man = @("Package : $RootName   built $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) UTC   by New-PkiServerPackage.ps1 $script:Version",
    "Files   : $($items.Count + 1)   PKI files: $nPki   service key files: $nKeyFiles   (IncludeServiceKeys=$([bool]$IncludeServiceKeys))",
    "Skipped : $($skipped.Count)") + @($skipped | ForEach-Object { "  - $_" })
Add-Item -Name "$RootName/PACKAGE-MANIFEST.txt" -Bytes $utf8.GetBytes((($man -join "`n") + "`n")) -Ext '.txt'

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
Write-Msg 'Copy it to Ubuntu / WSL:  unzip <zip>; cd agantra-pki-server; see README-SERVER-PACKAGE.txt' 'INFO'
exit 0
