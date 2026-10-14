# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
<#
.SYNOPSIS
    Backs up the WHOLE PKI (every PKI, every release, with all private keys) into one password-protected .certpacked inside a backup zip.
    Windows 11 Home/Pro 24H2+ or Windows Server 2025, Intel/AMD 64 bit, Administrator PowerShell 7. Full help: .\Backup-Pki.ps1 -Help
.EXAMPLE
    .\Backup-Pki.ps1
.EXAMPLE
    .\Backup-Pki.ps1 -Check
#>
param(
    [string]$PkiRoot,
    [string]$BackupRoot,
    [switch]$Check,
    [switch]$List,
    [switch]$Help
)

function Show-Help {
@'
============================================================
 Backup-Pki.ps1 - back up the whole PKI into one password-protected zip
 Version 5.3.6
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
WHAT IT DOES
  Takes everything that makes up your PKI - the pki\ folder (all PKIs and releases, root and issuing CA KEYS included), leafcerts\, external-ca\,
  csr-signed\, every <company>_pki.cnf, pki_tools.cnf, devkit.env - and packs it into ONE password-protected .certpacked (AES-256), then puts the
  .certpacked together with its checksums and the restore tools into a backup zip in the folder  backup-pki\  (created when it does not exist):

      backup-pki\pki-payload-<yyyymmdd>-<computer>-<windows-version>-<6 hex>.zip
          pki-payload-...\  <same name>.certpacked   the encrypted backup
                            SHA256SUMS, SHA512SUMS   checksums of every file in the zip
                            Restore-Pki.ps1          puts the backup back
                            Test-PkiBackup.ps1       checks that the .certpacked is still valid (checksums; -Deep also opens it)
                            Backup-Pki.ps1           makes the next backup
                            Prepare-Computer.ps1     installs PowerShell 7, OpenSSL 4, Python 3 (run it BEFORE a restore)
                            README.txt

ONLY YOUR PKI  The backup holds only the certificates and keys of YOUR PKI: the organizations named in your <company>_pki.cnf files (Agantra, Raksaka ...). Certificates of other CAs - the
           DigiCert / GlobalSign / Sectigo chain files, a certificate a public CA issued to you, with their keys - are recognised and LEFT OUT (the list is printed). A root that a public CA
           signed for YOUR key, and everything your CAs issued, stay in.
PRIVATE KEYS  A backup is made to RESTORE from, so it must hold every private key: all roots, all intermediates, all leaf / profile keys (and the .pfx files). Every certificate under pki\ and
           leafcerts\ is matched with its key (by the public key, with OpenSSL); a certificate without a key is listed, a CA certificate without a key is a WARNING. The result is stored in the backup
           (certpack.json) and Restore-Pki.ps1 prints it. Without OpenSSL on the PATH the keys are still copied but the match is not made (WARN).
INDEPENDENT   This script needs no other .ps1 (the code it shares with Restore-Pki and Test-PkiBackup is built into it). It copies itself, Restore-Pki.ps1, Test-PkiBackup.ps1 and
           Prepare-Computer.ps1 into the zip, so the zip is enough to restore on a new computer.

PASSWORD   You type it (twice) - it is asked FIRST, before the long scan. No password, no backup. At least 12 characters with 1 upper case letter, 1 lower case letter, 1 digit and
           1 special character; every rule that is broken is shown. It is stored nowhere: if you lose it, the backup is lost. Write it down.

OPTIONS
  -PkiRoot <folder>     the project folder that holds pki\ (default: the folder of this script)
  -BackupRoot <folder>  the backup folder itself (default: backup-pki inside -PkiRoot); the folder is created when it does not exist
  -Check                only list what would be backed up (no password, nothing written)
  -List                 list the backups that are in the backup folder
  -Help

WHERE IT RUNS
  Windows 11 Home or Pro, 24H2 or newer; Windows Server 2025 Essentials, Standard, Datacenter. Intel or AMD 64 bit (AMD64 / x86-64) ONLY: ARM and
  32 bit are refused. Administrator PowerShell 7 (pwsh) ONLY: any other window is refused. Prepare-Computer.ps1 installs PowerShell 7 (and OpenSSL 4, Python 3, .NET 8 and 10).
  A backup holds PRIVATE KEYS: keep the zip and the password apart, in two safe places.
  The Windows certificate stores are not part of the backup: after a restore run  pki_setup.ps1 -InstallTrust  to trust the PKI again.
  EXIT CODES   0 ok   1 error   2 not an Administrator window   3 password refused   5 system not supported (Windows version / edition / ARM)
============================================================
'@ | Write-Host
}

if ($Help) { Show-Help; return }
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host '[ERROR] Backup-Pki.ps1 needs PowerShell 7 or newer (this window is PowerShell' $PSVersionTable.PSVersion.ToString() '). Run Prepare-Computer.ps1 in an Administrator window to install it, then start this script with  pwsh . Nothing was done.' -ForegroundColor Red
    exit 4
}

$ErrorActionPreference = 'Stop'
#@@EMBED-LIBRARY@@
Set-StrictMode -Version Latest

Write-BkBanner 'Backup-Pki.ps1' 'back up the whole PKI'
$os = Assert-BkHost

# ---------------------------------------------------------------- where is the PKI, where do the backups go
if (-not $PkiRoot) { $PkiRoot = $PSScriptRoot }
$PkiRoot = [System.IO.Path]::GetFullPath($PkiRoot)
$backupDir = $(if ($BackupRoot) { [System.IO.Path]::GetFullPath($BackupRoot) } else { Join-Path $PkiRoot $script:BkFolderName })

if ($List) {
    if (-not (Test-Path -LiteralPath $backupDir -PathType Container)) { Say 'INFO' "No backup folder yet: $backupDir"; exit 0 }
    $zips = @(Get-ChildItem -LiteralPath $backupDir -Filter 'pki-payload-*.zip' -File | Sort-Object Name)
    Say 'INFO' "$($zips.Count) backup(s) in $backupDir"
    foreach ($z in $zips) { Write-Host ('  {0}   {1:N0} KB   {2}' -f $z.Name, ($z.Length / 1KB), $z.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) }
    exit 0
}

$pkiDir = Join-Path $PkiRoot 'pki'
if (-not (Test-Path -LiteralPath $pkiDir -PathType Container) -or @(Get-ChildItem -LiteralPath $pkiDir -Recurse -File -Force -ErrorAction SilentlyContinue).Count -eq 0) {
    Stop-Bk "No PKI found: $pkiDir is missing or empty. Run this script in the project folder, or give -PkiRoot <the folder that holds pki\>. Nothing was done." 1
}

# ---------------------------------------------------------------- password FIRST: no password, no process (before the long scan, so no key typed meanwhile can answer it)
$password = $null
if (-not $Check) { $password = Read-BkNewPassword }

# ---------------------------------------------------------------- what goes in: YOUR PKI only
$root = $PkiRoot.TrimEnd('\', '/')
$ownOrgs = @(Get-BkOwnOrganizations -Root $root)
if ($ownOrgs.Count -eq 0) { Say 'WARN' "No <company>_pki.cnf with an Organization found in ${PkiRoot}: your PKI cannot be told from the certificates of other CAs, everything is backed up." }
else { Say 'INFO' ("Your PKI      : organization(s) {0} (from the *_pki.cnf files); certificates of other CAs (DigiCert, GlobalSign, Sectigo ...) are not backed up" -f (($ownOrgs | Sort-Object) -join ', ')) }
Say 'INFO' 'Looking at every certificate and key (this takes a while for a big PKI) ...'
$inv = Get-BkKeyInventory -Root $root -Folders @('pki', 'leafcerts', 'external-ca', 'csr-signed') -OwnOrgs $ownOrgs

$items = [System.Collections.Generic.List[hashtable]]::new()
$skipped = [System.Collections.Generic.List[string]]::new()
$dirList = [System.Collections.Generic.List[string]]::new()      # every folder, also the empty ones (issued\ ...)
function Add-BkTree {
    param([string]$Dir)
    foreach ($sd in @(Get-ChildItem -LiteralPath $Dir -Recurse -Directory -Force) + @(Get-Item -LiteralPath $Dir)) {
        $r = (($sd.FullName.Substring($root.Length).TrimStart('\', '/')) -replace '\\', '/')
        if (-not (Test-BkExcluded -Rel "$r/x" -Inventory $inv)) { [void]$dirList.Add($r) }
    }
    foreach ($f in @(Get-ChildItem -LiteralPath $Dir -Recurse -File -Force)) {
        $rel = $f.FullName.Substring($root.Length).TrimStart('\', '/') -replace '\\', '/'
        if (Test-BkExcluded -Rel $rel -Inventory $inv) { [void]$skipped.Add($rel); continue }
        [void]$items.Add(@{ Source = $f.FullName; Entry = "data/$rel"; Rel = $rel })
    }
}
foreach ($d in 'pki', 'leafcerts', 'external-ca', 'csr-signed') { $p = Join-Path $PkiRoot $d; if (Test-Path -LiteralPath $p -PathType Container) { Add-BkTree $p } }
foreach ($f in @(Get-ChildItem -LiteralPath $PkiRoot -File -Force | Where-Object { $_.Name -like '*_pki.cnf' -or $_.Name -in 'pki_tools.cnf', 'devkit.env' })) {
    [void]$items.Add(@{ Source = $f.FullName; Entry = "data/$($f.Name)"; Rel = $f.Name })
}
$pkis = @(Get-ChildItem -LiteralPath $pkiDir -Directory -Force | ForEach-Object { $_.Name } | Where-Object { -not $inv.ExcludedFolders.Contains($_) } | Sort-Object)
$keyCount = @($items | Where-Object { $_.Rel -like '*.key' -or $_.Rel -like '*.pfx' -or $_.Rel -like '*.p12' }).Count
$bytes = 0L; foreach ($i in $items) { $bytes += ([System.IO.FileInfo]::new($i.Source)).Length }

# ---------------------------------------------------------------- every certificate of yours must have its private key in the backup
$own = @($inv.Certificates | Where-Object { $_.Own })
$uniq = @($own | Group-Object Thumbprint | ForEach-Object { $g = @($_.Group); [pscustomobject]@{ Thumbprint = $_.Name; Subject = $g[0].Subject; IsCa = $g[0].IsCa; SelfSigned = $g[0].SelfSigned; HasKey = (@($g | Where-Object { $_.HasKey }).Count -gt 0); Files = @($g | ForEach-Object { $_.Rel }) } })
$caAll = @($uniq | Where-Object { $_.IsCa })
$noKey = @($uniq | Where-Object { -not $_.HasKey })
$pkiInfo = foreach ($n in $pkis) {
    $mine = @($own | Where-Object { $_.Rel -like "pki/$n/*" -and $_.IsCa } | Group-Object Thumbprint | ForEach-Object { $_.Group[0] })
    [ordered]@{ name = $n; caCertificates = @($mine | ForEach-Object { [ordered]@{ thumbprint = $_.Thumbprint; subject = $_.Subject; kind = $(if ($_.SelfSigned) { 'root' } else { 'intermediate' }); file = $_.Rel; privateKeyInBackup = $_.HasKey } }) }
}

Say 'INFO' "PKI folder   : $PkiRoot"
Say 'INFO' ("To back up   : {0} files, {1:N1} MB, {2} private key / PFX files" -f $items.Count, ($bytes / 1MB), $keyCount)
Say 'INFO' ("PKI folders  : {0}" -f ($pkis -join ', '))
if ($skipped.Count -gt 0 -or $inv.ExcludedFolders.Count -gt 0) {
    Say 'INFO' ("Left out      : {0} file(s) that belong to other CAs, not to your PKI{1}" -f $skipped.Count, $(if ($inv.ExcludedFolders.Count -gt 0) { " (whole PKI folder(s): $($inv.ExcludedFolders -join ', '))" } else { '' }))
    foreach ($fs in ($inv.Foreign | Select-Object -First 8)) { Say 'INFO' "  other CA: $fs" }
    if ($inv.Foreign.Count -gt 8) { Say 'INFO' "  ... and $($inv.Foreign.Count - 8) more" }
}
if ($inv.NoOpenSsl) { Say 'WARN' 'OpenSSL is not on the PATH: the keys are copied, but certificates and keys could not be matched. Run Prepare-Computer.ps1 for the full check.' }
else {
    Say 'INFO' ("Certificates : {0} of your PKI ({1} CA: {2} roots, {3} intermediates); private key in the backup for {4} of them" -f $uniq.Count, $caAll.Count, @($caAll | Where-Object { $_.SelfSigned }).Count, @($caAll | Where-Object { -not $_.SelfSigned }).Count, @($uniq | Where-Object { $_.HasKey }).Count)
    foreach ($c in ($noKey | Select-Object -First 25)) { Say $(if ($c.IsCa) { 'WARN' } else { 'INFO' }) ("No private key in the backup for {0}{1}   ({2}) - it was signed from a request: the key stays with the requester" -f $(if ($c.IsCa) { 'the CA certificate ' } else { 'the certificate ' }), $c.Subject, $c.Files[0]) }
    if ($noKey.Count -gt 25) { Say 'INFO' "... and $($noKey.Count - 25) more" }
    if (@($noKey | Where-Object { $_.IsCa }).Count -gt 0) { Say 'WARN' 'A CA certificate without its key cannot issue after a restore (a CA signed by SignExternalCa keeps its key in the other department; or a deleted key).' }
}
Say 'INFO' "Backup folder: $backupDir$(if (-not (Test-Path -LiteralPath $backupDir)) { '  (will be created)' })"
if ($Check) { Say 'INFO' '-Check: nothing was written, no password was asked.'; exit 0 }

# ---------------------------------------------------------------- build
$stamp = (Get-Date).ToString('yyyyMMdd')
$stem = "pki-payload-$stamp-$(Get-BkComputerName)-$($os.Slug)-$(Get-BkShortId)"
$work = New-BkTempDirectory 'pkibackup-make'
try {
    [void][System.IO.Directory]::CreateDirectory($backupDir)
    $zipPath = Join-Path $backupDir "$stem.zip"
    if (Test-Path -LiteralPath $zipPath) { Stop-Bk "The backup file exists already: $zipPath (run again for a new unique name)." 1 }

    $files = foreach ($i in $items) { $h = Get-BkHash -Path $i.Source; [ordered]@{ path = $i.Entry; sha256 = $h.Sha256; size = ([System.IO.FileInfo]::new($i.Source)).Length } }
    $manifest = [ordered]@{
        format = $script:BkFormat; formatVersion = $script:BkFormatVersion
        createdUtc = [DateTime]::UtcNow.ToString('o'); generator = "Backup-Pki.ps1 $($script:BkVersion)"
        source = [ordered]@{ computer = [Environment]::MachineName; os = $os.Text; osSlug = $os.Slug; pkiRoot = $PkiRoot }
        archive = [ordered]@{ format = 'zip'; encryption = 'AES-256 (WinZip AE-2)' }
        pkiFolders = @($pkis); pki = @($pkiInfo)
        keyCheck = [ordered]@{ checked = (-not $inv.NoOpenSsl); certificates = $uniq.Count; withPrivateKey = @($uniq | Where-Object { $_.HasKey }).Count; caCertificates = $caAll.Count; caWithoutKey = @($noKey | Where-Object { $_.IsCa } | ForEach-Object { $_.Subject }) }
        directories = @($dirList); fileCount = $items.Count; privateKeyFiles = $keyCount
        files = @($files)
    }
    $gen = Join-Path $work 'gen'; [void][System.IO.Directory]::CreateDirectory($gen)
    $jsonF = Join-Path $gen 'certpack.json'; Write-BkTextFile $jsonF ($manifest | ConvertTo-Json -Depth 6)
    $sums = [System.Text.StringBuilder]::new()
    foreach ($f in $files) { [void]$sums.Append("$($f.sha256)  $($f.path)`n") }
    $sumF = Join-Path $gen 'SHA256SUMS'; Write-BkTextFile $sumF $sums.ToString()
    $innerReadme = @"
# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
PKI BACKUP (inside the .certpacked)  -  Backup-Pki.ps1 version $($script:BkVersion)
Created : $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm')) UTC on $([Environment]::MachineName) ($($os.Text))
Content : $($items.Count) files from $PkiRoot  -  folders: $($pkis -join ', ')
THIS ARCHIVE CONTAINS PRIVATE KEYS. Open it only with Restore-Pki.ps1, or with 7-Zip (rename to .zip). Every file is listed with its SHA-256 in certpack.json and SHA256SUMS.
"@
    $irF = Join-Path $gen 'README.txt'; Write-BkTextFile $irF ($innerReadme + "`n")

    $packList = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($x in @(@($jsonF, 'certpack.json'), @($sumF, 'SHA256SUMS'), @($irF, 'README.txt'))) { [void]$packList.Add(@{ Source = $x[0]; Entry = $x[1] }) }
    foreach ($i in $items) { [void]$packList.Add(@{ Source = $i.Source; Entry = $i.Entry }) }

    $stage = Join-Path $work $stem; [void][System.IO.Directory]::CreateDirectory($stage)
    $cp = Join-Path $stage "$stem.certpacked"
    Say 'INFO' 'Packing and encrypting (AES-256) ...'
    New-PkiAesZipArchive -Path $cp -Files $packList -Password $password -Encryption Aes256
    Say 'INFO' 'Checking the .certpacked: decrypting every file again ...'
    [void](Expand-PkiArchive -Path $cp -Password $password)        # decrypts and authenticates every entry
    Say 'OK' ("{0}.certpacked  ({1:N0} KB, {2} files)" -f $stem, (([System.IO.FileInfo]::new($cp)).Length / 1KB), $items.Count)

    # the tools next to the .certpacked
    $tools = foreach ($n in 'Restore-Pki.ps1', 'Test-PkiBackup.ps1', 'Backup-Pki.ps1', 'Prepare-Computer.ps1') {
        $src = $null
        foreach ($c in (Join-Path $PSScriptRoot $n), (Join-Path (Join-Path $PSScriptRoot 'trustkit') $n)) { if (-not $src -and (Test-Path -LiteralPath $c)) { $src = $c } }
        if (-not $src) { Stop-Bk "$n was not found next to this script (or in trustkit\). The backup zip would be incomplete. Nothing was kept." 1 }
        [pscustomobject]@{ Name = $n; Source = $src }
    }
    foreach ($t in $tools) { Copy-Item -LiteralPath $t.Source -Destination (Join-Path $stage $t.Name) -Force }

    $outer = @"
# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
PKI BACKUP  -  $stem
Version : $($script:BkVersion)   (made by Backup-Pki.ps1)
Created : $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm')) UTC on $([Environment]::MachineName)   $($os.Text)
Content : $($items.Count) files, $($pkis.Count) PKI folder(s): $($pkis -join ', ')
Keys    : private key in the backup for $(@($uniq | Where-Object { $_.HasKey }).Count) of $($uniq.Count) certificates (all roots, intermediates and profiles)
Security: the .certpacked is encrypted with AES-256 and holds PRIVATE KEYS (root and issuing CAs). The password is stored nowhere.
          Keep this zip and the password in two different safe places.

FILES
  $stem.certpacked   the encrypted backup (a password-protected zip: rename to .zip to open it with 7-Zip)
  SHA256SUMS, SHA512SUMS   checksums of every other file in this folder
  Restore-Pki.ps1    puts the backup back
  Test-PkiBackup.ps1 checks that the files are unchanged (checksums); -Deep also decrypts the .certpacked
  Backup-Pki.ps1     makes a new backup (needs the PKI project folder: -PkiRoot)
  (each script is standalone: it needs no other .ps1)
  Prepare-Computer.ps1  installs PowerShell 7, OpenSSL 4, Python 3, .NET SDK 8 and 10 and puts them on the PATH

HOW TO RESTORE   (Windows 11 Home/Pro 24H2+ or Windows Server 2025, Intel/AMD 64 bit, Administrator window)
  1. Unzip this zip. Open Windows PowerShell as Administrator in the unzipped folder.
  2. .\Prepare-Computer.ps1          (once per computer; then close the window)
  3. Open a NEW Administrator window with  pwsh  in the same folder.
  4. .\Test-PkiBackup.ps1            (are the files still valid?)
  5. .\Restore-Pki.ps1 -Destination C:\PKI-DevSecOps     (asks for the password; refuses to overwrite an existing PKI unless -Force)
  6. In the restored project folder:  .\pki_setup.ps1 -InstallTrust   (trusts the PKI again in the Windows stores)
  Help of each script:  .\Restore-Pki.ps1 -Help   .\Test-PkiBackup.ps1 -Help   .\Backup-Pki.ps1 -Help
"@
    Write-BkTextFile (Join-Path $stage 'README.txt') ($outer + "`n")

    # checksums of everything except the sum files
    $s256 = [System.Text.StringBuilder]::new(); $s512 = [System.Text.StringBuilder]::new()
    $hdr = "# Checksums of the files of $stem`n# Check them with Test-PkiBackup.ps1, or:  sha256sum -c SHA256SUMS  /  sha512sum -c SHA512SUMS`n# Author: Nicko Satria Utama - Company: Agantra Inovatif OU (NextMantra) - Email: nicko@nextmantra.com - Version $($script:BkVersion)`n"
    [void]$s256.Append($hdr); [void]$s512.Append($hdr)
    foreach ($f in @(Get-ChildItem -LiteralPath $stage -Recurse -File | Sort-Object FullName)) {
        $rel = $f.FullName.Substring($stage.Length).TrimStart('\', '/') -replace '\\', '/'
        $h = Get-BkHash -Path $f.FullName
        [void]$s256.Append("$($h.Sha256)  $rel`n"); [void]$s512.Append("$($h.Sha512)  $rel`n")
    }
    Write-BkTextFile (Join-Path $stage 'SHA256SUMS') $s256.ToString()
    Write-BkTextFile (Join-Path $stage 'SHA512SUMS') $s512.ToString()

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $true)
    $zh = Get-BkHash -Path $zipPath
    Say 'OK' ("Backup zip: {0}  ({1:N0} KB)" -f $zipPath, (([System.IO.FileInfo]::new($zipPath)).Length / 1KB))
    Say 'INFO' "SHA-256 of the zip : $($zh.Sha256)"
    Say 'INFO' "SHA-512 of the zip : $($zh.Sha512)"
    Write-Host ''
    Say 'WARN' 'This backup contains PRIVATE KEYS. Keep the zip and the password apart, in two safe places. The password cannot be recovered.'
    Say 'INFO' 'Next: copy the zip to another disk or computer. Check it later with Test-PkiBackup.ps1.'
}
finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
exit 0
