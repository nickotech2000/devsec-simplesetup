# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
<#
.SYNOPSIS
    Puts a PKI backup (made by Backup-Pki.ps1) back: asks for the password, checks every file, restores the PKI folders and keys.
    Windows 11 Home/Pro 24H2+ or Windows Server 2025, Intel/AMD 64 bit, Administrator PowerShell 7, after Prepare-Computer.ps1.
    Full help: .\Restore-Pki.ps1 -Help
.EXAMPLE
    .\Restore-Pki.ps1 -Destination C:\PKI-DevSecOps
.EXAMPLE
    .\Restore-Pki.ps1 -Package .\backup-pki\pki-payload-20261014-pc01-windows-11-25h2-a1b2c3.zip -Check
#>
param(
    [string]$Package,
    [string]$Destination,
    [switch]$Force,
    [switch]$Check,
    [switch]$RestrictAccess,
    [switch]$Help
)

function Show-Help {
@'
============================================================
 Restore-Pki.ps1 - put a PKI backup back
 Version 5.3.5
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
ORDER OF WORK  (a restore stops at the first problem, before anything is written)
  1. The computer: Windows 11 Home/Pro 24H2+ or Windows Server 2025, Intel/AMD 64 bit, Administrator window. Otherwise: refused.
  2. ALL required software is checked: PowerShell 7, OpenSSL 4, Python 3, .NET SDK 8, .NET SDK 10 (on the PATH). Whatever is missing is listed, and the script says:
     you need to run Prepare-Computer.ps1 (it installs all of them). Nothing else happens until it has been run.
  3. The checksums of the files in the backup zip (SHA256SUMS) are checked.
  4. You type the backup password (no password, no restore). Every file inside the .certpacked is decrypted and checked against its SHA-256.
  5. ONE BY ONE, each PKI of the backup is compared with this computer:
       - the pki folder of -Destination: every file of that PKI by SHA-256 (identical / different / missing);
       - the Local Machine certificate store (Root and Intermediate): every CA certificate of that PKI by thumbprint.
     A PKI that is in the pki folder already (all files identical), or whose CA certificates are ALL in the Local Machine store, is NOT restored. A PKI whose folder exists but differs
     is left alone and reported. Only what is missing is restored. If nothing is missing: "Nothing to restore", nothing is changed.
     (The store holds certificates, not private keys: -Force restores the keys of a PKI that is only in the store.)
  6. The other files (leafcerts, external-ca, csr-signed, settings) are compared file by file the same way.
  7. The files are written, then every restored file is checked against the backup again.
  The backup itself holds the private key of EVERY certificate: all roots, all intermediates, all profile / leaf certificates (Backup-Pki.ps1 checks this when it makes the backup).

USE
  .\Restore-Pki.ps1 -Destination C:\PKI-DevSecOps                 (run it from the unzipped backup folder: the .certpacked is next to it)
  .\Restore-Pki.ps1 -Package <backup zip | .certpacked | folder> -Destination <folder>
  .\Restore-Pki.ps1 -Check                                          (everything except writing: the password, the checksums, the one-by-one comparison, what would be restored)
  Standalone: this script needs no other .ps1. Prepare-Computer.ps1 (next to it in the backup zip) is only RUN by you, before.

OPTIONS
  -Package <path>      the backup zip (pki-payload-....zip), the .certpacked, or a folder that holds one. Default: the .certpacked next to this script.
  -Destination <dir>   the project folder to restore into. Default: the folder of this script when it is the project (it has pki_setup.ps1); otherwise you must give it.
  -Force               restore anyway: a PKI folder (or file) that exists is RENAMED to <name>.before-restore-<yyyymmdd-HHmmss> (never deleted), and a PKI that is only in the Local Machine store is restored too
  -Check               do not write anything
  -RestrictAccess      pki\, leafcerts\, external-ca\ get access for Administrators and SYSTEM only (icacls) BEFORE the keys are written
  -Help

AFTER IT
  The Windows certificate stores are not in the backup: run  pki_setup.ps1 -InstallTrust  in the restored folder to trust the PKI again.
  EXIT CODES   0 ok   1 error   2 not an Administrator window   3 wrong password   4 Prepare-Computer.ps1 not run   5 system not supported   6 checksum does not match
============================================================
'@ | Write-Host
}

if ($Help) { Show-Help; return }
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host '[ERROR] Restore-Pki.ps1 needs PowerShell 7 or newer (this window is PowerShell' $PSVersionTable.PSVersion.ToString() '). Run Prepare-Computer.ps1 in an Administrator window to install it, then start this script with  pwsh . Nothing was done.' -ForegroundColor Red
    exit 4
}

$ErrorActionPreference = 'Stop'
#@@EMBED-LIBRARY@@
Set-StrictMode -Version Latest

Write-BkBanner 'Restore-Pki.ps1' 'restore a PKI backup'
$os = Assert-BkHost
$prep = $(if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'Prepare-Computer.ps1')) { '.\Prepare-Computer.ps1' } else { 'Prepare-Computer.ps1 (from the backup zip or from trustkit\)' })
Assert-BkPrepared -PrepareScript $prep

$work = New-BkTempDirectory 'pkirestore'
$opened = $null
try {
    # ---------------------------------------------------------------- which backup
    $cp = $null; $checkDir = $null
    if (-not $Package) {
        $found = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.certpacked' -File -ErrorAction SilentlyContinue)
        if ($found.Count -eq 1) { $Package = $found[0].FullName }
        elseif ($found.Count -gt 1) { Stop-Bk ("There is more than one .certpacked next to this script; say which with -Package:`n  " + (($found | ForEach-Object { $_.Name }) -join "`n  ")) 1 }
        else { Stop-Bk 'No backup given. Use -Package <backup zip | .certpacked | folder>, or run this script from the unzipped backup folder. Nothing was done.' 1 }
    }
    if (-not (Test-Path -LiteralPath $Package)) { Stop-Bk "Backup not found: $Package" 1 }
    $Package = (Resolve-Path -LiteralPath $Package).Path
    if ((Get-Item -LiteralPath $Package).PSIsContainer) {
        $found = @(Get-ChildItem -LiteralPath $Package -Filter '*.certpacked' -File)
        if ($found.Count -eq 1) { $cp = $found[0].FullName; $checkDir = $Package }
        else {
            $zs = @(Get-ChildItem -LiteralPath $Package -Filter 'pki-payload-*.zip' -File | Sort-Object Name)
            if ($zs.Count -eq 1) { $Package = $zs[0].FullName }
            elseif ($zs.Count -eq 0) { Stop-Bk "No backup in $Package (no .certpacked and no pki-payload-*.zip)." 1 }
            else { Stop-Bk ("There are $($zs.Count) backups in $Package; say which one with -Package <file>:`n  " + (($zs | ForEach-Object { $_.Name }) -join "`n  ")) 1 }
        }
    }
    if (-not $cp -and $Package -like '*.zip') {
        Say 'INFO' 'Opening the backup zip ...'
        $ex = Join-Path $work 'zip'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($Package, $ex)
        $inner = @(Get-ChildItem -LiteralPath $ex -Recurse -Filter '*.certpacked' -File)
        if ($inner.Count -ne 1) { Stop-Bk "The zip must hold exactly one .certpacked (found $($inner.Count))." 1 }
        $cp = $inner[0].FullName; $checkDir = $inner[0].DirectoryName
    }
    elseif (-not $cp) { $cp = $Package; $checkDir = Split-Path -Parent $Package }

    # ---------------------------------------------------------------- the checksums of the zip contents
    $sumFile = Join-Path $checkDir 'SHA256SUMS'
    if (Test-Path -LiteralPath $sumFile) {
        $sums = Get-BkSumsFile $sumFile; $badSum = 0
        foreach ($k in $sums.Keys) {
            $fp = Join-Path $checkDir ($k -replace '/', [System.IO.Path]::DirectorySeparatorChar)
            if (-not (Test-Path -LiteralPath $fp)) { Say 'ERROR' "Missing: $k"; $badSum++; continue }
            if ((Get-BkHash $fp).Sha256 -ne $sums[$k]) { Say 'ERROR' "Different SHA-256: $k"; $badSum++ }
        }
        if ($badSum -gt 0) { Stop-Bk "$badSum file(s) of the backup do not match SHA256SUMS: the backup is damaged or was changed. Nothing was done." 6 }
        Say 'OK' "SHA-256 checksums: $($sums.Count) files match."
    }
    else { Say 'WARN' 'No SHA256SUMS next to the .certpacked: only the checks inside the .certpacked are done.' }

    # ---------------------------------------------------------------- where to
    if (-not $Destination) {
        if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'pki_setup.ps1')) { $Destination = $PSScriptRoot }
        else { Stop-Bk 'Say where to restore: -Destination <folder>  (for example C:\PKI-DevSecOps). Nothing was done.' 1 }
    }
    $Destination = [System.IO.Path]::GetFullPath($Destination)

    # ---------------------------------------------------------------- password, decrypt, verify
    $pw = Read-BkExistingPassword 'Backup password'
    Say 'INFO' 'Decrypting and checking every file ...'
    $opened = Open-BkPackage -Path $cp -Password $pw
    $m = $opened.Manifest
    $entries = @($m['files'] | Where-Object { ([string]$_['path']).StartsWith('data/') })
    Say 'OK' ("Backup made {0} on {1} ({2}): {3} files, PKI folders: {4}" -f $m['createdUtc'], $m['source']['computer'], $m['source']['os'], $entries.Count, (@($m['pkiFolders']) -join ', '))
    if ($m.ContainsKey('keyCheck')) {
        $kc = $m['keyCheck']
        if ($kc['checked']) { Say 'INFO' ("Private keys in this backup: {0} of {1} certificates; CA certificates without a key: {2}" -f $kc['withPrivateKey'], $kc['certificates'], @($kc['caWithoutKey']).Count) }
        foreach ($c in @($kc['caWithoutKey'])) { Say 'WARN' "This backup has no private key for the CA certificate: $c" }
    }
    Say 'INFO' "Destination : $Destination"

    # ---------------------------------------------------------------- one by one: is it there already?
    # Each PKI of the backup is compared with the pki folder of the destination (file by file, SHA-256) and with the Local Machine certificate
    # store (Root + Intermediate, by thumbprint). A PKI that is there already is not restored.
    $storeSet = Get-BkLocalMachineThumbprints
    $pkiMeta = @{}
    foreach ($pm in @($m['pki'])) { $pkiMeta[[string]$pm['name']] = $pm }
    $skipPki = @{}; $restorePki = [System.Collections.Generic.List[string]]::new(); $replacePki = [System.Collections.Generic.List[string]]::new()
    Write-Host ''
    Say 'INFO' 'Comparing the PKIs of the backup with this computer, one by one ...'
    foreach ($name in @($m['pkiFolders'])) {
        $name = [string]$name
        $mine = @($entries | Where-Object { ([string]$_['path']).StartsWith("data/pki/$name/") })
        $destDir = Join-Path (Join-Path $Destination 'pki') $name
        $same = 0; $diff = 0; $miss = 0
        if (Test-Path -LiteralPath $destDir -PathType Container) {
            foreach ($e in $mine) {
                $to = Join-Path $Destination (([string]$e['path']).Substring(5) -replace '/', [System.IO.Path]::DirectorySeparatorChar)
                if (-not (Test-Path -LiteralPath $to -PathType Leaf)) { $miss++ }
                elseif ((Get-BkHash $to).Sha256 -eq [string]$e['sha256']) { $same++ } else { $diff++ }
            }
        }
        else { $miss = $mine.Count }
        $folderExists = (Test-Path -LiteralPath $destDir -PathType Container)
        $folderComplete = ($folderExists -and $diff -eq 0 -and $miss -eq 0)
        Write-Host ("  PKI {0}" -f $name)
        if (-not $folderExists) { Write-Host '    pki folder    : not there' }
        elseif ($folderComplete) { Write-Host ("    pki folder    : there, all {0} files identical" -f $same) -ForegroundColor Green }
        else { Write-Host ("    pki folder    : there, but {0} identical, {1} different, {2} missing" -f $same, $diff, $miss) -ForegroundColor Yellow }
        $cas = @(); if ($pkiMeta.ContainsKey($name)) { $cas = @($pkiMeta[$name]['caCertificates']) }
        $inStore = 0
        foreach ($ca in $cas) {
            $has = $storeSet.Contains(([string]$ca['thumbprint']).ToUpperInvariant())
            if ($has) { $inStore++ }
            Write-Host ("    {0,-12} : {1}  {2}" -f $ca['kind'], $(if ($has) { 'in Local Machine store' } else { 'NOT in Local Machine store' }), ([string]$ca['subject'] -replace '^.*?CN=([^,]+).*$', '$1')) -ForegroundColor $(if ($has) { 'Green' } else { 'Gray' })
        }
        $storeAll = ($cas.Count -gt 0 -and $inStore -eq $cas.Count)
        if ($cas.Count -eq 0) { Write-Host '    store         : (this backup does not list the CA certificates of this PKI: store not compared)' }
        # decision
        if ($folderComplete -and -not $Force) { $skipPki[$name] = 'already in the pki folder (every file identical)'; Say 'OK' "    -> not restored: $($skipPki[$name])." }
        elseif ($folderExists -and -not $folderComplete -and -not $Force) { $skipPki[$name] = 'the pki folder has this PKI, but different files; it is left alone (-Force replaces it, the old folder is renamed)'; Say 'WARN' "    -> not restored: $($skipPki[$name])." }
        elseif ($storeAll -and -not $Force) { $skipPki[$name] = "all $($cas.Count) CA certificates are in the Local Machine certificate store"; Say 'OK' "    -> not restored: $($skipPki[$name]). (Only the certificates are in the store, not the private keys: -Force restores the keys anyway.)" }
        else { [void]$restorePki.Add($name); if ($folderExists) { [void]$replacePki.Add($name) }; Say 'INFO' "    -> will be restored$(if ($folderExists) { ' (the existing folder is renamed first)' })." }
    }

    # the other files (leafcerts, external-ca, csr-signed, *_pki.cnf ...): file by file
    $extra = @($entries | Where-Object { -not ([string]$_['path']).StartsWith('data/pki/') })
    $xWrite = [System.Collections.Generic.List[object]]::new(); $xSame = 0; $xDiff = [System.Collections.Generic.List[object]]::new()
    foreach ($e in $extra) {
        $to = Join-Path $Destination (([string]$e['path']).Substring(5) -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $to -PathType Leaf)) { [void]$xWrite.Add($e) }
        elseif ((Get-BkHash $to).Sha256 -eq [string]$e['sha256']) { $xSame++ }
        else { if ($Force) { [void]$xWrite.Add($e) }; [void]$xDiff.Add($e) }
    }
    if ($extra.Count -gt 0) {
        Write-Host ''
        Say 'INFO' ("Other files (leafcerts, external-ca, csr-signed, settings): {0} in the backup, {1} already there and identical, {2} missing, {3} there but different{4}" -f $extra.Count, $xSame, ($xWrite.Count - $(if ($Force) { $xDiff.Count } else { 0 })), $xDiff.Count, $(if ($xDiff.Count -gt 0 -and -not $Force) { ' (left alone; -Force replaces them, the old file is renamed)' } else { '' }))
    }

    $pkiFiles = @($entries | Where-Object { $p = ([string]$_['path']); $restorePki.Contains(($p.Substring(9) -split '/')[0]) -and $p.StartsWith('data/pki/') })
    $toWrite = @($pkiFiles) + @($xWrite)
    Write-Host ''
    if ($toWrite.Count -eq 0) {
        if (@($skipPki.Values | Where-Object { $_ -like 'the pki folder has this PKI*' }).Count -gt 0) { Say 'WARN' 'Nothing was restored: a PKI folder differs from the backup (see above). -Force replaces it (the old folder is renamed). Nothing was changed.' }
        else { Say 'OK' 'Nothing to restore: everything in the backup is there already. Nothing was changed.' }
        exit 0
    }
    Say 'INFO' ("To restore    : {0} files ({1} PKI(s): {2})" -f $toWrite.Count, $restorePki.Count, $(if ($restorePki.Count -gt 0) { $restorePki -join ', ' } else { 'none' }))
    if ($Check) { Say 'OK' '-Check: the password is right and every file is valid. Nothing was written.'; exit 0 }

    # ---------------------------------------------------------------- write
    [void][System.IO.Directory]::CreateDirectory($Destination)
    $ts = (Get-Date).ToString('yyyyMMdd-HHmmss')
    foreach ($name in $replacePki) {
        $src = Join-Path (Join-Path $Destination 'pki') $name; $new = "$src.before-restore-$ts"
        Move-Item -LiteralPath $src -Destination $new
        Say 'INFO' "Renamed: pki\$name -> $(Split-Path -Leaf $new)"
    }
    foreach ($e in @($xWrite | Where-Object { Test-Path -LiteralPath (Join-Path $Destination (([string]$_['path']).Substring(5) -replace '/', [System.IO.Path]::DirectorySeparatorChar)) -PathType Leaf })) {
        $old = Join-Path $Destination (([string]$e['path']).Substring(5) -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        Move-Item -LiteralPath $old -Destination "$old.before-restore-$ts"
        Say 'INFO' "Renamed: $(([string]$e['path']).Substring(5)) -> $(Split-Path -Leaf $old).before-restore-$ts"
    }
    $lockedDirs = 'pki', 'leafcerts', 'external-ca', 'csr-signed'
    $tops = @($toWrite | ForEach-Object { (([string]$_['path']).Substring(5) -split '/')[0] } | Sort-Object -Unique)
    foreach ($t in $tops) {
        if ($t -notin $lockedDirs) { continue }
        $dir = Join-Path $Destination $t
        $fresh = -not (Test-Path -LiteralPath $dir -PathType Container)
        [void][System.IO.Directory]::CreateDirectory($dir)
        if ($RestrictAccess -and $fresh) {
            try {
                & icacls.exe $dir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
                if ($LASTEXITCODE -ne 0) { Say 'WARN' "icacls could not restrict $dir (exit $LASTEXITCODE)." } else { Say 'OK' "Access to $t\ : Administrators and SYSTEM only." }
            }
            catch { Say 'WARN' "icacls could not restrict ${dir}: $($_.Exception.Message)" }
        }
        elseif ($RestrictAccess) { Say 'INFO' "$t\ existed already: its access rights were not changed." }
    }
    foreach ($dr in @($m['directories'])) {
        if (-not $dr) { continue }
        $d = [string]$dr
        if ($d.StartsWith('pki/') -and -not $restorePki.Contains(($d.Substring(4) -split '/')[0])) { continue }
        [void][System.IO.Directory]::CreateDirectory((Join-Path $Destination ($d -replace '/', [System.IO.Path]::DirectorySeparatorChar)))
    }
    $n = 0
    foreach ($e in $toWrite) {
        $rel = ([string]$e['path']).Substring(5)
        $from = Join-Path $opened.Dir (([string]$e['path']) -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        $to = Join-Path $Destination ($rel -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $to))
        Copy-Item -LiteralPath $from -Destination $to -Force
        $n++
    }
    Say 'INFO' "$n files written. Checking them against the backup ..."
    $bad = 0
    foreach ($e in $toWrite) {
        $to = Join-Path $Destination (([string]$e['path']).Substring(5) -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $to) -or (Get-BkHash $to).Sha256 -ne [string]$e['sha256']) { Say 'ERROR' "Does not match: $to"; $bad++ }
    }
    if ($bad -gt 0) { Stop-Bk "$bad restored file(s) do not match the backup." 6 }
    Say 'OK' "Restored $n files into $Destination; every file matches the backup."
    foreach ($k in $skipPki.Keys) { Say 'INFO' "Not restored (already there): PKI $k - $($skipPki[$k])" }
    Write-Host ''
    Say 'INFO' 'Next: in the restored folder run  .\pki_setup.ps1 -ListPki  (the PKIs), and  .\pki_setup.ps1 -InstallTrust  to trust them again in the Windows stores.'
    if (-not $RestrictAccess) { Say 'INFO' 'The keys got the access rights of the destination folder. Use -RestrictAccess next time to limit them to Administrators and SYSTEM.' }
}
finally {
    if ($opened) { Remove-Item -LiteralPath $opened.Dir -Recurse -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
exit 0
