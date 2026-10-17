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
    [switch]$Yes,
    [switch]$Check,
    [switch]$RestrictAccess,
    [switch]$Help
)

function Show-Help {
@'
====================================================================================================
 Restore-Pki.ps1  -  put a PKI backup back
 Version 6.4.7
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
====================================================================================================
 On a terminal: SPACE = next page, ENTER = next line, Q = quit.
 Manual : docs\PkiBackup-MANUAL.txt     Related: Backup-Pki.ps1, Test-PkiBackup.ps1
 Needs  : Windows, an Administrator PowerShell 7 window, and the software of Prepare-Computer.ps1.

WHAT IT IS
  It reads a backup made by Backup-Pki.ps1 and writes the PKI back to a folder. It is careful:
  it writes only what is missing. It deletes nothing and overwrites nothing without asking.

QUICK START  (on a new computer)
  1. Unzip the backup zip. Open a Windows PowerShell as administrator in that folder.
  2. Install the software, once:               .\Prepare-Computer.ps1
  3. Open a NEW administrator PowerShell 7 (pwsh) in the same folder.
  4. Check the backup:                          .\Test-PkiBackup.ps1
  5. Try the restore (nothing is written):
       .\Restore-Pki.ps1 -Destination C:\PKI-DevSecOps -Check
  6. Restore:
       .\Restore-Pki.ps1 -Destination C:\PKI-DevSecOps
  7. In the restored folder:                    .\pki_setup.ps1 -InstallTrust

WHAT IT DOES, IN ORDER  (it stops at the first problem, before anything is written)
  1. The computer: Windows 11 Home or Pro 24H2+, or Windows Server 2025, Intel/AMD 64 bit,
     Administrator window. Otherwise it is refused.
  2. The software: PowerShell 7, OpenSSL 4, Python 3, .NET SDK 8 and .NET SDK 10 on the PATH. What
     is missing is listed. Then you must run Prepare-Computer.ps1 (exit 4).
  3. The checksums of the files in the zip (SHA256SUMS).
  4. The password. Every file inside the .certpacked is decrypted and checked.
  5. ONE BY ONE, each PKI of the backup is compared with this computer:
       - the folder <Destination>\pki\<name>: every file by SHA-256 (identical, different, missing)
       - the Local Machine certificate store (Root and Intermediate): every CA certificate by
         thumbprint
  6. The other files (leafcerts, external-ca, csr-signed, settings) are compared file by file.
  7. The missing files are written. Then every written file is checked again.
  While it runs, the decrypted files are in a temporary folder of the administrator. The folder is
  deleted at the end, also after an error.

WHAT IT RESTORES, WHAT IT SKIPS
  - A PKI whose folder is there with all files identical: skipped.
  - A PKI whose CA certificates are ALL in the Local Machine store: skipped. The store holds
    certificates, not private keys. -Force restores the keys anyway.
  - A PKI folder that is there but different: you are asked "Replace it with the version from the
    backup? [Y/n]". Enter = Y. With Y the old folder is renamed to
    <name>.before-restore-<time> (never deleted) and the backup version is written. With n the old
    one stays. With nobody to ask (no keyboard) the old one stays.
  - Everything else that is missing is written.
  - If nothing is missing: "Nothing to restore" and nothing is changed (exit 0).
  - ONLY YOUR PKI: certificates of other CAs in an older backup are listed as "Not restored".

OPTIONS
  -Package <path>      The backup zip, the .certpacked, or a folder that holds one. Default: the
                       .certpacked next to this script.
  -Destination <dir>   The project folder to restore into. Default: the folder of this script when
                       it is the project (it has pki_setup.ps1). A script from the backup zip needs
                       -Destination.
  -Check               Do everything except writing: password, checksums, comparison, the list of
                       what would be restored.
  -Yes                 Answer Y to every "replace?" question. Old folders and files are still
                       renamed, never deleted.
  -Force               Restore anyway. A PKI folder or file that exists is RENAMED to
                       <name>.before-restore-<yyyymmdd-HHmmss> first. A PKI that is only in the
                       Local Machine store is restored too.
  -RestrictAccess      pki\, leafcerts\, external-ca\ and csr-signed\ get access for Administrators
                       and SYSTEM only (icacls), BEFORE the keys are written.
  -Help                This text.

AFTER IT
  The Windows certificate stores are not in the backup. Run  pki_setup.ps1 -InstallTrust  in the
  restored folder to trust the PKI again.

EXIT CODES
  0 ok    1 error    2 not an Administrator window    3 wrong password
  4 Prepare-Computer.ps1 not run (software missing)    5 system not supported
  6 a checksum does not match (the backup is damaged or was changed)
====================================================================================================
'@ | Write-Host
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

if ($Help) { Invoke-PagedHelp { Show-Help }; return }
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host '[ERROR] Restore-Pki.ps1 needs PowerShell 7 or newer (this window is PowerShell' $PSVersionTable.PSVersion.ToString() '). Run Prepare-Computer.ps1 in an Administrator window to install it, then start this script with  pwsh . Nothing was done.' -ForegroundColor Red
    exit 4
}

$ErrorActionPreference = 'Stop'
#@@EMBED-LIBRARY@@
Set-StrictMode -Version Latest

$script:BkAssumeYes = [bool]$Yes
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
    # ONLY YOUR PKI: certificates of other CAs (DigiCert, GlobalSign, Sectigo ...) are never restored, whatever this backup holds
    $dataDir = Join-Path $opened.Dir 'data'
    $ownOrgs = @(Get-BkOwnOrganizations -Root $dataDir)
    Say 'INFO' 'Looking at every certificate and key of the backup: which are yours ...'
    $inv = Get-BkKeyInventory -Root $dataDir -Folders @('pki', 'leafcerts', 'external-ca', 'csr-signed') -OwnOrgs $ownOrgs
    if ($ownOrgs.Count -eq 0) { Say 'WARN' 'The backup holds no <company>_pki.cnf with an Organization: your PKI cannot be told from other CAs; everything is restored.' }
    else {
        $before = $entries.Count
        $entries = @($entries | Where-Object { -not (Test-BkExcluded -Rel (([string]$_['path']).Substring(5)) -Inventory $inv) })
        Say 'INFO' ("Your PKI      : organization(s) {0}. Only these are restored." -f (($ownOrgs | Sort-Object) -join ', '))
        if ($before -ne $entries.Count) {
            Say 'INFO' ("Not restored  : {0} file(s) of other CAs (not your PKI)" -f ($before - $entries.Count))
            foreach ($fs in ($inv.Foreign | Select-Object -First 8)) { Say 'INFO' "  other CA: $fs" }
        }
    }
    $pkiList = @(@($m['pkiFolders']) | Where-Object { -not $inv.ExcludedFolders.Contains([string]$_) })
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
    $skipPki = @{}; $restorePki = [System.Collections.Generic.List[string]]::new(); $replacePki = [System.Collections.Generic.List[string]]::new()
    Write-Host ''
    Say 'INFO' 'Comparing the PKIs of the backup with this computer, one by one ...'
    foreach ($name in $pkiList) {
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
        # the CA certificates of YOUR PKI (from the decrypted files, not from a list): only these are looked for in the store
        $cas = @($inv.Certificates | Where-Object { $_.Own -and $_.IsCa -and $_.Rel -like "pki/$name/*" } | Group-Object Thumbprint | ForEach-Object { $_.Group[0] } | Sort-Object @{ Expression = { -not $_.SelfSigned } }, Subject)
        $inStore = 0
        foreach ($ca in $cas) {
            $has = $storeSet.Contains($ca.Thumbprint)
            if ($has) { $inStore++ }
            Write-Host ("    {0,-12} : {1}  {2}" -f $(if ($ca.SelfSigned) { 'root' } else { 'intermediate' }), $(if ($has) { 'in Local Machine store' } else { 'NOT in Local Machine store' }), ($ca.Subject -replace '^.*?CN=([^,]+).*$', '$1')) -ForegroundColor $(if ($has) { 'Green' } else { 'Gray' })
        }
        $storeAll = ($cas.Count -gt 0 -and $inStore -eq $cas.Count)
        if ($cas.Count -eq 0) { Write-Host '    store         : (this backup does not list the CA certificates of this PKI: store not compared)' }
        # decision
        if ($folderComplete -and -not $Force) { $skipPki[$name] = 'already in the pki folder (every file identical)'; Say 'OK' "    -> not restored: $($skipPki[$name])." }
        elseif ($folderExists -and -not $folderComplete -and -not $Force) {
            # an older version of your PKI is there: offer the version of the backup (Enter = Y)
            $ans = $true
            if ($Check) { Say 'INFO' "    -> (-Check) would ask: replace this PKI with the version in the backup? [Y/n]" }
            else { $ans = Read-BkYesNo ("    PKI {0} is in the pki folder already ({1} identical, {2} different, {3} missing). Replace it with the version in the backup? The old folder is renamed, not deleted." -f $name, $same, $diff, $miss) }
            if ($ans -eq $true) { [void]$restorePki.Add($name); [void]$replacePki.Add($name); Say 'INFO' '    -> will be replaced with the backup version (the old folder is renamed).' }
            elseif ($ans -eq $false) { $skipPki[$name] = 'you answered N: the pki folder is left as it is'; Say 'WARN' "    -> not restored: $($skipPki[$name])." }
            else { $skipPki[$name] = 'the pki folder has this PKI with different files and nobody can be asked (no keyboard): left alone; use -Yes or -Force to replace it'; Say 'WARN' "    -> not restored: $($skipPki[$name])." }
        }
        elseif ($storeAll -and -not $Force) { $skipPki[$name] = "all $($cas.Count) CA certificates are in the Local Machine certificate store"; Say 'OK' "    -> not restored: $($skipPki[$name]). (Only the certificates are in the store, not the private keys: -Force restores the keys anyway.)" }
        else { [void]$restorePki.Add($name); if ($folderExists) { [void]$replacePki.Add($name) }; Say 'INFO' "    -> will be restored$(if ($folderExists) { ' (the existing folder is renamed first)' })." }
    }

    # the other files (leafcerts, external-ca, csr-signed, *_pki.cnf ...): file by file
    $extra = @($entries | Where-Object { -not ([string]$_['path']).StartsWith('data/pki/') })
    $xReplace = 0; $xWrite = [System.Collections.Generic.List[object]]::new(); $xSame = 0; $xDiff = [System.Collections.Generic.List[object]]::new()
    foreach ($e in $extra) {
        $to = Join-Path $Destination (([string]$e['path']).Substring(5) -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $to -PathType Leaf)) { [void]$xWrite.Add($e) }
        elseif ((Get-BkHash $to).Sha256 -eq [string]$e['sha256']) { $xSame++ }
        else { if ($Force) { [void]$xWrite.Add($e) }; [void]$xDiff.Add($e) }
    }
    if ($xDiff.Count -gt 0 -and -not $Force) {
        $ansX = $true
        if ($Check) { Say 'INFO' "(-Check) would ask: replace $($xDiff.Count) other file(s) with the backup version? [Y/n]" }
        else { $ansX = Read-BkYesNo ("{0} other file(s) (leafcerts, external-ca, csr-signed, settings) differ from the backup. Replace them with the backup version? The old files are renamed, not deleted." -f $xDiff.Count) }
        if ($ansX -eq $true) { foreach ($e in $xDiff) { [void]$xWrite.Add($e) }; $xReplace = $xDiff.Count }
        else { Say 'WARN' "$($xDiff.Count) different file(s) are left as they are." }
    }
    if ($extra.Count -gt 0) {
        Write-Host ''
        Say 'INFO' ("Other files (leafcerts, external-ca, csr-signed, settings): {0} in the backup, {1} already there and identical, {2} missing, {3} there but different{4}" -f $extra.Count, $xSame, ($xWrite.Count - $xReplace), $xDiff.Count, $(if ($xDiff.Count -gt 0) { $(if ($Force -or $xReplace -gt 0) { ' (replaced, the old files are renamed)' } else { ' (left alone)' }) } else { '' }))
    }

    $pkiFiles = @($entries | Where-Object { $p = ([string]$_['path']); $restorePki.Contains(($p.Substring(9) -split '/')[0]) -and $p.StartsWith('data/pki/') })
    $toWrite = @($pkiFiles) + @($xWrite)
    Write-Host ''
    if ($toWrite.Count -eq 0) {
        if (@($skipPki.Values | Where-Object { $_ -like 'the pki folder has this PKI*' -or $_ -like 'you answered N*' }).Count -gt 0) { Say 'WARN' 'Nothing was restored: a PKI folder differs from the backup and was left as it is (see above). -Yes or -Force replaces it (the old folder is renamed). Nothing was changed.' }
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
