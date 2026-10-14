# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
<#
.SYNOPSIS
    Checks that a PKI backup is still valid: SHA-256 and SHA-512 of the .certpacked and of every file next to it. -Deep also decrypts it.
    Windows 11 Home/Pro 24H2+ or Windows Server 2025, Intel/AMD 64 bit, Administrator PowerShell 7. Full help: .\Test-PkiBackup.ps1 -Help
.EXAMPLE
    .\Test-PkiBackup.ps1
.EXAMPLE
    .\Test-PkiBackup.ps1 -Backup .\backup-pki -Deep
#>
param(
    [string]$Backup,
    [switch]$Deep,
    [switch]$Help
)

function Show-Help {
@'
============================================================
 Test-PkiBackup.ps1 - is the backup (the .certpacked) still valid?
 Version 5.3.5
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
WHAT IT DOES
  Reads SHA256SUMS and SHA512SUMS of the backup and compares them with the real files: the .certpacked, the scripts, the README. A single changed
  byte (a damaged disk, a bad copy, a changed script) is found. No password is needed and nothing is changed or restored.
  -Deep   also asks for the backup password, decrypts the .certpacked and checks the SHA-256 of every file inside (proves the password still works).

USE
  .\Test-PkiBackup.ps1                          (run from the unzipped backup folder: it checks the folder it is in)
  .\Test-PkiBackup.ps1 -Backup <path>           <path> = one backup zip | an unzipped backup folder | the backup-pki folder (every zip in it is checked)
  .\Test-PkiBackup.ps1 -Backup .\backup-pki -Deep

OPTIONS
  -Backup <path>   what to check (see above). Default: the folder of this script.
  -Deep            decrypt the .certpacked too (asks for the password)
  -Help

STANDALONE   This script needs no other .ps1 (the shared code is built into it).
OUTPUT   one line per file: OK or FAIL, then a total. EXIT CODES   0 everything is valid   1 error   2 not an Administrator window   3 wrong password
         5 system not supported (Windows version / edition / ARM)   6 a checksum does not match (the backup is damaged or was changed)
WHERE IT RUNS   Windows 11 Home or Pro 24H2+, Windows Server 2025 Essentials / Standard / Datacenter; Intel or AMD 64 bit only; Administrator PowerShell 7.
============================================================
'@ | Write-Host
}

if ($Help) { Show-Help; return }
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host '[ERROR] Test-PkiBackup.ps1 needs PowerShell 7 or newer (this window is PowerShell' $PSVersionTable.PSVersion.ToString() '). Run Prepare-Computer.ps1 in an Administrator window to install it, then start this script with  pwsh . Nothing was done.' -ForegroundColor Red
    exit 4
}

$ErrorActionPreference = 'Stop'
#@@EMBED-LIBRARY@@
Set-StrictMode -Version Latest

Write-BkBanner 'Test-PkiBackup.ps1' 'check a PKI backup'
[void](Assert-BkHost)

function Test-OneFolder {
    # returns the number of problems
    param([string]$Dir, [string]$Label)
    $bad = 0; $ok = 0
    Say 'INFO' "Checking $Label"
    $s256 = Join-Path $Dir 'SHA256SUMS'; $s512 = Join-Path $Dir 'SHA512SUMS'
    if (-not (Test-Path -LiteralPath $s256)) { Say 'ERROR' 'SHA256SUMS is missing: this is not a backup folder, or the file was deleted.'; return 1 }
    $cps = @(Get-ChildItem -LiteralPath $Dir -Filter '*.certpacked' -File)
    if ($cps.Count -ne 1) { Say 'ERROR' "The folder must hold exactly one .certpacked (found $($cps.Count))."; $bad++ }
    $a = Get-BkSumsFile $s256
    $b = $(if (Test-Path -LiteralPath $s512) { Get-BkSumsFile $s512 } else { $null })
    if ($null -eq $b) { Say 'WARN' 'SHA512SUMS is missing: only SHA-256 is checked.' }
    foreach ($k in $a.Keys) {
        $fp = Join-Path $Dir ($k -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $fp)) { Write-Host ("  FAIL  {0}  (missing)" -f $k) -ForegroundColor Red; $bad++; continue }
        $h = Get-BkHash $fp
        $why = ''
        if ($h.Sha256 -ne $a[$k]) { $why = 'SHA-256 differs' }
        elseif ($null -ne $b -and $b.Contains($k) -and $h.Sha512 -ne $b[$k]) { $why = 'SHA-512 differs' }
        elseif ($null -ne $b -and -not $b.Contains($k)) { $why = 'not in SHA512SUMS' }
        if ($why) { Write-Host ("  FAIL  {0}  ({1})" -f $k, $why) -ForegroundColor Red; $bad++ } else { Write-Host ("  OK    {0}" -f $k) -ForegroundColor Green; $ok++ }
    }
    foreach ($f in @(Get-ChildItem -LiteralPath $Dir -Recurse -File)) {
        $rel = $f.FullName.Substring($Dir.TrimEnd('\', '/').Length).TrimStart('\', '/') -replace '\\', '/'
        if ($rel -in 'SHA256SUMS', 'SHA512SUMS') { continue }
        if (-not $a.Contains($rel)) { Write-Host ("  FAIL  {0}  (not listed in SHA256SUMS: added later?)" -f $rel) -ForegroundColor Red; $bad++ }
    }
    if ($Deep -and $cps.Count -eq 1) {
        $script:BkDeepPassword = $(if ($script:BkDeepPassword) { $script:BkDeepPassword } else { Read-BkExistingPassword 'Backup password' })
        $o = Open-BkPackage -Path $cps[0].FullName -Password $script:BkDeepPassword
        try { Write-Host ("  OK    deep check: the password opens the .certpacked and all {0} files inside match" -f @($o.Manifest['files']).Count) -ForegroundColor Green; $ok++ }
        finally { Remove-Item -LiteralPath $o.Dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    if ($bad -eq 0) { Say 'OK' "$Label : valid ($ok checks passed)." } else { Say 'ERROR' "$Label : $bad problem(s), $ok checks passed." }
    return $bad
}

$script:BkDeepPassword = $null
if (-not $Backup) { $Backup = $PSScriptRoot }
if (-not (Test-Path -LiteralPath $Backup)) { Stop-Bk "Not found: $Backup" 1 }
$Backup = (Resolve-Path -LiteralPath $Backup).Path
$work = New-BkTempDirectory 'pkitest'
$problems = 0
try {
    if (-not (Get-Item -LiteralPath $Backup).PSIsContainer) {
        if ($Backup -notlike '*.zip') { Stop-Bk 'Give a backup zip (pki-payload-....zip), an unzipped backup folder, or the backup-pki folder.' 1 }
        $dirs = @(,$Backup)
    }
    elseif (Test-Path -LiteralPath (Join-Path $Backup 'SHA256SUMS')) { $dirs = @(,$Backup) }
    else {
        $dirs = @(Get-ChildItem -LiteralPath $Backup -Filter 'pki-payload-*.zip' -File | Sort-Object Name | ForEach-Object { $_.FullName })
        $dirs += @(Get-ChildItem -LiteralPath $Backup -Directory | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'SHA256SUMS') } | ForEach-Object { $_.FullName })
        if ($dirs.Count -eq 0) { Stop-Bk "No backup found in $Backup (no pki-payload-*.zip and no unzipped backup folder)." 1 }
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $i = 0
    foreach ($d in $dirs) {
        $i++
        if ($d -like '*.zip') {
            $ex = Join-Path $work "z$i"
            try { [System.IO.Compression.ZipFile]::ExtractToDirectory($d, $ex) } catch { Say 'ERROR' "$(Split-Path -Leaf $d): the zip itself is damaged ($($_.Exception.Message))"; $problems++; continue }
            $root = @(Get-ChildItem -LiteralPath $ex -Directory)
            $use = $(if ($root.Count -eq 1 -and -not (Test-Path -LiteralPath (Join-Path $ex 'SHA256SUMS'))) { $root[0].FullName } else { $ex })
            $problems += (Test-OneFolder -Dir $use -Label (Split-Path -Leaf $d))
        }
        else { $problems += (Test-OneFolder -Dir $d -Label $d) }
    }
}
finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host ''
if ($problems -gt 0) { Stop-Bk "$problems problem(s): the backup is damaged or was changed. Do not restore from it; use another copy." 6 }
Say 'OK' 'Everything is valid.'
exit 0
