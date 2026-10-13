# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    DevKit, Windows: makes the *.sh files of this folder ready for Linux - LF line endings (a CRLF .sh fails on Linux with
    "$'\r': command not found") and the executable bit - without any Linux knowledge.
.DESCRIPTION
    .\Make-ShExecutable.ps1                     this folder, recursive
    .\Make-ShExecutable.ps1 -Path D:\share\kit  another folder
    The line endings are always fixed (it is a plain file rewrite). The executable bit needs a Linux file system:
      * WSL installed  : the script runs   wsl chmod +x   on the files (works for folders under C:\ ... through /mnt/c, and for \\wsl$ paths)
      * pwsh on Linux / macOS: it runs chmod +x
      * otherwise       : nothing can be set on an NTFS folder; the files get the bit when they are unpacked on Linux
                          (run   bash make-executable.sh   there, or start them with   bash ./script.sh   - that needs no executable bit).
    Full help: .\Make-ShExecutable.ps1 -Help
#>
param([string]$Path = $PSScriptRoot, [switch]$LineEndingsOnly, [switch]$Help)
$ErrorActionPreference = 'Stop'
if ($Help) {
@'
============================================================
 Make-ShExecutable.ps1 - make the .sh files executable (Windows developers)
 Version 5.0.0
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : docs\DevKit-MANUAL.txt     Linux twin: make-executable.sh

 .\Make-ShExecutable.ps1                    all *.sh and lib\*.sh of this folder
 .\Make-ShExecutable.ps1 -Path <folder>     another folder (recursive)
 .\Make-ShExecutable.ps1 -LineEndingsOnly   only CRLF -> LF

 1. CRLF -> LF in every .sh / .py / .env  (the usual reason why a script copied from Windows fails on Ubuntu).
 2. chmod +x: through WSL (wsl chmod) or, when pwsh runs on Linux / macOS, chmod. Without WSL on Windows the bit cannot be
    set; use  bash ./GenerateLeafCertificate.sh ...  (works without the bit) or run  bash make-executable.sh  on the Ubuntu machine.

WHERE IT RUNS  (5.0.0)
  Windows 11 24H2 or newer (Home, Pro, Pro for Workstations, Education, Pro Education, Enterprise), Windows Server 2025 and Windows Server 2022
  (Essentials, Standard, Datacenter; RTM or newer). On Windows Server 2022 only the CLASSIC track is generated or issued (no Quantum / ML-DSA);
  FIPS and non-FIPS, DV / OV / EV are available. REFUSED with an error (exit 5, nothing is done): Windows 10 and earlier, Windows 11 before 24H2,
  Windows Server before 2022, and the Chinese, Government, IoT / IoT Enterprise, SE and Embedded editions. Linux (pwsh): the distributions of the
  .sh scripts. Settings shared by all scripts (optional): pki_tools.cnf.
'@ | Write-Host
    exit 0
}

# Where may this script run? Windows 11 24H2+ / Server 2025 / Server 2022 (classic only), supported Linux. Error and exit 5 otherwise.
$__pf = Join-Path $PSScriptRoot 'scripts/00a_Platform.ps1'
if (-not (Test-Path -LiteralPath $__pf)) { [Console]::Error.WriteLine('[ERROR] scripts/00a_Platform.ps1 is missing: the operating system cannot be checked. Nothing was done.'); exit 5 }
. $__pf; Assert-PkiPlatform
$root = (Resolve-Path -LiteralPath $Path).Path
$files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force | Where-Object { $_.Extension -in '.sh', '.py', '.env' -or $_.Name -eq 'SHA256SUMS' })
$fixed = 0
foreach ($f in $files) {
    $t = [System.IO.File]::ReadAllText($f.FullName)
    if ($t.Contains("`r")) { [System.IO.File]::WriteAllText($f.FullName, ($t -replace "`r`n", "`n" -replace "`r", "`n"), [System.Text.UTF8Encoding]::new($false)); $fixed++ }
}
Write-Host "[OK] $($files.Count) shell/helper file(s) checked, $fixed converted from CRLF to LF." -ForegroundColor Green
if ($LineEndingsOnly) { exit 0 }
$sh = @($files | Where-Object { $_.Extension -eq '.sh' })
if ($sh.Count -eq 0) { Write-Host '[INFO] no .sh file found.'; exit 0 }
if (-not $IsWindows) {
    foreach ($f in $sh) { & chmod +x $f.FullName }
    Write-Host "[OK] chmod +x on $($sh.Count) file(s)." -ForegroundColor Green; exit 0
}
$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
if ($wsl) {
    $linuxRoot = (& wsl.exe wslpath -a ($root -replace '\\', '/') 2>$null | Select-Object -First 1)
    if ($linuxRoot) {
        & wsl.exe -e find $linuxRoot -type f -name '*.sh' -exec chmod +x '{}' +
        if ($LASTEXITCODE -eq 0) { Write-Host "[OK] wsl chmod +x done for $($sh.Count) file(s) under $linuxRoot." -ForegroundColor Green; exit 0 }
    }
    Write-Host '[WARN] WSL is installed but chmod through it failed.' -ForegroundColor Yellow
}
Write-Host '[INFO] The executable bit cannot be set from Windows without WSL. That is fine:' -ForegroundColor Cyan
Write-Host '       - start the scripts with  bash ./GenerateLeafCertificate.sh ...  (no executable bit needed), or'
Write-Host '       - on the Ubuntu machine, in the unpacked folder:  bash make-executable.sh'
exit 0
