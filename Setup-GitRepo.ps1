# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Prepares the git repository of the PKI scripts so that a "git clone" on Linux / WSL gives runnable scripts:
    execute bit (mode 100755) for every .sh / .py in the index, hooks on, LF everywhere, folder 'Scripts' -> 'scripts'.
    Full help: .\Setup-GitRepo.ps1 -Help
.EXAMPLE
    .\Setup-GitRepo.ps1
.EXAMPLE
    .\Setup-GitRepo.ps1 -FixCase -Commit
#>
param(
    [string]$Repo = $PSScriptRoot,
    [switch]$FixCase,
    [switch]$Commit,
    [switch]$Check,
    [switch]$Help
)
$ErrorActionPreference = 'Stop'

if ($Help) {
@'
============================================================
 Setup-GitRepo.ps1 - make the private GitHub repository clone-and-run on Ubuntu / WSL
 Version 5.3.6     Author: Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com
============================================================
WHY
  Windows git does not know the Unix execute bit: a new .sh is stored with mode 100644 and a Linux clone gets files that cannot be
  started ("Permission denied"). Git hooks are not copied by a clone either. This script fixes both in the repository itself.

WHAT IT DOES (run it in the working copy on Windows, once, and after you add a new .sh / .py)
  1  git config core.hooksPath .githooks   (pre-commit gives every staged .sh / .py the execute bit and refuses CRLF, a BOM and private keys;
                                             post-checkout / post-merge / post-rewrite chmod the scripts on Linux)
  2  git config core.autocrlf false, core.eol lf, core.fileMode true (when the file system allows it)
  3  git update-index --chmod=+x for every tracked or untracked-but-addable .sh and .py   -> mode 100755 in the index
  4  converts CRLF / BOM in the scripts and text files to LF (.gitattributes keeps them LF)
  5  -FixCase: renames a tracked 'Scripts' folder to 'scripts' (the code loads scripts/PkiModules.ps1; Linux is case sensitive)
  6  -Commit: git add of the changes above and one commit. Without it nothing is committed.
  -Check   only report what would change (exit 1 when something would)

REPOSITORY LAYOUT (what the scripts expect)
  *.ps1, agantra_pki.cnf, README.md                                 repository root
  docs/                         every manual (*-MANUAL.txt), the design, the checklists, the other documentation text files
  scripts/                      the PowerShell modules (00..21, PkiModules.ps1)
  linux/                        Install-DevEnvironment.sh, pki-transport.sh, fix-permissions.sh, setup-git.sh, pki-server/ (the server kit)
  devkit/                       the source of the DevKit (PkiTransport.ps1 -DevKit): Install-PkiTrust, shell generators, lib/, START-HERE
  .githooks/, .gitattributes, .gitignore

AFTER "git clone" ON LINUX / WSL
  git clone git@github.com:nickotech2000/devsec-simplesetup.git && cd devsec-simplesetup
  ./linux/pki-server/pki-server.sh --help          (works at once: the index holds 100755)
  bash linux/setup-git.sh                           (turns the hooks on in this clone and repairs the bits if a tool lost them)
  If a .sh still says "Permission denied" or "bad interpreter: /usr/bin/env bash^M":  bash linux/fix-permissions.sh
  Cloned onto /mnt/c (Windows disk) in WSL? Mounted without 'metadata' the execute bit cannot be stored: clone into ~ (the Linux
  file system) or run  bash linux/fix-permissions.sh.

The PKI itself (pki\, leafcerts\, *.key) is in .gitignore: it never goes to GitHub. Use New-PkiServerPackage.ps1 to move the PKI.
============================================================

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

function Write-Msg { param([string]$T, [string]$L = 'INFO') $c = switch ($L) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'ERROR' { 'Red' } default { 'Cyan' } }; Write-Host "[$L] $T" -ForegroundColor $c }
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Write-Msg 'git was not found in PATH.' 'ERROR'; exit 1 }
$Repo = (Resolve-Path -LiteralPath $Repo).Path
Push-Location $Repo
try {
    $top = (& git rev-parse --show-toplevel 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $top) { Write-Msg "$Repo is not a git working copy (git init, or clone the repository first)." 'ERROR'; exit 1 }
    Set-Location $top
    $changes = 0
    $utf8 = [System.Text.UTF8Encoding]::new($false)

    # 1, 2 configuration
    if (-not $Check) {
        git config core.hooksPath .githooks; git config core.autocrlf false; git config core.eol lf
        Write-Msg 'git config: core.hooksPath=.githooks, core.autocrlf=false, core.eol=lf' 'OK'
    } elseif ((git config core.hooksPath) -ne '.githooks') { Write-Msg 'hooks are not enabled (core.hooksPath)' 'WARN'; $changes++ }

    # 5 case
    $tracked = @(git ls-files)
    $upper = @($tracked | Where-Object { $_ -cmatch '^Scripts/' })
    if ($upper.Count -gt 0) {
        if ($FixCase -and -not $Check) {
            git mv -f Scripts scripts_tmp_case 2>&1 | Out-Null; git mv -f scripts_tmp_case scripts
            Write-Msg "renamed the folder Scripts -> scripts ($($upper.Count) files)" 'OK'
        } else { Write-Msg "the repository has the folder 'Scripts', the code loads 'scripts' (Linux is case sensitive): run with -FixCase" 'WARN'; $changes++ }
    }

    # 4 line endings (working tree)
    $textExt = '\.(sh|py|ps1|txt|cnf|json|md|crt|pem|pub)$'
    $files = @(git ls-files --cached --others --exclude-standard) | Where-Object { $_ -match $textExt -and (Test-Path -LiteralPath $_ -PathType Leaf) }
    foreach ($f in $files) {
        $b = [System.IO.File]::ReadAllBytes((Join-Path $top $f))
        $hasBom = $b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF
        $hasCr = $b -contains 13
        if ($hasCr -or ($hasBom -and $f -match '\.(sh|py|cnf|pem|crt|pub)$')) {
            $changes++
            if ($Check) { Write-Msg "CRLF/BOM: $f" 'WARN'; continue }
            $s = $utf8.GetString($b); if ($s.Length -gt 0 -and $s[0] -eq [char]0xFEFF -and $f -notmatch '\.ps1$') { $s = $s.Substring(1) }
            [System.IO.File]::WriteAllBytes((Join-Path $top $f), $utf8.GetBytes(($s -replace "`r`n", "`n")))
            Write-Msg "LF: $f" 'INFO'
        }
    }

    # 3 execute bit in the index
    $shs = @(git ls-files --cached --others --exclude-standard) | Where-Object { $_ -match '\.(sh|py)$' -or $_ -like '.githooks/*' }
    $nExec = 0
    foreach ($f in $shs) {
        $mode = (git ls-files -s -- $f 2>$null) -split '\s+' | Select-Object -First 1
        if ($mode -eq '100755') { continue }
        $changes++; $nExec++
        if ($Check) { Write-Msg "mode $mode (needs 100755): $f" 'WARN'; continue }
        git add -- $f 2>&1 | Out-Null
        git update-index --chmod=+x -- $f
    }
    if (-not $Check) { Write-Msg "execute bit (100755) set in the index for $nExec file(s); $(@($shs).Count) script(s) checked" 'OK' }

    if ($Check) { if ($changes -gt 0) { Write-Msg "$changes thing(s) to fix: run .\Setup-GitRepo.ps1" 'WARN'; exit 1 } else { Write-Msg 'repository is clone-and-run ready' 'OK'; exit 0 } }

    if ($Commit) {
        git add -A -- . 2>&1 | Out-Null
        git update-index --chmod=+x -- @(git ls-files '*.sh' '*.py' '.githooks/*')
        $st = git status --porcelain
        if ($st) {
            git commit -m "Linux scripts: execute bit, LF, hooks (Setup-GitRepo.ps1)" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>" | Out-Null
            if ($LASTEXITCODE -ne 0) { Write-Msg 'git commit failed (the pre-commit hook refused it: see the lines above).' 'ERROR'; exit 1 }
            Write-Msg 'committed. Push it: git push' 'OK'
        } else { Write-Msg 'nothing to commit' 'INFO' }
    } else { Write-Msg 'Not committed (use -Commit, or: git commit -m "...").  The pre-commit hook keeps the execute bit for new scripts.' 'INFO' }
    $bad = @(git ls-files -s | Where-Object { $_ -match '\.(sh|py)$' -and $_ -notmatch '^100755' })
    if ($bad.Count -gt 0) { Write-Msg "still without execute bit in the index: $($bad.Count)" 'WARN' } else { Write-Msg 'every .sh / .py in the index is 100755' 'OK' }
}
finally { Pop-Location }
exit 0
