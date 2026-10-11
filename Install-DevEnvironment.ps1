# ============================================================
# Install-DevEnvironment.ps1
#
# Windows 11 Developer Environment Bootstrap
#
# Author  : Nicko Satria Utama
# Company : Agantra Inovatif OÜ (NextMantra)
#
# ============================================================
#
# PURPOSE
# -------
# Prepare a fresh Windows 11 Home / Professional installation
# for modern software development.
#
# SUPPORTED STARTING ENVIRONMENTS
# -------------------------------
# 1. Original Windows 11 Home / Professional
#    - Windows PowerShell 5.1
# 2. Windows 11 OOBE image with PowerShell 7.x
#    - PowerShell 7.0.x through 7.6.x
#
# POWERSHELL TARGET
# -----------------
# PowerShell 7 LTS
#
# DEVELOPMENT TOOLS
# -----------------
# PowerShell 7       Latest available LTS
# .NET 10 SDK        Latest .NET 10 SDK
# .NET 8 SDK         Latest .NET 8 LTS
# Node.js             Latest
# Go                  Latest
# PHP                 Latest
# Python              Latest stable
# Git                 Latest
# OpenSSL             FireDaemon OpenSSL with FIPS & Quantum-Safe Cryptography
# Windows Terminal    Latest
# 7-Zip               Latest (the archive tool of the PKI transport: AES-256 zip, 7z)
#
# REVISION 4.9 (additive; everything above still works)
#   -Help       usage            -Check    scan only, installs nothing        -Only <list>   install just these components
#   -Skip7Zip   7-Zip is installed when missing
#   -Unblock    UNBLOCK + UNLOCK this folder (also done silently at every start)
#   OpenSSL     version is checked (4.0.1 or newer, upgraded through winget when older) and PROVEN: FIPS provider, ML-DSA,
#               ML-KEM, ML-DSA inside FIPS. oqsprovider is optional now (-WithOqsProvider): OpenSSL 4 has native ML-DSA and
#               ML-KEM, and the master openssl.cnf only mentions oqsprovider when its DLL really exists.
#
# ============================================================

#requires -Version 5.1

param(
    [switch]$SkipPowerShell,
    [switch]$SkipDotNet,
    [switch]$SkipNodeJS,
    [switch]$SkipGo,
    [switch]$SkipPHP,
    [switch]$SkipPython,
    [switch]$SkipGit,
    [switch]$SkipOpenSSL,
    [switch]$SkipWindowsTerminal,
    [switch]$Skip7Zip,
    [ValidateSet('PowerShell','DotNet','NodeJS','Go','PHP','Python','Git','OpenSSL','7Zip','WindowsTerminal')][string[]]$Only,
    [switch]$WithOqsProvider,
    [switch]$Check,
    [switch]$Unblock,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Show-DevEnvHelp {
    @'
============================================================
 Install-DevEnvironment.ps1 - Windows 11 developer bootstrap
 Version 4.9
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
============================================================
 Manual : docs\Install-DevEnvironment-MANUAL.txt     Linux / macOS sibling: Install-DevEnvironment.sh

WHAT IT DOES   (run in an ELEVATED PowerShell; -Check, -Help and -Unblock need no elevation)
  Installs through WinGet what is missing: PowerShell 7, .NET 10 and 8 SDK, Node.js, Go, PHP, Python, Git, 7-Zip, FireDaemon
  OpenSSL (FIPS + quantum-safe), Windows Terminal. Then it PROVES OpenSSL: version 4.0.1 or newer, FIPS provider active,
  ML-DSA sign / verify, ML-KEM key generation, ML-DSA inside the FIPS provider.

USAGE
  .\Install-DevEnvironment.ps1                          everything
  .\Install-DevEnvironment.ps1 -Check                   scan only: what is installed, OpenSSL readiness; changes nothing
  .\Install-DevEnvironment.ps1 -Only OpenSSL,7Zip       just these (what the PKI scripts need)
  .\Install-DevEnvironment.ps1 -SkipPHP -SkipGo         everything except these
  .\Install-DevEnvironment.ps1 -Unblock                 UNBLOCK + UNLOCK this folder, children and recursive, then stop

PARAMETERS
  -Only <list>           PowerShell, DotNet, NodeJS, Go, PHP, Python, Git, OpenSSL, 7Zip, WindowsTerminal. Installs only these.
  -SkipPowerShell -SkipDotNet -SkipNodeJS -SkipGo -SkipPHP -SkipPython -SkipGit -SkipOpenSSL -SkipWindowsTerminal -Skip7Zip
  -Check                 Scan only. Exit code 0 when OpenSSL is ready, 4 when it is not.
  -WithOqsProvider       Also download the third-party oqsprovider (NOT needed: OpenSSL 4 has native ML-DSA and ML-KEM).
                         Without it the master openssl.cnf does not mention oqsprovider at all.
  -Unblock               UNBLOCK (Internet mark) and UNLOCK (Read-only) every file below this script's folder, then stop.
                         The same is done silently at every start, before anything else.
  -Help                  This text.

OPENSSL
  FireDaemon.OpenSSL is installed by WinGet. If it reports less than 4.0.1 the script runs "winget upgrade". It then writes
  fipsmodule.cnf (openssl fipsinstall), the machine variables OPENSSL_MODULES and OPENSSL_CONF, and a master openssl.cnf that
  activates the default and FIPS providers. The PKI scripts ignore OPENSSL_CONF (they use their own configuration).

EXIT CODES   0 ok   1 error (for example not elevated)   4 OpenSSL not ready
'@
}
if ($Help) { Show-DevEnvHelp; exit 0 }

# UNBLOCK + UNLOCK of this script's folder, children and recursive, BEFORE anything else (Windows PowerShell 5.1 safe).
function Invoke-BootstrapUnlock {
    param([string]$Root)
    $ro = [System.IO.FileAttributes]::ReadOnly
    $unlocked = 0; $unblocked = 0
    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root)) { return @{ Unlocked = 0; Unblocked = 0 } }
    $items = @(Get-Item -LiteralPath $Root -Force) + @(Get-ChildItem -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue)
    foreach ($i in $items) {
        try { if (($i.Attributes -band $ro) -ne 0) { $i.Attributes = $i.Attributes -bxor $ro; $unlocked++ } } catch { }
        if (-not $i.PSIsContainer) {
            try { if ($null -ne (Get-Item -LiteralPath $i.FullName -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue)) { Unblock-File -LiteralPath $i.FullName -ErrorAction Stop; $unblocked++ } } catch { }
        }
    }
    return @{ Unlocked = $unlocked; Unblocked = $unblocked }
}
$BootstrapUnlock = @{ Unlocked = 0; Unblocked = 0 }
try { $BootstrapUnlock = Invoke-BootstrapUnlock -Root $PSScriptRoot } catch { }
if ($Unblock) {
    Write-Host ('UNBLOCK + UNLOCK (children and recursive): {0}' -f $PSScriptRoot) -ForegroundColor Cyan
    Write-Host ('Unblocked {0} file(s) (Internet mark), unlocked {1} item(s) (Read-only).' -f $BootstrapUnlock.Unblocked, $BootstrapUnlock.Unlocked) -ForegroundColor Green
    exit 0
}
if ($Only -and @($Only).Count -gt 0) {
    $SkipPowerShell = ($Only -notcontains 'PowerShell'); $SkipDotNet = ($Only -notcontains 'DotNet'); $SkipNodeJS = ($Only -notcontains 'NodeJS')
    $SkipGo = ($Only -notcontains 'Go'); $SkipPHP = ($Only -notcontains 'PHP'); $SkipPython = ($Only -notcontains 'Python')
    $SkipGit = ($Only -notcontains 'Git'); $SkipOpenSSL = ($Only -notcontains 'OpenSSL'); $Skip7Zip = ($Only -notcontains '7Zip')
    $SkipWindowsTerminal = ($Only -notcontains 'WindowsTerminal')
}

# ============================================================
# GLOBAL VARIABLES
# ============================================================

$ScriptName = 'Install-DevEnvironment.ps1'
$BootstrapStart = Get-Date

$LogRoot = Join-Path $env:ProgramData 'Agantra\WindowsDeveloperBootstrap\Logs'

if (-not (Test-Path -LiteralPath $LogRoot)) {
    New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
}

$LogFile = Join-Path $LogRoot ('Install-DevEnvironment-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

# ============================================================
# COLOR HELPERS
# ============================================================

function Write-Console {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )
    Write-Host $Message -ForegroundColor $Color
}

function Write-Banner {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title
    )
    Write-Host ''
    Write-Console '============================================================' Cyan
    Write-Console (' {0}' -f $Title) Cyan
    Write-Console '============================================================' Cyan
    Write-Host ''
}

# ============================================================
# LOGGING
# ============================================================

function Get-ElapsedText {
    $Elapsed = (Get-Date) - $BootstrapStart
    return ('{0:00}:{1:00}:{2:00}.{3:000}' -f [int]$Elapsed.TotalHours, $Elapsed.Minutes, $Elapsed.Seconds, $Elapsed.Milliseconds)
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet('INFO', 'STEP', 'SUCCESS', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO'
    )

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $Elapsed = Get-ElapsedText
    $Line = '[{0}] [+{1}] [{2}] {3}' -f $Timestamp, $Elapsed, $Level, $Message

    switch ($Level) {
        'INFO'    { Write-Console $Line Gray }
        'STEP'    { Write-Console $Line Cyan }
        'SUCCESS' { Write-Console $Line Green }
        'WARN'    { Write-Console $Line Yellow }
        'ERROR'   { Write-Console $Line Red }
        'DEBUG'   { Write-Console $Line DarkGray }
    }

    try {
        Add-Content -LiteralPath $LogFile -Value $Line -Encoding UTF8
    }
    catch {
        # Logging must never terminate the bootstrap.
    }
}

# ============================================================
# ADMINISTRATOR CHECK
# ============================================================

function Test-IsAdministrator {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ============================================================
# START
# ============================================================

Write-Banner 'Windows 11 Developer Environment Bootstrap'
Write-Log 'Bootstrap starting.' 'STEP'
Write-Log ('Script: {0}' -f $ScriptName)
Write-Log ('PowerShell process ID: {0}' -f $PID)
Write-Log ('Current user: {0}' -f $env:USERNAME)
Write-Log ('Computer: {0}' -f $env:COMPUTERNAME)

if (-not $Check -and -not (Test-IsAdministrator)) {
    Write-Log 'Administrator privileges are required.' 'ERROR'
    Write-Host ''
    Write-Console 'Run PowerShell as Administrator and execute the script again.' Red
    Write-Host ''
    exit 1
}

if (Test-IsAdministrator) { Write-Log 'Administrator privileges confirmed.' 'SUCCESS' } else { Write-Log 'Check mode: not elevated (nothing will be installed).' 'INFO' }

# ============================================================
# WINDOWS INFORMATION
# ============================================================

$OS = Get-CimInstance Win32_OperatingSystem
Write-Banner 'Windows Environment'
Write-Log ('Operating System : {0}' -f $OS.Caption)
Write-Log ('Windows Version  : {0}' -f $OS.Version)
Write-Log ('Windows Build    : {0}' -f $OS.BuildNumber)

if ($OS.Caption -notmatch 'Windows 11') {
    Write-Log 'This bootstrap is designed for Windows 11.' 'WARN'
} else {
    Write-Log 'Windows 11 detected.' 'SUCCESS'
}

# ============================================================
# POWERSHELL HOST DETECTION
# ============================================================

function Get-PowerShellHostInformation {
    return @{
        Major   = [int]$PSVersionTable.PSVersion.Major
        Minor   = [int]$PSVersionTable.PSVersion.Minor
        Patch   = [int]$PSVersionTable.PSVersion.Patch
        Version = $PSVersionTable.PSVersion.ToString()
        Edition = if ($PSEdition -eq 'Core') { 'PowerShell 7+' } else { 'Windows PowerShell 5.1' }
    }
}

$CurrentPS = Get-PowerShellHostInformation
Write-Banner 'PowerShell Host Detection'
Write-Log ('Detected edition : {0}' -f $CurrentPS.Edition)
Write-Log ('Detected version : {0}' -f $CurrentPS.Version)

# ============================================================
# PATH FUNCTIONS
# ============================================================

function Normalize-PathEntry {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    return $Path.Trim().TrimEnd('\').ToLowerInvariant()
}

function Get-PersistentPathEntries {
    param([string]$Scope)
    $Value = [Environment]::GetEnvironmentVariable('Path', $Scope)
    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
    return @($Value -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
}

function Add-PersistentPath {
    param([string]$Path, [string]$Scope)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return }
    $Entries = Get-PersistentPathEntries -Scope $Scope
    $Target = Normalize-PathEntry -Path $Path
    foreach ($Entry in $Entries) {
        if ((Normalize-PathEntry -Path $Entry) -eq $Target) { return }
    }
    $Entries += $Path
    [Environment]::SetEnvironmentVariable('Path', ($Entries -join ';'), $Scope)
    Write-Log ('Added {0} PATH: {1}' -f $Scope, $Path) 'SUCCESS'
}

function Remove-DuplicatePersistentPath {
    param([string]$Scope)
    $Entries = Get-PersistentPathEntries -Scope $Scope
    $Unique = @()
    $Seen = @{}
    foreach ($Entry in $Entries) {
        $Normalized = Normalize-PathEntry -Path $Entry
        if (-not [string]::IsNullOrWhiteSpace($Normalized) -and -not $Seen.ContainsKey($Normalized)) {
            $Seen[$Normalized] = $true
            $Unique += $Entry
        }
    }
    [Environment]::SetEnvironmentVariable('Path', ($Unique -join ';'), $Scope)
}

function Refresh-CurrentProcessPath {
    $MachinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $Combined = @()
    if ($MachinePath) { $Combined += $MachinePath -split ';' }
    if ($UserPath) { $Combined += $UserPath -split ';' }
    
    $Unique = @()
    $Seen = @{}
    foreach ($Entry in $Combined) {
        $Normalized = Normalize-PathEntry -Path $Entry
        if (-not [string]::IsNullOrWhiteSpace($Normalized) -and -not $Seen.ContainsKey($Normalized)) {
            $Seen[$Normalized] = $true
            $Unique += $Entry.Trim()
        }
    }
    $env:Path = $Unique -join ';'
}

# ============================================================
# WINGET DETECTION
# ============================================================

function Get-WinGetPath {
    $Command = Get-Command 'winget.exe' -ErrorAction SilentlyContinue
    if ($null -ne $Command) { return $Command.Source }
    $Candidate = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
    if (Test-Path -LiteralPath $Candidate) { return $Candidate }
    return $null
}

Refresh-CurrentProcessPath
$Winget = Get-WinGetPath

if ([string]::IsNullOrWhiteSpace($Winget)) {
    Write-Banner 'WinGet'
    Write-Log 'WinGet was not detected.' 'ERROR'
    exit 1
}

Write-Banner 'WinGet'
Write-Log ('WinGet executable: {0}' -f $Winget) 'SUCCESS'

# ============================================================
# WINGET INSTALL / UPGRADE
# ============================================================

function Install-OrUpgrade-WinGetPackage {
    param([string]$Id, [string]$Name, [string]$Version = $null)
    Write-Banner $Name
    Write-Log ('Package ID: {0}' -f $Id) 'STEP'

    $Args = @('install', '--id', $Id, '--exact', '--source', 'winget', '--accept-source-agreements', '--accept-package-agreements', '--silent', '--disable-interactivity')
    if ($Version) { $Args += @('--version', $Version) }

    & $Winget @Args 2>&1 | ForEach-Object { Write-Log $_.ToString() 'DEBUG' }
    if ($LASTEXITCODE -eq 0) {
        Write-Log ('{0} processing completed.' -f $Name) 'SUCCESS'
    } else {
        Write-Log ('WinGet operation returned exit code {0}.' -f $LASTEXITCODE) 'WARN'
    }
    Refresh-CurrentProcessPath
}

# ============================================================
# OPENSSL 4: FIND AND PROVE  (Windows PowerShell 5.1 safe)
# ============================================================

function Invoke-NativeCapture {
    param([string]$Exe, [string[]]$Arguments, [string]$ConfPath)
    $oldEap = $ErrorActionPreference; $oldConf = $env:OPENSSL_CONF
    $ErrorActionPreference = 'Continue'
    if ($ConfPath) { $env:OPENSSL_CONF = $ConfPath }
    try { $out = & $Exe @Arguments 2>&1 | ForEach-Object { $_.ToString() }; $code = $LASTEXITCODE }
    catch { $out = @($_.Exception.Message); $code = 1 }
    finally { $ErrorActionPreference = $oldEap; $env:OPENSSL_CONF = $oldConf }
    return @{ ExitCode = $code; Output = (@($out) -join "`n") }
}

function Get-OpenSslVersionInfo {
    param([string]$Exe)
    $r = Invoke-NativeCapture -Exe $Exe -Arguments @('version')
    if ($r.Output -match '^OpenSSL\s+(\d+)\.(\d+)\.?(\d*)') {
        $patch = 0; if ($Matches[3]) { $patch = [int]$Matches[3] }
        return @{ Exe = $Exe; Text = ($r.Output -split "`n")[0].Trim(); Major = [int]$Matches[1]; Minor = [int]$Matches[2]; Patch = $patch }
    }
    return $null
}

function Test-OpenSslVersionOk {
    param($Info)
    if ($null -eq $Info) { return $false }
    return ([version]('{0}.{1}.{2}' -f $Info.Major, $Info.Minor, $Info.Patch) -ge [version]'4.0.1')
}

function Get-BestOpenSsl {
    $cands = @()
    foreach ($c in @(Get-Command 'openssl.exe' -All -ErrorAction SilentlyContinue)) { if ($c.Source) { $cands += $c.Source } }
    foreach ($d in 'FireDaemon OpenSSL 4', 'FireDaemon OpenSSL', 'FireDaemon OpenSSL 3', 'OpenSSL-Win64', 'OpenSSL') {
        $p = Join-Path $env:ProgramFiles ($d + '\bin\openssl.exe'); if (Test-Path -LiteralPath $p) { $cands += $p }
    }
    $best = $null
    foreach ($c in ($cands | Select-Object -Unique)) {
        $v = Get-OpenSslVersionInfo -Exe $c
        if ((Test-OpenSslVersionOk $v) -and ($null -eq $best -or [version]('{0}.{1}.{2}' -f $v.Major, $v.Minor, $v.Patch) -gt [version]('{0}.{1}.{2}' -f $best.Major, $best.Minor, $best.Patch))) { $best = $v }
    }
    return $best
}

function Write-ReadyRow {
    param([string]$Status, [string]$Name, [string]$Text)
    $col = 'Green'; if ($Status -eq 'FAIL') { $col = 'Red' } elseif ($Status -eq 'WARN') { $col = 'Yellow' }
    Write-Console ('[{0}] {1,-16} {2}' -f $Status, $Name, $Text) $col
}

# The proof: version, FIPS provider active, ML-DSA sign + verify, ML-KEM key generation, ML-DSA inside the FIPS provider.
function Test-OpenSslReadiness {
    param([string]$Exe)
    $all = $true
    $tmp = Join-Path $env:TEMP ('ossl-ready-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    try {
        $v = Get-OpenSslVersionInfo -Exe $Exe
        if (Test-OpenSslVersionOk $v) { Write-ReadyRow 'PASS' 'version' $v.Text } else { Write-ReadyRow 'FAIL' 'version' ('4.0.1 or newer is required (found: {0})' -f $(if ($v) { $v.Text } else { 'nothing runnable' })); $all = $false }

        $base = Split-Path -Parent (Split-Path -Parent $Exe)
        $fipsCnf = $null
        foreach ($c in (Join-Path $base 'ssl\fipsmodule.cnf'), (Join-Path (Split-Path -Parent $Exe) 'fipsmodule.cnf')) { if (Test-Path -LiteralPath $c) { $fipsCnf = $c; break } }
        $neutral = Join-Path $tmp 'neutral.cnf'
        Set-Content -LiteralPath $neutral -Encoding ASCII -Value "openssl_conf = openssl_init`r`n[openssl_init]`r`nproviders = provider_sect`r`n[provider_sect]`r`ndefault = default_sect`r`n[default_sect]`r`nactivate = 1`r`n"
        $fipsTest = $null
        if ($fipsCnf) {
            $fipsTest = Join-Path $tmp 'fips.cnf'
            $inc = $fipsCnf -replace '\\', '/'
            Set-Content -LiteralPath $fipsTest -Encoding ASCII -Value ("openssl_conf = openssl_init`r`n.include $inc`r`n[openssl_init]`r`nproviders = provider_sect`r`n[provider_sect]`r`nfips = fips_sect`r`nbase = base_sect`r`n[base_sect]`r`nactivate = 1`r`n")
            $r = Invoke-NativeCapture -Exe $Exe -Arguments @('list', '-providers', '-provider', 'fips', '-provider', 'base') -ConfPath $fipsTest
            if ($r.ExitCode -eq 0 -and $r.Output -match 'fips') { Write-ReadyRow 'PASS' 'FIPS provider' ('active ({0})' -f $fipsCnf) } else { Write-ReadyRow 'FAIL' 'FIPS provider' ('does not load with {0}' -f $fipsCnf); $all = $false; $fipsTest = $null }
        } else { Write-ReadyRow 'FAIL' 'FIPS provider' 'fipsmodule.cnf not found (run this script without -Check to create it)'; $all = $false }

        Set-Content -LiteralPath (Join-Path $tmp 'd.txt') -Value 'hello' -Encoding ASCII
        $k = Join-Path $tmp 'k.pem'; $d = Join-Path $tmp 'd.txt'; $sg = Join-Path $tmp 's.bin'
        $a = Invoke-NativeCapture -Exe $Exe -Arguments @('genpkey', '-algorithm', 'ML-DSA-65', '-out', $k) -ConfPath $neutral
        $b = Invoke-NativeCapture -Exe $Exe -Arguments @('pkeyutl', '-sign', '-inkey', $k, '-rawin', '-in', $d, '-out', $sg) -ConfPath $neutral
        $c2 = Invoke-NativeCapture -Exe $Exe -Arguments @('pkeyutl', '-verify', '-inkey', $k, '-rawin', '-in', $d, '-sigfile', $sg) -ConfPath $neutral
        if ($a.ExitCode -eq 0 -and $b.ExitCode -eq 0 -and $c2.ExitCode -eq 0) { Write-ReadyRow 'PASS' 'ML-DSA' 'ML-DSA-65 key, sign and verify (post-quantum signatures)' } else { Write-ReadyRow 'FAIL' 'ML-DSA' 'ML-DSA-65 sign / verify failed'; $all = $false }
        $kem = Join-Path $tmp 'kem.pem'
        $e = Invoke-NativeCapture -Exe $Exe -Arguments @('genpkey', '-algorithm', 'ML-KEM-768', '-out', $kem) -ConfPath $neutral
        if ($e.ExitCode -eq 0 -and (Test-Path -LiteralPath $kem)) { Write-ReadyRow 'PASS' 'ML-KEM' 'ML-KEM-768 key generation (post-quantum key exchange)' } else { Write-ReadyRow 'FAIL' 'ML-KEM' 'ML-KEM-768 key generation failed'; $all = $false }
        if ($fipsTest) {
            $kf = Join-Path $tmp 'kf.pem'
            $f = Invoke-NativeCapture -Exe $Exe -Arguments @('genpkey', '-provider', 'fips', '-propquery', 'fips=yes', '-algorithm', 'ML-DSA-65', '-out', $kf) -ConfPath $fipsTest
            if ($f.ExitCode -eq 0 -and (Test-Path -LiteralPath $kf)) { Write-ReadyRow 'PASS' 'ML-DSA in FIPS' 'ML-DSA-65 key inside the FIPS provider' } else { Write-ReadyRow 'WARN' 'ML-DSA in FIPS' 'not available inside the FIPS provider of this build' }
        }
        # the machine-wide configuration of this script must load without provider errors
        if ($env:OPENSSL_CONF) {
            $m = Invoke-NativeCapture -Exe $Exe -Arguments @('list', '-providers')
            if ($m.ExitCode -eq 0 -and $m.Output -notmatch '(?i)unable to load|could not load|error') { Write-ReadyRow 'PASS' 'machine config' ('OPENSSL_CONF loads cleanly ({0})' -f $env:OPENSSL_CONF) }
            else { Write-ReadyRow 'WARN' 'machine config' 'OPENSSL_CONF prints provider errors (a provider named there is missing). The PKI scripts are not affected.' }
        }
    }
    finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    return $all
}

# ============================================================
# -Check: SCAN ONLY
# ============================================================
if ($Check) {
    Write-Banner 'Scan (nothing is installed)'
    $scan = @(
        @('PowerShell 7', 'pwsh'), @('.NET SDK', 'dotnet'), @('Node.js', 'node'), @('Go', 'go'), @('PHP', 'php'),
        @('Python', 'python'), @('Git', 'git'), @('Windows Terminal', 'wt')
    )
    foreach ($x in $scan) {
        $cmd = Get-Command $x[1] -ErrorAction SilentlyContinue
        if ($cmd) { Write-ReadyRow 'PASS' $x[0] $cmd.Source } else { Write-ReadyRow 'WARN' $x[0] 'not found' }
    }
    $z = Join-Path $env:ProgramFiles '7-Zip\7z.exe'
    if ((Test-Path -LiteralPath $z) -or (Get-Command '7z' -ErrorAction SilentlyContinue)) { Write-ReadyRow 'PASS' '7-Zip' $(if (Test-Path -LiteralPath $z) { $z } else { '7z on PATH' }) } else { Write-ReadyRow 'WARN' '7-Zip' 'not found' }
    Write-Host ''
    Write-Console 'OPENSSL READINESS  (4.x with FIPS and quantum-safe)' Cyan
    $b = Get-BestOpenSsl
    if ($b) {
        $okCheck = Test-OpenSslReadiness -Exe $b.Exe
        Write-Host ''
        if ($okCheck) { Write-Console 'READY: OpenSSL 4 with the FIPS provider, ML-DSA and ML-KEM.' Green; exit 0 }
        Write-Console 'NOT READY: see above. Run this script (elevated) without -Check.' Red; exit 4
    }
    Write-ReadyRow 'FAIL' 'OpenSSL' 'no OpenSSL 4.0.1 or newer found'
    Write-Console 'NOT READY: run  .\Install-DevEnvironment.ps1 -Only OpenSSL  (elevated).' Red
    exit 4
}

# ============================================================
# POWERSHELL INSTALL
# ============================================================

if (-not $SkipPowerShell) {
    Install-OrUpgrade-WinGetPackage -Id 'Microsoft.PowerShell' -Name 'PowerShell 7'
    Add-PersistentPath -Path (Join-Path $env:ProgramFiles 'PowerShell\7') -Scope Machine
    Add-PersistentPath -Path (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps') -Scope User
    Refresh-CurrentProcessPath
}

# ============================================================
# .NET 10 & 8
# ============================================================

if (-not $SkipDotNet) {
    Install-OrUpgrade-WinGetPackage -Id 'Microsoft.DotNet.SDK.10' -Name '.NET 10 SDK'
    Install-OrUpgrade-WinGetPackage -Id 'Microsoft.DotNet.SDK.8' -Name '.NET 8 SDK LTS'
    Add-PersistentPath -Path "$env:ProgramFiles\dotnet" -Scope Machine
    Refresh-CurrentProcessPath
}

# ============================================================
# NODE.JS, GO, PHP, PYTHON, GIT
# ============================================================

if (-not $SkipNodeJS) {
    Install-OrUpgrade-WinGetPackage -Id 'OpenJS.NodeJS' -Name 'Node.js'
    Add-PersistentPath -Path "$env:ProgramFiles\nodejs" -Scope Machine
}

if (-not $SkipGo) {
    Install-OrUpgrade-WinGetPackage -Id 'GoLang.Go' -Name 'Go'
    Add-PersistentPath -Path "$env:ProgramFiles\Go\bin" -Scope Machine
}

if (-not $SkipPHP) {
    Install-OrUpgrade-WinGetPackage -Id 'PHP.PHP' -Name 'PHP'
}

if (-not $SkipPython) {
    Install-OrUpgrade-WinGetPackage -Id 'Python.PythonInstallManager' -Name 'Python Install Manager'
}

if (-not $SkipGit) {
    Install-OrUpgrade-WinGetPackage -Id 'Git.Git' -Name 'Git for Windows'
    Add-PersistentPath -Path "$env:ProgramFiles\Git\cmd" -Scope Machine
}

# ============================================================
# 7-ZIP  (the archive tool of the PKI transport)
# ============================================================

if (-not $Skip7Zip) {
    $SevenZipExe = Join-Path $env:ProgramFiles '7-Zip\7z.exe'
    if (Test-Path -LiteralPath $SevenZipExe) {
        Write-Log ('7-Zip already installed: {0}' -f $SevenZipExe) 'SUCCESS'
    } else {
        Install-OrUpgrade-WinGetPackage -Id '7zip.7zip' -Name '7-Zip'
    }
    Add-PersistentPath -Path (Join-Path $env:ProgramFiles '7-Zip') -Scope Machine
    Refresh-CurrentProcessPath
}

# ============================================================
# FIREDAEMON OPENSSL WITH FIPS & QUANTUM (OQS)
# ============================================================

if (-not $SkipOpenSSL) {
    Write-Banner 'FireDaemon OpenSSL (FIPS + Quantum-Safe PQC)'

    # 1. Enforce WinGet Download & Install of FireDaemon OpenSSL
    Install-OrUpgrade-WinGetPackage -Id 'FireDaemon.OpenSSL' -Name 'FireDaemon OpenSSL'

    # Candidate directories where FireDaemon OpenSSL binary and modules reside
    $CandidateDirs = @(
        "$env:ProgramFiles\FireDaemon OpenSSL",
        "$env:ProgramFiles\FireDaemon OpenSSL 3",
        "$env:ProgramFiles\FireDaemon OpenSSL 4",
        "$env:ProgramFiles\OpenSSL",
        "C:\Program Files\FireDaemon OpenSSL"
    )

    $OpenSSLBase = $null
    foreach ($Dir in $CandidateDirs) {
        if (Test-Path -LiteralPath "$Dir\bin\openssl.exe") {
            $OpenSSLBase = $Dir
            break
        }
    }

    if (-not $OpenSSLBase) {
        Write-Log 'FireDaemon OpenSSL executable was not found after WinGet installation.' 'ERROR'
    } else {
        $BinDir = Join-Path $OpenSSLBase 'bin'
        $OpenSSLExe = Join-Path $BinDir 'openssl.exe'
        
        Add-PersistentPath -Path $BinDir -Scope Machine
        Refresh-CurrentProcessPath

        Write-Log ('Located FireDaemon OpenSSL at: {0}' -f $OpenSSLExe) 'SUCCESS'

        # The package must really be OpenSSL 4.0.1 or newer: upgrade through WinGet when it is older.
        $FdInfo = Get-OpenSslVersionInfo -Exe $OpenSSLExe
        if ($FdInfo) { Write-Log ('FireDaemon OpenSSL reports: {0}' -f $FdInfo.Text) 'INFO' }
        if (-not (Test-OpenSslVersionOk $FdInfo)) {
            Write-Log 'This OpenSSL is older than 4.0.1: trying "winget upgrade FireDaemon.OpenSSL".' 'WARN'
            & $Winget upgrade --id 'FireDaemon.OpenSSL' --exact --source winget --accept-source-agreements --accept-package-agreements --silent --disable-interactivity 2>&1 | ForEach-Object { Write-Log $_.ToString() 'DEBUG' }
            Refresh-CurrentProcessPath
            $FdInfo = Get-OpenSslVersionInfo -Exe $OpenSSLExe
            if (Test-OpenSslVersionOk $FdInfo) { Write-Log ('Upgraded: {0}' -f $FdInfo.Text) 'SUCCESS' }
            else { Write-Log 'Still older than 4.0.1. The PKI scripts need 4.0.1 or newer; install a newer FireDaemon OpenSSL by hand.' 'ERROR' }
        }

        # Enforce module directory location
        $OsslModulesDir = Join-Path $BinDir 'ossl-modules'
        if (-not (Test-Path -LiteralPath $OsslModulesDir)) {
            $OsslModulesDir = Join-Path $OpenSSLBase 'lib\ossl-modules'
        }
        if (-not (Test-Path -LiteralPath $OsslModulesDir)) {
            New-Item -ItemType Directory -Path (Join-Path $BinDir 'ossl-modules') -Force | Out-Null
            $OsslModulesDir = Join-Path $BinDir 'ossl-modules'
        }

        [Environment]::SetEnvironmentVariable('OPENSSL_MODULES', $OsslModulesDir, 'Machine')
        $env:OPENSSL_MODULES = $OsslModulesDir

        # Enforce SSL configuration directory
        $SslDir = Join-Path $OpenSSLBase 'ssl'
        if (-not (Test-Path -LiteralPath $SslDir)) {
            $SslDir = Join-Path $OpenSSLBase 'bin'
        }
        if (-not (Test-Path -LiteralPath $SslDir)) {
            New-Item -ItemType Directory -Path $SslDir -Force | Out-Null
        }

        $MainCnf = Join-Path $SslDir 'openssl.cnf'
        [Environment]::SetEnvironmentVariable('OPENSSL_CONF', $MainCnf, 'Machine')
        $env:OPENSSL_CONF = $MainCnf

        # ----------------------------------------------------
        # 2. ENFORCE FIPS MODULE CONFIGURATION
        # ----------------------------------------------------
        Write-Log 'Enforcing FireDaemon OpenSSL FIPS Module Configuration...' 'STEP'
        $FipsCnf = Join-Path $SslDir 'fipsmodule.cnf'
        $FipsDll = Get-ChildItem -Path $OpenSSLBase -Filter "fips.dll" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

        if ($FipsDll) {
            Write-Log ('Located fips.dll at: {0}' -f $FipsDll.FullName) 'INFO'
            & $OpenSSLExe fipsinstall -out "$FipsCnf" -module "$($FipsDll.FullName)" 2>&1 | ForEach-Object { Write-Log $_.ToString() 'DEBUG' }
        } else {
            Write-Log 'fips.dll not found in installation path. Generating baseline FIPS configuration file...' 'WARN'
        }

        if (-not (Test-Path -LiteralPath $FipsCnf)) {
            $FipsConfigContent = @"
[fips_sect]
activate = 1
conditional_errors = 1
security_checks = 1
"@
            Set-Content -Path $FipsCnf -Value $FipsConfigContent -Encoding UTF8
            Write-Log 'Generated baseline fipsmodule.cnf configuration.' 'SUCCESS'
        } else {
            Write-Log 'fipsmodule.cnf generated and verified.' 'SUCCESS'
        }

        # ----------------------------------------------------
        # 3. ENFORCE QUANTUM-SAFE (OQS) PROVIDER MODULE
        # ----------------------------------------------------
        Write-Log 'Enforcing Quantum-Safe Cryptography (OQS Provider)...' 'STEP'
        $OqsDllPath = Join-Path $OsslModulesDir 'oqsprovider.dll'

        if (-not $WithOqsProvider) {
            Write-Log 'oqsprovider is not installed: OpenSSL 4 has native ML-DSA and ML-KEM (use -WithOqsProvider to add the third-party provider).' 'INFO'
        } elseif (-not (Test-Path -LiteralPath $OqsDllPath)) {
            try {
                Write-Log 'Downloading Quantum-Safe OQS Provider binary module...' 'INFO'
                $OqsReleaseUrl = 'https://github.com/open-quantum-safe/oqs-provider/releases/latest/download/oqsprovider-win64.zip'
                $ZipPath = Join-Path $env:TEMP 'oqsprovider-win64.zip'
                $ExtractPath = Join-Path $env:TEMP 'oqsprovider-extract'

                Invoke-WebRequest -Uri $OqsReleaseUrl -OutFile $ZipPath -UseBasicParsing
                Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force
                
                $DownloadedOqsDll = Get-ChildItem -Path $ExtractPath -Filter 'oqsprovider.dll' -Recurse | Select-Object -First 1
                if ($DownloadedOqsDll) {
                    Copy-Item -Path $DownloadedOqsDll.FullName -Destination $OqsDllPath -Force
                    Write-Log ('oqsprovider.dll installed to: {0}' -f $OqsDllPath) 'SUCCESS'
                }
                Remove-Item -Path $ZipPath, $ExtractPath -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Log ('Failed to retrieve OQS Provider: {0}' -f $_.Exception.Message) 'WARN'
            }
        } else {
            Write-Log ('oqsprovider.dll verified at: {0}' -f $OqsDllPath) 'INFO'
        }

        # ----------------------------------------------------
        # 4. ENFORCE MASTER OPENSSL.CNF CONFIGURATION
        # ----------------------------------------------------
        Write-Log 'Enforcing master openssl.cnf configuration for FIPS and Quantum...' 'STEP'
        $FipsIncludePath = ($FipsCnf -replace '\\', '/')

        $OqsProviderLine = ''
        $OqsSection = ''
        if (Test-Path -LiteralPath $OqsDllPath) { $OqsProviderLine = 'oqsprovider = oqsprovider_sect'; $OqsSection = "[oqsprovider_sect]`r`nactivate = 1" }

        $MasterConfig = @"
# ============================================================
# FireDaemon OpenSSL Configuration (FIPS + Quantum-Safe)
# ============================================================

.include $FipsIncludePath

openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
fips = fips_sect
$OqsProviderLine

[default_sect]
activate = 1

[fips_sect]
activate = 1

$OqsSection
"@

        Set-Content -Path $MainCnf -Value $MasterConfig -Encoding UTF8
        Write-Log ('Master configuration successfully enforced in: {0}' -f $MainCnf) 'SUCCESS'
    }

    Refresh-CurrentProcessPath
}

# ============================================================
# WINDOWS TERMINAL
# ============================================================

if (-not $SkipWindowsTerminal) {
    Install-OrUpgrade-WinGetPackage -Id 'Microsoft.WindowsTerminal' -Name 'Windows Terminal'
}

# ============================================================
# PATH CLEANUP & FINAL SCAN
# ============================================================

Write-Banner 'PATH Cleanup'
Remove-DuplicatePersistentPath -Scope Machine
Remove-DuplicatePersistentPath -Scope User
Refresh-CurrentProcessPath

Write-Banner 'Final OpenSSL & Provider Diagnostic Scan'

try {
    Write-Console '--- OpenSSL Version ---' Cyan
    & openssl version

    Write-Console '--- Active Providers (FIPS / Quantum) ---' Cyan
    & openssl provider -a

    Write-Console '--- Quantum Cryptography Algorithms ---' Cyan
    & openssl list -signature-algorithms | Select-String -Pattern "ML-DSA|dilithium|falcon|sphincs" -ErrorAction SilentlyContinue
    & openssl list -kem-algorithms | Select-String -Pattern "ML-KEM|kyber" -ErrorAction SilentlyContinue
} catch {
    Write-Log 'Failed to execute OpenSSL diagnostic verification.' 'WARN'
}

# ============================================================
# OPENSSL READINESS (PROOF)
# ============================================================

$OpenSslReady = $true
if (-not $SkipOpenSSL) {
    Write-Banner 'OpenSSL Readiness (4.x with FIPS and quantum-safe)'
    $BestSsl = Get-BestOpenSsl
    if ($BestSsl) { $OpenSslReady = Test-OpenSslReadiness -Exe $BestSsl.Exe }
    else { Write-Log 'No OpenSSL 4.0.1 or newer was found.' 'ERROR'; $OpenSslReady = $false }
}

# ============================================================
# FINAL TELEMETRY
# ============================================================

$BootstrapEnd = Get-Date
$TotalElapsed = $BootstrapEnd - $BootstrapStart

Write-Banner 'Installation Summary'
Write-Console ('Start time       : {0}' -f $BootstrapStart.ToString('yyyy-MM-dd HH:mm:ss')) Gray
Write-Console ('End time         : {0}' -f $BootstrapEnd.ToString('yyyy-MM-dd HH:mm:ss')) Gray
Write-Console ('Total duration   : {0:00}:{1:00}:{2:00}.{3:000}' -f [int]$TotalElapsed.TotalHours, $TotalElapsed.Minutes, $TotalElapsed.Seconds, $TotalElapsed.Milliseconds) Green
Write-Console ('Log file         : {0}' -f $LogFile) Gray

Write-Host ''
if ($OpenSslReady) {
    Write-Console 'Developer environment bootstrap completed successfully.' Green
} else {
    Write-Console 'Bootstrap finished, but OpenSSL is NOT ready (see the readiness table above).' Red
    exit 4
}
Write-Host ''
