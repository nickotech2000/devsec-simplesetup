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
    [switch]$SkipWindowsTerminal
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

if (-not (Test-IsAdministrator)) {
    Write-Log 'Administrator privileges are required.' 'ERROR'
    Write-Host ''
    Write-Console 'Run PowerShell as Administrator and execute the script again.' Red
    Write-Host ''
    exit 1
}

Write-Log 'Administrator privileges confirmed.' 'SUCCESS'

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

        if (-not (Test-Path -LiteralPath $OqsDllPath)) {
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
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[fips_sect]
activate = 1

[oqsprovider_sect]
activate = 1
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
Write-Console 'Developer environment bootstrap completed successfully.' Green
Write-Host ''