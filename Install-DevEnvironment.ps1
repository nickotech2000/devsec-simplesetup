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
#
# 1. Original Windows 11 Home / Professional
#    - Windows PowerShell 5.1
#
# 2. Windows 11 OOBE image with PowerShell 7.x
#    - PowerShell 7.0.x
#    - PowerShell 7.1.x
#    - PowerShell 7.2.x
#    - PowerShell 7.3.x
#    - PowerShell 7.4.x
#    - PowerShell 7.5.x
#    - PowerShell 7.6.x
#
# The script detects the CURRENT PowerShell host instead of
# assuming a specific starting version.
#
# POWERSHELL TARGET
# -----------------
#
# Current target:
#
#     PowerShell 7.6.6 LTS
#
# The script does NOT hard-code the target installer version.
# WinGet is queried for the currently available
# Microsoft.PowerShell package.
#
# Therefore, when a newer LTS becomes available, the same
# bootstrap can install the newer package without changing
# this script.
#
# IMPORTANT:
# PowerShell 7 does NOT replace Windows PowerShell 5.1.
# Both can exist side-by-side.
#
# ============================================================
#
# DEVELOPMENT TOOLS
# -----------------
#
# PowerShell 7       Latest available LTS
# .NET 10 SDK        Latest .NET 10 LTS
# .NET 8 SDK         Latest .NET 8 LTS
# Node.js             Latest
# Go                  Latest
# PHP                 Latest
# Python              Latest stable
# Git                 Latest
# Git Bash            Included with Git
# OpenSSL             Latest available
# Windows Terminal    Latest
#
# ============================================================
#
# PATH
# ----
#
# The script updates persistent:
#
#     Machine PATH
#     User PATH
#
# It also refreshes the CURRENT process PATH so verification
# can happen without restarting the script.
#
# ============================================================
#
# TELEMETRY
# ---------
#
# The script displays:
#
#     [timestamp]
#     [elapsed time]
#     [INFO]
#     [STEP]
#     [OK]
#     [WARN]
#     [ERROR]
#
# A complete log is written to:
#
#     C:\ProgramData\Agantra\WindowsDeveloperBootstrap\Logs
#
# ============================================================
#
# REQUIREMENTS
# ------------
#
#     Windows 11
#     Administrator privileges
#     Internet connection
#     WinGet / App Installer
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

$LogRoot = Join-Path `
    $env:ProgramData `
    'Agantra\WindowsDeveloperBootstrap\Logs'

if (-not (Test-Path -LiteralPath $LogRoot)) {

    New-Item `
        -ItemType Directory `
        -Path $LogRoot `
        -Force |
        Out-Null
}

$LogFile = Join-Path `
    $LogRoot `
    ('Install-DevEnvironment-{0}.log' -f `
        (Get-Date -Format 'yyyyMMdd-HHmmss'))

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

    return (
        '{0:00}:{1:00}:{2:00}.{3:000}' -f `
        [int]$Elapsed.TotalHours,
        $Elapsed.Minutes,
        $Elapsed.Seconds,
        $Elapsed.Milliseconds
    )
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet(
            'INFO',
            'STEP',
            'SUCCESS',
            'WARN',
            'ERROR',
            'DEBUG'
        )]
        [string]$Level = 'INFO'
    )

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'

    $Elapsed = Get-ElapsedText

    $Line = '[{0}] [+{1}] [{2}] {3}' -f `
        $Timestamp,
        $Elapsed,
        $Level,
        $Message

    switch ($Level) {

        'INFO' {
            Write-Console $Line Gray
        }

        'STEP' {
            Write-Console $Line Cyan
        }

        'SUCCESS' {
            Write-Console $Line Green
        }

        'WARN' {
            Write-Console $Line Yellow
        }

        'ERROR' {
            Write-Console $Line Red
        }

        'DEBUG' {
            Write-Console $Line DarkGray
        }
    }

    try {

        Add-Content `
            -LiteralPath $LogFile `
            -Value $Line `
            -Encoding UTF8
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

    $Principal = New-Object `
        Security.Principal.WindowsPrincipal($Identity)

    return $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

# ============================================================
# START
# ============================================================

Write-Banner 'Windows 11 Developer Environment Bootstrap'

Write-Log `
    'Bootstrap starting.' `
    'STEP'

Write-Log `
    ('Script: {0}' -f $ScriptName)

Write-Log `
    ('PowerShell process ID: {0}' -f $PID)

Write-Log `
    ('Current user: {0}' -f $env:USERNAME)

Write-Log `
    ('Computer: {0}' -f $env:COMPUTERNAME)

if (-not (Test-IsAdministrator)) {

    Write-Log `
        'Administrator privileges are required.' `
        'ERROR'

    Write-Host ''
    Write-Console 'Run PowerShell as Administrator and execute the script again.' Red
    Write-Host ''

    exit 1
}

Write-Log `
    'Administrator privileges confirmed.' `
    'SUCCESS'

# ============================================================
# WINDOWS INFORMATION
# ============================================================

function Get-WindowsInformation {

    $OS = Get-CimInstance Win32_OperatingSystem

    return $OS
}

$OS = Get-WindowsInformation

Write-Banner 'Windows Environment'

Write-Log (
    'Operating System : {0}' -f $OS.Caption
)

Write-Log (
    'Windows Version  : {0}' -f $OS.Version
)

Write-Log (
    'Windows Build    : {0}' -f $OS.BuildNumber
)

if ($OS.Caption -notmatch 'Windows 11') {

    Write-Log `
        'This bootstrap is designed for Windows 11.' `
        'WARN'
}
else {

    Write-Log `
        'Windows 11 detected.' `
        'SUCCESS'
}

# ============================================================
# POWERSHELL HOST DETECTION
# ============================================================

function Get-PowerShellHostInformation {

    $Major = [int]$PSVersionTable.PSVersion.Major
    $Minor = [int]$PSVersionTable.PSVersion.Minor
    $Patch = [int]$PSVersionTable.PSVersion.Patch

    $Version = $PSVersionTable.PSVersion.ToString()

    if ($PSEdition -eq 'Core') {

        $Edition = 'PowerShell 7+'

    }
    else {

        $Edition = 'Windows PowerShell 5.1'
    }

    return @{
        Major   = $Major
        Minor   = $Minor
        Patch   = $Patch
        Version = $Version
        Edition = $Edition
    }
}

$CurrentPS = Get-PowerShellHostInformation

Write-Banner 'PowerShell Host Detection'

Write-Log (
    'Detected edition : {0}' -f $CurrentPS.Edition
)

Write-Log (
    'Detected version : {0}' -f $CurrentPS.Version
)

Write-Log (
    'PSEdition        : {0}' -f $PSEdition
)

Write-Log (
    'PSHome           : {0}' -f $PSHOME
)

if ($CurrentPS.Edition -eq 'Windows PowerShell 5.1') {

    Write-Log `
        'Starting from Windows PowerShell 5.1.' `
        'INFO'

    Write-Log `
        'PowerShell 7 will be installed side-by-side.' `
        'INFO'
}
else {

    Write-Log `
        'Starting from PowerShell 7.x.' `
        'INFO'

    Write-Log `
        'Existing PowerShell 7 will be upgraded if required.' `
        'INFO'
}

# ============================================================
# PATH FUNCTIONS
# ============================================================

function Normalize-PathEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    return $Path.Trim().TrimEnd('\').ToLowerInvariant()
}

function Get-PersistentPathEntries {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Machine', 'User')]
        [string]$Scope
    )

    $Value = [Environment]::GetEnvironmentVariable(
        'Path',
        $Scope
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return @()
    }

    $Result = @()

    foreach ($Entry in ($Value -split ';')) {

        if (-not [string]::IsNullOrWhiteSpace($Entry)) {

            $Result += $Entry.Trim()
        }
    }

    return $Result
}

function Add-PersistentPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Machine', 'User')]
        [string]$Scope
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }

    if (-not (Test-Path -LiteralPath $Path)) {

        Write-Log (
            'PATH does not currently exist, skipping: {0}' -f $Path
        ) 'DEBUG'

        return
    }

    $Entries = @(Get-PersistentPathEntries -Scope $Scope)

    $Target = Normalize-PathEntry -Path $Path

    foreach ($Entry in $Entries) {

        if (
            (Normalize-PathEntry -Path $Entry) -eq
            $Target
        ) {
            return
        }
    }

    $Entries += $Path

    [Environment]::SetEnvironmentVariable(
        'Path',
        ($Entries -join ';'),
        $Scope
    )

    Write-Log (
        'Added {0} PATH: {1}' -f $Scope, $Path
    ) 'SUCCESS'
}

function Remove-DuplicatePersistentPath {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Machine', 'User')]
        [string]$Scope
    )

    $Entries = @(Get-PersistentPathEntries -Scope $Scope)

    $Unique = @()
    $Seen = @{}

    foreach ($Entry in $Entries) {

        $Normalized = Normalize-PathEntry -Path $Entry

        if ([string]::IsNullOrWhiteSpace($Normalized)) {
            continue
        }

        if (-not $Seen.ContainsKey($Normalized)) {

            $Seen[$Normalized] = $true

            $Unique += $Entry
        }
    }

    [Environment]::SetEnvironmentVariable(
        'Path',
        ($Unique -join ';'),
        $Scope
    )
}

function Refresh-CurrentProcessPath {

    $MachinePath = [Environment]::GetEnvironmentVariable(
        'Path',
        'Machine'
    )

    $UserPath = [Environment]::GetEnvironmentVariable(
        'Path',
        'User'
    )

    $Combined = @()

    if (-not [string]::IsNullOrWhiteSpace($MachinePath)) {

        foreach ($Entry in ($MachinePath -split ';')) {

            if (-not [string]::IsNullOrWhiteSpace($Entry)) {
                $Combined += $Entry.Trim()
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($UserPath)) {

        foreach ($Entry in ($UserPath -split ';')) {

            if (-not [string]::IsNullOrWhiteSpace($Entry)) {
                $Combined += $Entry.Trim()
            }
        }
    }

    $Unique = @()
    $Seen = @{}

    foreach ($Entry in $Combined) {

        $Normalized = Normalize-PathEntry -Path $Entry

        if ([string]::IsNullOrWhiteSpace($Normalized)) {
            continue
        }

        if (-not $Seen.ContainsKey($Normalized)) {

            $Seen[$Normalized] = $true

            $Unique += $Entry
        }
    }

    $env:Path = $Unique -join ';'
}

# ============================================================
# WINGET DETECTION
# ============================================================

function Get-WinGetPath {

    $Command = Get-Command `
        'winget.exe' `
        -ErrorAction SilentlyContinue

    if ($null -ne $Command) {
        return $Command.Source
    }

    $WindowsApps = Join-Path `
        $env:LOCALAPPDATA `
        'Microsoft\WindowsApps'

    $Candidate = Join-Path `
        $WindowsApps `
        'winget.exe'

    if (Test-Path -LiteralPath $Candidate) {
        return $Candidate
    }

    return $null
}

Refresh-CurrentProcessPath

$Winget = Get-WinGetPath

if ([string]::IsNullOrWhiteSpace($Winget)) {

    Write-Banner 'WinGet'

    Write-Log `
        'WinGet was not detected.' `
        'ERROR'

    Write-Console `
        'Windows 11 normally provides WinGet through Microsoft App Installer.' `
        Yellow

    Write-Console `
        'Update/install App Installer and run this script again.' `
        Yellow

    exit 1
}

Write-Banner 'WinGet'

Write-Log (
    'WinGet executable: {0}' -f $Winget
) 'SUCCESS'

try {

    $WingetVersion = & $Winget --version 2>&1

    Write-Log (
        'WinGet version: {0}' -f ($WingetVersion -join ' ')
    )
}
catch {

    Write-Log `
        'Unable to determine WinGet version.' `
        'WARN'
}

# ============================================================
# WINGET PACKAGE INFORMATION
# ============================================================

function Get-WinGetPackageVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id
    )

    try {

        $Output = & $Winget search `
            '--id' `
            $Id `
            '--exact' `
            '--source' `
            'winget' `
            '--accept-source-agreements' `
            2>&1

        $Text = ($Output -join "`n")

        #
        # Expected format contains:
        #
        # PowerShell Microsoft.PowerShell 7.6.6.0 winget
        #
        # We use a tolerant regex because WinGet table formatting
        # can vary.
        #

        $Matches = [regex]::Matches(
            $Text,
            '(?m)^\s*\S.*?\s+' +
            [regex]::Escape($Id) +
            '\s+([0-9][0-9A-Za-z\.\-\+]*)\s+winget\s*$'
        )

        if ($Matches.Count -gt 0) {

            return $Matches[$Matches.Count - 1].Groups[1].Value
        }

        return $null
    }
    catch {

        return $null
    }
}

# ============================================================
# WINGET INSTALL / UPGRADE
# ============================================================

function Install-OrUpgrade-WinGetPackage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    Write-Banner $Name

    Write-Log (
        'Package ID: {0}' -f $Id
    ) 'STEP'

    $AvailableVersion = Get-WinGetPackageVersion -Id $Id

    if ($AvailableVersion) {

        Write-Log (
            'Available WinGet version: {0}' -f $AvailableVersion
        )
    }
    else {

        Write-Log `
            'Available version could not be parsed. WinGet will select latest.' `
            'WARN'
    }

    #
    # First try upgrade.
    #

    $UpgradeArguments = @(
        'upgrade'
        '--id'
        $Id
        '--exact'
        '--source'
        'winget'
        '--accept-source-agreements'
        '--accept-package-agreements'
        '--silent'
        '--disable-interactivity'
    )

    Write-Log `
        'Running WinGet upgrade...' `
        'STEP'

    & $Winget @UpgradeArguments 2>&1 |
        ForEach-Object {
            Write-Log $_.ToString() 'DEBUG'
        }

    $UpgradeExitCode = $LASTEXITCODE

    if ($UpgradeExitCode -eq 0) {

        Write-Log `
            'WinGet upgrade completed.' `
            'SUCCESS'
    }
    else {

        Write-Log (
            'WinGet upgrade returned exit code {0}. Trying install.' -f
            $UpgradeExitCode
        ) 'DEBUG'

        #
        # If not installed, install.
        #

        $InstallArguments = @(
            'install'
            '--id'
            $Id
            '--exact'
            '--source'
            'winget'
            '--accept-source-agreements'
            '--accept-package-agreements'
            '--silent'
            '--disable-interactivity'
        )

        Write-Log `
            'Running WinGet install...' `
            'STEP'

        & $Winget @InstallArguments 2>&1 |
            ForEach-Object {
                Write-Log $_.ToString() 'DEBUG'
            }

        $InstallExitCode = $LASTEXITCODE

        if ($InstallExitCode -eq 0) {

            Write-Log `
                'WinGet install completed.' `
                'SUCCESS'
        }
        else {

            Write-Log (
                'WinGet install returned exit code {0}.' -f
                $InstallExitCode
            ) 'WARN'
        }
    }

    Refresh-CurrentProcessPath
}

# ============================================================
# POWERSHELL INSTALL / UPGRADE
# ============================================================

if (-not $SkipPowerShell) {

    Write-Banner 'PowerShell Latest LTS'

    Write-Log (
        'Current host: {0} {1}' -f
        $CurrentPS.Edition,
        $CurrentPS.Version
    ) 'INFO'

    $PowerShellAvailableVersion = Get-WinGetPackageVersion `
        -Id 'Microsoft.PowerShell'

    if ($PowerShellAvailableVersion) {

        Write-Log (
            'Latest PowerShell available through WinGet: {0}' -f
            $PowerShellAvailableVersion
        ) 'SUCCESS'
    }
    else {

        Write-Log `
            'Could not determine the available PowerShell version.' `
            'WARN'
    }

    if ($CurrentPS.Edition -eq 'Windows PowerShell 5.1') {

        Write-Log `
            'Windows PowerShell 5.1 detected.' `
            'INFO'

        Write-Log `
            'Installing PowerShell 7 side-by-side.' `
            'STEP'

    }
    elseif ($CurrentPS.Major -lt 7) {

        Write-Log `
            'PowerShell version is below 7.' `
            'INFO'

    }
    else {

        Write-Log (
            'PowerShell 7.x detected: {0}' -f $CurrentPS.Version
        ) 'INFO'

        Write-Log `
            'Checking for a newer PowerShell release.' `
            'STEP'
    }

    Install-OrUpgrade-WinGetPackage `
        -Id 'Microsoft.PowerShell' `
        -Name 'PowerShell 7'

    #
    # Standard PowerShell 7 installation directory.
    #

    $PowerShell7Path = Join-Path `
        $env:ProgramFiles `
        'PowerShell\7'

    Add-PersistentPath `
        -Path $PowerShell7Path `
        -Scope Machine

    #
    # WindowsApps contains the application alias for MSIX.
    #

    $WindowsAppsPath = Join-Path `
        $env:LOCALAPPDATA `
        'Microsoft\WindowsApps'

    Add-PersistentPath `
        -Path $WindowsAppsPath `
        -Scope User

    Refresh-CurrentProcessPath

    #
    # Locate newly installed PowerShell.
    #

    $PowerShell7 = Get-Command `
        'pwsh.exe' `
        -ErrorAction SilentlyContinue

    if ($null -eq $PowerShell7) {

        $PowerShell7Candidate = Join-Path `
            $PowerShell7Path `
            'pwsh.exe'

        if (Test-Path -LiteralPath $PowerShell7Candidate) {

            $PowerShell7 = Get-Item `
                -LiteralPath $PowerShell7Candidate
        }
    }

    if ($null -ne $PowerShell7) {

        try {

            $InstalledPSVersion = & $PowerShell7.Source `
                -NoLogo `
                -NoProfile `
                -Command '$PSVersionTable.PSVersion.ToString()' `
                2>&1

            Write-Log (
                'PowerShell 7 installed/available: {0}' -f
                ($InstalledPSVersion -join ' ')
            ) 'SUCCESS'
        }
        catch {

            Write-Log `
                'PowerShell 7 was installed but version verification failed.' `
                'WARN'
        }
    }
    else {

        Write-Log `
            'pwsh.exe was not found immediately after installation.' `
            'WARN'

        Write-Log `
            'Open a new terminal after bootstrap completion and run pwsh --version.' `
            'WARN'
    }
}

# ============================================================
# .NET 10
# ============================================================

if (-not $SkipDotNet) {

    Install-OrUpgrade-WinGetPackage `
        -Id 'Microsoft.DotNet.SDK.10' `
        -Name '.NET 10 SDK LTS'

    Add-PersistentPath `
        -Path "$env:ProgramFiles\dotnet" `
        -Scope Machine

    Refresh-CurrentProcessPath
}

# ============================================================
# .NET 8
# ============================================================

if (-not $SkipDotNet) {

    Install-OrUpgrade-WinGetPackage `
        -Id 'Microsoft.DotNet.SDK.8' `
        -Name '.NET 8 SDK LTS'

    Add-PersistentPath `
        -Path "$env:ProgramFiles\dotnet" `
        -Scope Machine

    Refresh-CurrentProcessPath
}

# ============================================================
# NODE.JS
# ============================================================

if (-not $SkipNodeJS) {

    Install-OrUpgrade-WinGetPackage `
        -Id 'OpenJS.NodeJS' `
        -Name 'Node.js'

    Add-PersistentPath `
        -Path "$env:ProgramFiles\nodejs" `
        -Scope Machine

    Refresh-CurrentProcessPath
}

# ============================================================
# GO
# ============================================================

if (-not $SkipGo) {

    Install-OrUpgrade-WinGetPackage `
        -Id 'GoLang.Go' `
        -Name 'Go'

    Add-PersistentPath `
        -Path "$env:ProgramFiles\Go\bin" `
        -Scope Machine

    $GoUserBin = Join-Path `
        $env:USERPROFILE `
        'go\bin'

    if (-not (Test-Path -LiteralPath $GoUserBin)) {

        New-Item `
            -ItemType Directory `
            -Path $GoUserBin `
            -Force |
            Out-Null
    }

    Add-PersistentPath `
        -Path $GoUserBin `
        -Scope User

    Refresh-CurrentProcessPath
}

# ============================================================
# PHP
# ============================================================

if (-not $SkipPHP) {

    Install-OrUpgrade-WinGetPackage `
        -Id 'PHP.PHP' `
        -Name 'PHP'

    #
    # Discover PHP installation directories.
    #

    $PHPRoots = @(
        "$env:ProgramFiles\PHP"
        "$env:ProgramFiles\PHP*"
    )

    foreach ($PHPPattern in $PHPRoots) {

        $PHPDirectories = Get-ChildItem `
            -Path $PHPPattern `
            -Directory `
            -ErrorAction SilentlyContinue

        foreach ($PHPDirectory in $PHPDirectories) {

            Add-PersistentPath `
                -Path $PHPDirectory.FullName `
                -Scope Machine

            $PHPBin = Join-Path `
                $PHPDirectory.FullName `
                'bin'

            Add-PersistentPath `
                -Path $PHPBin `
                -Scope Machine
        }
    }

    Refresh-CurrentProcessPath
}

# ============================================================
# PYTHON
# ============================================================

if (-not $SkipPython) {

    Write-Banner 'Python'

    #
    # Current CPython recommendation is Python Install Manager.
    #

    Install-OrUpgrade-WinGetPackage `
        -Id 'Python.PythonInstallManager' `
        -Name 'Python Install Manager'

    Refresh-CurrentProcessPath

    #
    # Python global command directory.
    #

    $PythonGlobalBin = Join-Path `
        $env:LOCALAPPDATA `
        'Python\bin'

    Add-PersistentPath `
        -Path $PythonGlobalBin `
        -Scope User

    #
    # WindowsApps contains Python Install Manager aliases.
    #

    $PythonWindowsApps = Join-Path `
        $env:LOCALAPPDATA `
        'Microsoft\WindowsApps'

    Add-PersistentPath `
        -Path $PythonWindowsApps `
        -Scope User

    Refresh-CurrentProcessPath

    #
    # Locate Python manager.
    #

    $PythonManager = Get-Command `
        'pymanager.exe' `
        -ErrorAction SilentlyContinue

    if ($null -eq $PythonManager) {

        $PythonManager = Get-Command `
            'py.exe' `
            -ErrorAction SilentlyContinue
    }

    if ($null -ne $PythonManager) {

        Write-Log `
            'Python Install Manager detected.' `
            'SUCCESS'

        try {

            #
            # Install the latest Python 3 runtime.
            #

            & $PythonManager.Source `
                install 3 `
                2>&1 |
                ForEach-Object {
                    Write-Log $_.ToString() 'DEBUG'
                }

            if ($LASTEXITCODE -eq 0) {

                Write-Log `
                    'Latest Python 3 runtime installation completed.' `
                    'SUCCESS'
            }
            else {

                Write-Log (
                    'Python runtime installation returned exit code {0}.' -f
                    $LASTEXITCODE
                ) 'WARN'
            }
        }
        catch {

            Write-Log (
                'Python runtime installation failed: {0}' -f
                $_.Exception.Message
            ) 'WARN'
        }
    }
    else {

        Write-Log `
            'Python manager is not available in the current process yet.' `
            'WARN'

        Write-Log `
            'A new terminal may be required before python/py becomes available.' `
            'WARN'
    }

    #
    # Discover Python runtime directories.
    #

    $PythonRoots = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Python')
        (Join-Path $env:LOCALAPPDATA 'Python')
    )

    foreach ($PythonRoot in $PythonRoots) {

        if (Test-Path -LiteralPath $PythonRoot) {

            Add-PersistentPath `
                -Path $PythonRoot `
                -Scope User

            $PythonVersions = Get-ChildItem `
                -LiteralPath $PythonRoot `
                -Directory `
                -ErrorAction SilentlyContinue

            foreach ($PythonVersion in $PythonVersions) {

                Add-PersistentPath `
                    -Path $PythonVersion.FullName `
                    -Scope User

                $PythonScripts = Join-Path `
                    $PythonVersion.FullName `
                    'Scripts'

                Add-PersistentPath `
                    -Path $PythonScripts `
                    -Scope User
            }
        }
    }

    Refresh-CurrentProcessPath
}

# ============================================================
# GIT
# ============================================================

if (-not $SkipGit) {

    Install-OrUpgrade-WinGetPackage `
        -Id 'Git.Git' `
        -Name 'Git for Windows'

    Add-PersistentPath `
        -Path "$env:ProgramFiles\Git\cmd" `
        -Scope Machine

    #
    # IMPORTANT:
    #
    # Do NOT add Git\usr\bin globally.
    #
    # Git Bash provides its own Unix environment.
    # Adding usr\bin to global Windows PATH can shadow native
    # Windows commands.
    #

    Refresh-CurrentProcessPath
}

# ============================================================
# OPENSSL
# ============================================================

if (-not $SkipOpenSSL) {

    Write-Banner 'OpenSSL'

    $OpenSSLInstalled = $false

    $OpenSSLPackageIds = @(
        'ShiningLight.OpenSSL.Light'
        'ShiningLight.OpenSSL'
    )

    foreach ($OpenSSLId in $OpenSSLPackageIds) {

        if ($OpenSSLInstalled) {
            break
        }

        Write-Log (
            'Trying OpenSSL package: {0}' -f $OpenSSLId
        ) 'STEP'

        $Arguments = @(
            'install'
            '--id'
            $OpenSSLId
            '--exact'
            '--source'
            'winget'
            '--accept-source-agreements'
            '--accept-package-agreements'
            '--silent'
            '--disable-interactivity'
        )

        & $Winget @Arguments 2>&1 |
            ForEach-Object {
                Write-Log $_.ToString() 'DEBUG'
            }

        if ($LASTEXITCODE -eq 0) {

            $OpenSSLInstalled = $true

            Write-Log (
                'OpenSSL package processed: {0}' -f $OpenSSLId
            ) 'SUCCESS'
        }
    }

    if (-not $OpenSSLInstalled) {

        Write-Log `
            'OpenSSL installation did not report success.' `
            'WARN'
    }

    $OpenSSLPaths = @(
        "$env:ProgramFiles\OpenSSL\bin"
        "$env:ProgramFiles\OpenSSL-Win64\bin"
        "$env:ProgramFiles\OpenSSL-Win32\bin"
    )

    foreach ($OpenSSLPath in $OpenSSLPaths) {

        Add-PersistentPath `
            -Path $OpenSSLPath `
            -Scope Machine
    }

    Refresh-CurrentProcessPath
}

# ============================================================
# WINDOWS TERMINAL
# ============================================================

if (-not $SkipWindowsTerminal) {

    Install-OrUpgrade-WinGetPackage `
        -Id 'Microsoft.WindowsTerminal' `
        -Name 'Windows Terminal'
}

# ============================================================
# FINAL PATH CLEANUP
# ============================================================

Write-Banner 'PATH Cleanup'

Remove-DuplicatePersistentPath `
    -Scope Machine

Remove-DuplicatePersistentPath `
    -Scope User

Refresh-CurrentProcessPath

Write-Log `
    'Persistent PATH cleanup completed.' `
    'SUCCESS'

# ============================================================
# FINAL TOOL SCAN
# ============================================================

Write-Banner 'Final Developer Environment Scan'

function Invoke-VersionCheck {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    Write-Console (
        '--- {0} ---' -f $Name
    ) Cyan

    try {

        $CommandInfo = Get-Command `
            $Command `
            -ErrorAction Stop

        Write-Log (
            '{0}: executable = {1}' -f `
                $Name,
                $CommandInfo.Source
        ) 'SUCCESS'

        $Output = & $Command @Arguments 2>&1

        foreach ($Line in $Output) {

            if ($null -ne $Line) {
                Write-Console $Line.ToString() White
            }
        }

        if ($LASTEXITCODE -ne 0) {

            Write-Log (
                '{0}: exit code {1}' -f `
                    $Name,
                    $LASTEXITCODE
            ) 'WARN'
        }
    }
    catch {

        Write-Log (
            '{0}: command not available in current process.' -f
            $Name
        ) 'WARN'
    }

    Write-Host ''
}

# ============================================================
# POWERHELL
# ============================================================

Invoke-VersionCheck `
    -Name 'PowerShell 7' `
    -Command 'pwsh.exe' `
    -Arguments @(
        '-NoLogo'
        '-NoProfile'
        '-Command'
        '$PSVersionTable.PSVersion.ToString()'
    )

# ============================================================
# .NET
# ============================================================

Invoke-VersionCheck `
    -Name '.NET SDK' `
    -Command 'dotnet.exe' `
    -Arguments @('--version')

Write-Console 'Installed .NET SDKs:' Cyan

try {
    & dotnet.exe --list-sdks 2>&1
}
catch {
    Write-Log 'Unable to query .NET SDKs.' 'WARN'
}

Write-Host ''

Write-Console 'Installed .NET Runtimes:' Cyan

try {
    & dotnet.exe --list-runtimes 2>&1
}
catch {
    Write-Log 'Unable to query .NET runtimes.' 'WARN'
}

Write-Host ''

# ============================================================
# NODE.JS
# ============================================================

Invoke-VersionCheck `
    -Name 'Node.js' `
    -Command 'node.exe' `
    -Arguments @('--version')

Invoke-VersionCheck `
    -Name 'npm' `
    -Command 'npm.cmd' `
    -Arguments @('--version')

# ============================================================
# GO
# ============================================================

Invoke-VersionCheck `
    -Name 'Go' `
    -Command 'go.exe' `
    -Arguments @('version')

# ============================================================
# PHP
# ============================================================

Invoke-VersionCheck `
    -Name 'PHP' `
    -Command 'php.exe' `
    -Arguments @('--version')

# ============================================================
# PYTHON
# ============================================================

Invoke-VersionCheck `
    -Name 'Python' `
    -Command 'python.exe' `
    -Arguments @('--version')

Invoke-VersionCheck `
    -Name 'Python Launcher / Manager' `
    -Command 'py.exe' `
    -Arguments @('--version')

Invoke-VersionCheck `
    -Name 'pip' `
    -Command 'pip.exe' `
    -Arguments @('--version')

# ============================================================
# GIT
# ============================================================

Invoke-VersionCheck `
    -Name 'Git' `
    -Command 'git.exe' `
    -Arguments @('--version')

# ============================================================
# OPENSSL
# ============================================================

Invoke-VersionCheck `
    -Name 'OpenSSL' `
    -Command 'openssl.exe' `
    -Arguments @('version')

# ============================================================
# WINDOWS TERMINAL
# ============================================================

Invoke-VersionCheck `
    -Name 'Windows Terminal' `
    -Command 'wt.exe' `
    -Arguments @('--version')

# ============================================================
# GIT BASH
# ============================================================

Write-Console '--- Git Bash ---' Cyan

$GitBashCandidates = @(
    "$env:ProgramFiles\Git\bin\bash.exe"
    "$env:ProgramFiles\Git\usr\bin\bash.exe"
)

$GitBashFound = $false

foreach ($GitBashPath in $GitBashCandidates) {

    if (Test-Path -LiteralPath $GitBashPath) {

        Write-Log (
            'Git Bash: {0}' -f $GitBashPath
        ) 'SUCCESS'

        $GitBashFound = $true

        break
    }
}

if (-not $GitBashFound) {

    Write-Log `
        'Git Bash executable was not found.' `
        'WARN'
}

# ============================================================
# FINAL POWERHELL HOST SCAN
# ============================================================

Write-Banner 'PowerShell Final Scan'

$FinalPwsh = Get-Command `
    'pwsh.exe' `
    -ErrorAction SilentlyContinue

if ($null -ne $FinalPwsh) {

    try {

        $FinalVersion = & $FinalPwsh.Source `
            -NoLogo `
            -NoProfile `
            -Command '$PSVersionTable.PSVersion.ToString()' `
            2>&1

        Write-Console (
            'Installed PowerShell 7 version: {0}' -f
            ($FinalVersion -join ' ')
        ) Green
    }
    catch {

        Write-Log `
            'Final PowerShell 7 version scan failed.' `
            'WARN'
    }
}
else {

    Write-Log `
        'PowerShell 7 is not visible from the current process.' `
        'WARN'
}

Write-Host ''

# ============================================================
# FINAL PATH DISPLAY
# ============================================================

Write-Banner 'Persistent PATH Summary'

Write-Console 'Machine PATH:' Cyan

$MachinePathFinal = `
    [Environment]::GetEnvironmentVariable(
        'Path',
        'Machine'
    )

Write-Host $MachinePathFinal

Write-Host ''

Write-Console 'User PATH:' Cyan

$UserPathFinal = `
    [Environment]::GetEnvironmentVariable(
        'Path',
        'User'
    )

Write-Host $UserPathFinal

# ============================================================
# FINAL TELEMETRY
# ============================================================

$BootstrapEnd = Get-Date

$TotalElapsed = $BootstrapEnd - $BootstrapStart

Write-Banner 'Installation Summary'

Write-Console (
    'Start time       : {0}' -f
    $BootstrapStart.ToString('yyyy-MM-dd HH:mm:ss')
) Gray

Write-Console (
    'End time         : {0}' -f
    $BootstrapEnd.ToString('yyyy-MM-dd HH:mm:ss')
) Gray

Write-Console (
    'Total duration   : {0:00}:{1:00}:{2:00}.{3:000}' -f `
        [int]$TotalElapsed.TotalHours,
        $TotalElapsed.Minutes,
        $TotalElapsed.Seconds,
        $TotalElapsed.Milliseconds
) Green

Write-Console (
    'Log file         : {0}' -f $LogFile
) Gray

Write-Host ''

Write-Console 'Developer environment bootstrap completed.' Green

Write-Host ''
Write-Console '============================================================' Green
Write-Console ' IMPORTANT: OPEN A NEW TERMINAL'
Write-Console '============================================================' Green
Write-Host ''

Write-Console `
    'The current terminal was started before the PATH changes.' `
    Yellow

Write-Console `
    'Close this terminal and open a NEW Windows Terminal / PowerShell.' `
    Yellow

Write-Host ''

Write-Console 'Then run:' Cyan
Write-Host ''
Write-Host '  pwsh --version'
Write-Host '  dotnet --version'
Write-Host '  dotnet --list-sdks'
Write-Host '  dotnet --list-runtimes'
Write-Host '  node --version'
Write-Host '  npm --version'
Write-Host '  go version'
Write-Host '  php --version'
Write-Host '  python --version'
Write-Host '  py --version'
Write-Host '  pip --version'
Write-Host '  git --version'
Write-Host '  openssl version'
Write-Host '  wt --version'
Write-Host ''

Write-Log `
    'Bootstrap completed successfully.' `
    'SUCCESS'

# ============================================================
# END
# ============================================================