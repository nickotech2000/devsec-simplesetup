# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 5.1
<#
.SYNOPSIS
    Prepares a Windows computer: installs OpenSSL 4 and the latest Python with winget or Chocolatey, and makes sure both are on the PATH. STANDALONE.
    Full help: .\Prepare-Computer.ps1 -Help
.EXAMPLE
    .\Prepare-Computer.ps1 -Check        (only look)
.EXAMPLE
    .\Prepare-Computer.ps1 -Only OpenSsl -Yes
#>
param(
    [ValidateSet('All', 'OpenSsl', 'Python')][string]$Only = 'All',
    [ValidateSet('Auto', 'Winget', 'Chocolatey')][string]$Manager = 'Auto',
    [switch]$Check,
    [switch]$Yes,
    [switch]$Force,
    [switch]$NoPath,
    [switch]$Help
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:ToolVersion = '5.2.6'

function Show-Help {
@'
============================================================
 Prepare-Computer.ps1 - get this Windows computer ready: OpenSSL 4 + the latest Python, both on the PATH
 Version 5.2.6
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
WHAT IT DOES   (run it once, from an Administrator PowerShell)
  1. OpenSSL   looks for openssl.exe; installs OpenSSL 4 when it is missing or older than 4.
  2. Python    looks for a working Python 3 (3.10 or newer); installs the latest Python 3 when it is missing or older.
  3. PATH      makes sure `openssl` and `python` work in a new PowerShell window: when the program is installed but not found on the PATH, its folder is
               added (Administrator = all users; normal window = this user). An older OpenSSL that comes first on the PATH is overtaken: the folder of the new one is put in front.
  Package managers: winget first (FireDaemon.OpenSSL, Python.Python.3.x - the highest 3.x winget lists), Chocolatey second (openssl, python).

OPTIONS
  -Only All | OpenSsl | Python    what to prepare (default All)
  -Manager Auto | Winget | Chocolatey    Auto = winget first, then Chocolatey
  -Check      only look: say what is there, what would be installed, what would be added to the PATH. Nothing is changed.
  -Yes        do not ask before installing
  -Force      install / upgrade through the package manager even when a good version is already there
  -NoPath     do not touch the PATH
  -Help

AFTER IT
  Open a NEW PowerShell window (the PATH is read when a window starts).  Then:   openssl version     python --version     .\New-PkiCsr.ps1
  If the PKI is already installed on this computer (Local Machine certificate store, from Install-PkiCa.ps1), nothing changes: this script does not touch certificates.

WHERE IT RUNS
  Windows 11 24H2 or newer (Home, Pro, Pro for Workstations, Education, Pro Education, Enterprise), Windows Server 2025 and Windows Server 2022 (Essentials,
  Standard, Datacenter). Refused (exit 5): Windows 10 and earlier, Windows 11 before 24H2, Windows Server before 2022 and the Chinese, Government, IoT,
  SE and Embedded editions. Windows PowerShell 5.1 or PowerShell 7. Needs Internet access to the package source. On Linux use prepare-computer.sh.
  EXIT CODES   0 ok   1 error   4 something is still missing (OpenSSL below 4, Python not found, no package manager)   5 system not supported
============================================================
'@ | Write-Host
}

function Say { param([string]$Level, [string]$Text)
    $c = 'Cyan'; if ($Level -eq 'OK') { $c = 'Green' } elseif ($Level -eq 'WARN') { $c = 'Yellow' } elseif ($Level -eq 'ERROR') { $c = 'Red' }
    Write-Host ('[{0}] {1}' -f $Level, $Text) -ForegroundColor $c
}
function Stop-Tool { param([string]$Text, [int]$Code = 1) Say 'ERROR' $Text; exit $Code }

if ($Help) { Show-Help; return }

# ---------------------------------------------------------------- the system
function Test-HostSupported {
    $isWin = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
    if ($isWin -or $env:PKI_FAKE_OS) {
        $osBuild = 0; $osProduct = ''; $osEd = ''; $osKind = ''
        if ($isWin) {
            try {
                $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
                $osBuild = [int]$cv.CurrentBuildNumber; $osProduct = [string]$cv.ProductName; $osKind = [string]$cv.InstallationType; $osEd = [string]$cv.EditionID
            } catch { $osBuild = [Environment]::OSVersion.Version.Build }
        }
        if ($env:PKI_FAKE_OS) { $fp = $env:PKI_FAKE_OS.Split(':'); $osKind = $fp[0]; $osBuild = [int]$fp[1]; $osProduct = 'test (PKI_FAKE_OS)'; $osEd = $(if ($fp.Count -gt 2) { $fp[2] } elseif ($osKind -like 'Server*') { 'ServerStandard' } else { 'Professional' }) }
        $name = if ($osProduct) { "$osProduct (build $osBuild)" } else { "Windows build $osBuild" }
        if ($osEd) { $name = "$name, edition $osEd" }
        $txt = "$osEd $osProduct"
        $bad = ''
        if ($txt -match '(?i)china|chinese|CountrySpecific') { $bad = 'a Chinese edition: specialised editions are NOT supported' }
        elseif ($txt -match '(?i)government|EnterpriseG\b|EnterpriseGN|\bGov\b') { $bad = 'a Government edition: specialised editions are NOT supported' }
        elseif ($txt -match '(?i)IoT') { $bad = 'an IoT / IoT Enterprise edition: specialised editions are NOT supported' }
        elseif ($txt -match '(?i)\bSE\b|Embedded') { $bad = 'an SE / Embedded edition: specialised editions are NOT supported' }
        elseif ($osKind -like 'Server*') {
            if ($osEd -and $osEd -notmatch '^Server(Standard|Datacenter|Solution|Essentials)(Core|Eval|ACor)?$') { $bad = 'this Windows Server edition is NOT supported (Essentials, Standard, Datacenter only)' }
            elseif ($osBuild -lt 20348) { $bad = 'a Windows Server before 2022 is NOT supported' }
            elseif ($osBuild -ge 22000 -and $osBuild -lt 26100) { $bad = 'this Windows Server build is NOT supported (only Windows Server 2022 and 2025)' }
        }
        else {
            if ($osBuild -lt 22000) { $bad = 'Windows 10 and earlier are NOT supported' }
            elseif ($osBuild -lt 26100) { $bad = 'Windows 11 before 24H2 is NOT supported (needs 24H2 = build 26100 or newer)' }
            elseif ($osEd -and $osEd -notmatch '^(Core|CoreN|CoreSingleLanguage|Professional|ProfessionalN|ProfessionalWorkstation|ProfessionalWorkstationN|ProfessionalEducation|ProfessionalEducationN|Education|EducationN|Enterprise|EnterpriseN)$') { $bad = 'this Windows edition is NOT supported' }
        }
        if ($bad) { Stop-Tool "This computer is ${name}: $bad. Nothing was done." 5 }
        return
    }
    $rel = if ($env:PKI_OS_RELEASE_FILE) { $env:PKI_OS_RELEASE_FILE } else { '/etc/os-release' }
    $id = ''; $ver = ''; $pretty = ''
    if (Test-Path -LiteralPath $rel) {
        foreach ($l in (Get-Content -LiteralPath $rel)) {
            if ($l -match '^ID="?([^"]*)"?$') { $id = $Matches[1] } elseif ($l -match '^VERSION_ID="?([^"]*)"?$') { $ver = $Matches[1] } elseif ($l -match '^PRETTY_NAME="?([^"]*)"?$') { $pretty = $Matches[1] }
        }
    }
    $maj = 0; [void][int]::TryParse(($ver -split '\.')[0], [ref]$maj)
    $ok = $false
    switch ($id) {
        'ubuntu' { $ok = ($maj -ge 24) }
        { $_ -in 'centos', 'rhel', 'rocky', 'ol' } { $ok = ($maj -ge 10) }
        { $_ -in 'sles', 'sles_sap', 'sled', 'opensuse-leap' } { $ok = ($maj -ge 15) }
        'opensuse-tumbleweed' { $ok = $true }
    }
    if (-not $ok) { Stop-Tool ("This system is '{0}' (ID={1} VERSION_ID={2}): NOT supported. Supported: Windows 11 24H2+, Windows Server 2022 / 2025; Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky 10+, Oracle Linux 10+, SLES 15+, openSUSE 15+. Nothing was done." -f $pretty, $id, $ver) 5 }
}

Write-Host '============================================================'
Write-Host ' Prepare-Computer.ps1 - OpenSSL 4 + the latest Python, both on the PATH'
Write-Host ' Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   nicko@nextmantra.com'
Write-Host '============================================================'
Say 'INFO' "Prepare-Computer.ps1 version $script:ToolVersion"
Test-HostSupported
$isWin = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
if (-not $isWin -and -not $env:PKI_FAKE_OS) { Stop-Tool 'This script is for Windows. On Linux use ./prepare-computer.sh' 1 }
$script:Missing = $false

$admin = $false
try { $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
if (-not $admin -and -not $Check) { Say 'WARN' 'This is not an Administrator window: installs for all users may fail and the PATH is changed for this user only. Best: right-click PowerShell, "Run as administrator".' }

# ---------------------------------------------------------------- package managers
$wg = Get-Command 'winget.exe' -ErrorAction SilentlyContinue
if (-not $wg -and $env:LOCALAPPDATA) { $p = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'; if (Test-Path -LiteralPath $p) { $wg = [pscustomobject]@{ Source = $p } } }
$ch = Get-Command 'choco.exe' -ErrorAction SilentlyContinue
$use = ''
switch ($Manager) {
    'Winget' { if ($wg) { $use = 'winget' } }
    'Chocolatey' { if ($ch) { $use = 'choco' } }
    default { if ($wg) { $use = 'winget' } elseif ($ch) { $use = 'choco' } }
}
Say 'INFO' ("Package managers: winget {0}, Chocolatey {1}." -f $(if ($wg) { 'found' } else { 'not found' }), $(if ($ch) { 'found' } else { 'not found' }))

# ---------------------------------------------------------------- PATH helpers
function Get-PathParts { param([string]$Scope)
    # the raw value (no %VAR% expansion) of the Path of the Machine or the User
    try {
        if ($Scope -eq 'Machine') { $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment') } else { $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment') }
        if ($null -eq $k) { return @() }
        $v = [string]$k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); $k.Close()
        return @($v -split ';' | Where-Object { $_ })
    } catch { return @() }
}
function Test-OnPath { param([string]$Dir)
    $d = $Dir.TrimEnd('\').ToLowerInvariant()
    foreach ($e in ($env:Path -split ';')) { if ($e -and $e.TrimEnd('\').ToLowerInvariant() -eq $d) { return $true } }
    return $false
}
function Add-ToPath {
    param([Parameter(Mandatory)][string]$Dir, [bool]$Front = $false)
    if ($NoPath) { Say 'INFO' "-NoPath: $Dir is not added to the PATH."; return }
    $scope = if ($admin) { 'Machine' } else { 'User' }
    $parts = @(Get-PathParts -Scope $scope)
    $have = $false; foreach ($e in $parts) { if ($e.TrimEnd('\').ToLowerInvariant() -eq $Dir.TrimEnd('\').ToLowerInvariant()) { $have = $true } }
    if ($Check) { Say 'INFO' ("-Check: would add {0} to the {1} PATH{2}." -f $Dir, $scope, $(if ($Front) { ' (in front)' } else { '' })); return }
    if (-not $have) {
        $new = if ($Front) { @($Dir) + $parts } else { $parts + @($Dir) }
        try {
            if ($scope -eq 'Machine') { $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment', $true) } else { $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true) }
            $k.SetValue('Path', ($new -join ';'), [Microsoft.Win32.RegistryValueKind]::ExpandString); $k.Close()
            Say 'OK' ("Added to the {0} PATH{1}: {2}" -f $scope, $(if ($Front) { ' (in front)' } else { '' }), $Dir)
        } catch { Say 'WARN' "Could not change the $scope PATH ($($_.Exception.Message)). Add this folder yourself: $Dir"; return }
    }
    # this window too
    if (-not (Test-OnPath $Dir)) { $env:Path = if ($Front) { "$Dir;$env:Path" } else { "$env:Path;$Dir" } }
    Say 'INFO' 'Open a NEW PowerShell window so that every program sees the new PATH.'
}
function Update-SessionPath {
    $m = [Environment]::GetEnvironmentVariable('Path', 'Machine'); $u = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = (@($m, $u) | Where-Object { $_ }) -join ';'
}
function Confirm-Install { param([string]$What)
    if ($Yes -or $Check) { return $true }
    if ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
        $a = (Read-Host "Install $What now? (Y/n)").Trim(); if ($a -match '^(?i)n(o)?$') { Say 'INFO' 'Stopped by you.'; return $false }
    }
    return $true
}
function Invoke-Pm { param([string[]]$WingetArgs, [string[]]$ChocoArgs)
    if ($use -eq 'winget') { & $wg.Source @WingetArgs 2>&1 | ForEach-Object { Write-Host "  $_" } } else { & $ch.Source @ChocoArgs 2>&1 | ForEach-Object { Write-Host "  $_" } }
}

# ================================================================ OPENSSL
function Find-OpenSsl {
    $cands = New-Object System.Collections.ArrayList
    if ($env:PKI_OPENSSL) { [void]$cands.Add($env:PKI_OPENSSL) }
    foreach ($n in 'openssl4', 'openssl') { $g = Get-Command $n -ErrorAction SilentlyContinue; if ($g) { [void]$cands.Add($g.Source) } }
    foreach ($d in @("$env:ProgramFiles\FireDaemon OpenSSL 4\bin", "$env:ProgramFiles\FireDaemon OpenSSL\bin", "$env:ProgramFiles\FireDaemon OpenSSL 3\bin", "$env:ProgramFiles\OpenSSL-Win64\bin", "$env:ProgramFiles\OpenSSL\bin", "$env:ProgramData\chocolatey\bin")) {
        if ($d -and (Test-Path -LiteralPath $d)) { $p = Join-Path $d 'openssl.exe'; if (Test-Path -LiteralPath $p) { [void]$cands.Add($p) } }
    }
    $best = $null
    foreach ($c in $cands) {
        if (-not (Test-Path -LiteralPath $c)) { continue }
        try { $v = (& $c version 2>&1 | Select-Object -First 1).ToString() } catch { continue }
        if ($v -match '^OpenSSL (\d+)\.(\d+)') {
            $o = [pscustomobject]@{ Path = $c; Text = $v.Trim(); Major = [int]$Matches[1]; Minor = [int]$Matches[2] }
            if ($null -eq $best -or $o.Major -gt $best.Major -or ($o.Major -eq $best.Major -and $o.Minor -gt $best.Minor)) { $best = $o }
        }
    }
    return $best
}
function Confirm-OpenSslOnPath {
    param($Ossl)
    $dir = Split-Path -Parent $Ossl.Path
    $onPath = Get-Command 'openssl' -ErrorAction SilentlyContinue
    if ($onPath) {
        $same = ((Split-Path -Parent $onPath.Source).TrimEnd('\').ToLowerInvariant() -eq $dir.TrimEnd('\').ToLowerInvariant())
        if ($same) { Say 'OK' "openssl is on the PATH: $($onPath.Source)"; return }
        $v = ''; try { $v = (& $onPath.Source version 2>&1 | Select-Object -First 1).ToString().Trim() } catch { }
        if ($v -match '^OpenSSL (\d+)\.' -and [int]$Matches[1] -ge $Ossl.Major) { Say 'OK' "openssl is on the PATH: $($onPath.Source)  ($v)"; return }
        Say 'WARN' "The openssl first on the PATH is older ($v): $($onPath.Source). The folder of $($Ossl.Text) is put in front."
        Add-ToPath -Dir $dir -Front $true
        return
    }
    Say 'WARN' 'openssl is installed but not found on the PATH.'
    Add-ToPath -Dir $dir -Front $false
}
function Install-OpenSslNow {
    Say 'INFO' '--- OpenSSL ---'
    $have = Find-OpenSsl
    if ($have) { Say 'INFO' ("OpenSSL found: {0}  ({1})" -f $have.Text, $have.Path) } else { Say 'INFO' 'OpenSSL is not installed.' }
    if ($have -and $have.Major -ge 4 -and -not $Force) { Say 'OK' 'OpenSSL 4 is there.'; Confirm-OpenSslOnPath $have; return }
    if (-not $use) { Say 'ERROR' 'No package manager (winget or Chocolatey) for OpenSSL. winget comes with Windows 11 (App Installer); Chocolatey: https://chocolatey.org/install'; $script:Missing = $true; if ($have) { Confirm-OpenSslOnPath $have }; return }
    $wa = @('install', '--id', 'FireDaemon.OpenSSL', '--exact', '--source', 'winget', '--accept-source-agreements', '--accept-package-agreements', '--silent', '--disable-interactivity')
    $ca = @('install', 'openssl', '-y', '--no-progress')
    Say 'INFO' ("Would run: {0}" -f $(if ($use -eq 'winget') { 'winget ' + ($wa -join ' ') } else { 'choco ' + ($ca -join ' ') }))
    if ($Check) { if ($have) { Confirm-OpenSslOnPath $have }; return }
    if (-not (Confirm-Install 'OpenSSL')) { return }
    try {
        Invoke-Pm -WingetArgs $wa -ChocoArgs $ca
        if ($LASTEXITCODE -ne 0) {
            Say 'WARN' "The package manager returned exit code $LASTEXITCODE (winget also does that when the package is already installed). Trying an upgrade ..."
            Invoke-Pm -WingetArgs @('upgrade', '--id', 'FireDaemon.OpenSSL', '--exact', '--source', 'winget', '--accept-source-agreements', '--accept-package-agreements', '--silent', '--disable-interactivity') -ChocoArgs @('upgrade', 'openssl', '-y', '--no-progress')
        }
    } catch { Say 'ERROR' "The OpenSSL installation failed: $($_.Exception.Message)"; $script:Missing = $true; return }
    Update-SessionPath
    $now = Find-OpenSsl
    if (-not $now) { Say 'ERROR' 'The package manager finished but openssl.exe was not found. Open a NEW PowerShell window and run this script with -Check.'; $script:Missing = $true; return }
    Say 'OK' ("OpenSSL: {0}  ({1})" -f $now.Text, $now.Path)
    Confirm-OpenSslOnPath $now
    if ($now.Major -lt 4) {
        Say 'WARN' "The package manager gave OpenSSL $($now.Major).$($now.Minor), not 4. RSA and ECDSA requests work; ML-DSA (quantum) needs 3.5 or 4. $(if ($use -eq 'choco') { 'Try -Manager Winget (FireDaemon.OpenSSL is 4.x).' } else { 'Try -Manager Chocolatey, or run: winget source update.' })"
        $script:Missing = $true
    }
}

# ================================================================ PYTHON
function Find-Python {
    $cands = New-Object System.Collections.ArrayList
    foreach ($n in 'python', 'python3') { foreach ($g in @(Get-Command $n -All -ErrorAction SilentlyContinue)) { if ($g.Source -and $g.Source -notmatch '\\WindowsApps\\') { [void]$cands.Add($g.Source) } } }
    $pyl = Get-Command 'py.exe' -ErrorAction SilentlyContinue
    $roots = @("$env:ProgramFiles\Python*", "${env:ProgramFiles(x86)}\Python*", "$env:LOCALAPPDATA\Programs\Python\Python*")
    foreach ($r in $roots) { if ($r) { foreach ($d in @(Get-ChildItem -Path $r -Directory -ErrorAction SilentlyContinue)) { $p = Join-Path $d.FullName 'python.exe'; if (Test-Path -LiteralPath $p) { [void]$cands.Add($p) } } } }
    $best = $null
    foreach ($c in $cands) {
        try { $v = (& $c --version 2>&1 | Select-Object -First 1).ToString() } catch { continue }
        if ($v -match '^Python (\d+)\.(\d+)\.?(\d*)') {
            $o = [pscustomobject]@{ Path = $c; Text = $v.Trim(); Major = [int]$Matches[1]; Minor = [int]$Matches[2] }
            if ($o.Major -lt 3) { continue }
            if ($null -eq $best -or $o.Minor -gt $best.Minor) { $best = $o }
        }
    }
    return $best
}
function Get-LatestWingetPythonId {
    $ids = New-Object System.Collections.ArrayList
    try { foreach ($l in (& $wg.Source search --id Python.Python. --source winget --accept-source-agreements 2>&1)) { if ($l.ToString() -match '(Python\.Python\.3\.(\d+))(\s|$)') { [void]$ids.Add([pscustomobject]@{ Id = $Matches[1]; Minor = [int]$Matches[2] }) } } } catch { }
    if ($ids.Count -gt 0) { return ($ids | Sort-Object Minor -Descending | Select-Object -First 1).Id }
    return 'Python.Python.3.14'
}
function Confirm-PythonOnPath {
    param($Py)
    $dir = Split-Path -Parent $Py.Path
    $onPath = Get-Command 'python' -ErrorAction SilentlyContinue
    if ($onPath -and $onPath.Source -notmatch '\\WindowsApps\\') { Say 'OK' "python is on the PATH: $($onPath.Source)"; }
    else { if ($onPath) { Say 'WARN' 'python on the PATH is the Microsoft Store stub (it only opens the Store).' } else { Say 'WARN' 'Python is installed but not found on the PATH.' }; Add-ToPath -Dir $dir -Front $true }
    $sc = Join-Path $dir 'Scripts'
    if ((Test-Path -LiteralPath $sc) -and -not (Test-OnPath $sc) -and -not $NoPath) { Add-ToPath -Dir $sc -Front $false }
}
function Install-PythonNow {
    Say 'INFO' '--- Python ---'
    $have = Find-Python
    if ($have) { Say 'INFO' ("Python found: {0}  ({1})" -f $have.Text, $have.Path) } else { Say 'INFO' 'Python 3 is not installed (or only the Microsoft Store stub is there).' }
    if ($have -and $have.Minor -ge 10 -and -not $Force) { Say 'OK' 'Python 3.10 or newer is there. (-Force upgrades to the latest through the package manager.)'; Confirm-PythonOnPath $have; return }
    if (-not $use) { Say 'ERROR' 'No package manager (winget or Chocolatey) for Python.'; $script:Missing = $true; if ($have) { Confirm-PythonOnPath $have }; return }
    $id = if ($use -eq 'winget') { Get-LatestWingetPythonId } else { 'python' }
    $wa = @('install', '--id', $id, '--exact', '--source', 'winget', '--accept-source-agreements', '--accept-package-agreements', '--silent', '--disable-interactivity')
    $ca = @('install', 'python', '-y', '--no-progress')
    Say 'INFO' ("Would run: {0}" -f $(if ($use -eq 'winget') { 'winget ' + ($wa -join ' ') } else { 'choco ' + ($ca -join ' ') }))
    if ($Check) { if ($have) { Confirm-PythonOnPath $have }; return }
    if (-not (Confirm-Install 'Python')) { return }
    try {
        Invoke-Pm -WingetArgs $wa -ChocoArgs $ca
        if ($LASTEXITCODE -ne 0) {
            Say 'WARN' "The package manager returned exit code $LASTEXITCODE. Trying an upgrade ..."
            Invoke-Pm -WingetArgs @('upgrade', '--id', $id, '--exact', '--source', 'winget', '--accept-source-agreements', '--accept-package-agreements', '--silent', '--disable-interactivity') -ChocoArgs @('upgrade', 'python', '-y', '--no-progress')
        }
    } catch { Say 'ERROR' "The Python installation failed: $($_.Exception.Message)"; $script:Missing = $true; return }
    Update-SessionPath
    $now = Find-Python
    if (-not $now) { Say 'ERROR' 'The package manager finished but python.exe was not found. Open a NEW PowerShell window and run this script with -Check.'; $script:Missing = $true; return }
    Say 'OK' ("Python: {0}  ({1})" -f $now.Text, $now.Path)
    Confirm-PythonOnPath $now
    try { $pv = (& $now.Path -m pip --version 2>&1 | Select-Object -First 1).ToString(); if ($pv -match '^pip ') { Say 'OK' "pip: $pv" } else { Say 'WARN' 'pip was not found: python -m ensurepip --upgrade' } } catch { Say 'WARN' 'pip was not found: python -m ensurepip --upgrade' }
}

if ($Only -in 'All', 'OpenSsl') { Install-OpenSslNow }
if ($Only -in 'All', 'Python') { Install-PythonNow }
Write-Host ''
if ($Check) { Say 'INFO' '-Check: nothing was changed.' }
if ($script:Missing) { Say 'WARN' 'Not everything is ready: read the lines above.'; exit 4 }
Say 'OK' 'Ready. Open a NEW PowerShell window, then: openssl version   python --version'
exit 0
